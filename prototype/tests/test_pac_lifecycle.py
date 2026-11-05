"""真实子进程的互斥与看门狗回归；只使用临时目录和自建 HKCU 测试键。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid

import pytest

from conftest import free_port


# 与 Rust OpenOptions::share_mode(0) 相同的 Windows 文件共享约束。
LOCK_HOLDER = r"""
import ctypes, pathlib, sys
from ctypes import wintypes as W
create = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
create.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
create.restype = W.HANDLE
directory = pathlib.Path(sys.argv[1])
directory.mkdir(parents=True, exist_ok=True)
handle = create(str(directory / "pac.lock"), 0xC0000000, 0, None, 4, 0x80, None)
if handle == W.HANDLE(-1).value:
    raise ctypes.WinError(ctypes.get_last_error())
print("locked", flush=True)
sys.stdin.buffer.read()
"""


@pytest.fixture
def rust_binary(request):
    target = request.config.getoption("--target-binary")
    if not target or sys.platform != "win32":
        pytest.skip("需要 Windows Rust 二进制")
    return target


@pytest.fixture
def lock_holder():
    processes = []

    def start(directory):
        proc = subprocess.Popen(
            [sys.executable, "-c", LOCK_HOLDER, str(directory)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        processes.append(proc)
        assert proc.stdout.readline().strip() == b"locked"
        return proc

    yield start
    for proc in processes:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()


@pytest.mark.parametrize("prior", [None, "http://corp.example/代理.pac"])
@pytest.mark.parametrize("change", ["unchanged", "replaced", "deleted", "new-session"])
def test_watchdog_waits_for_owner_and_preserves_other_settings(
    rust_binary, lock_holder, tmp_path, prior, change
):
    import winreg

    subkey = rf"Software\winget-accel-test-{uuid.uuid4().hex}"
    owned = "http://127.0.0.1:18443/winget-accel.pac"
    state_path = tmp_path / "state.json"
    log_path = tmp_path / "watchdog.log"
    state = {"version": 2, "prior": prior, "ownedPac": owned, "session": "old-session"}
    state_path.write_text(json.dumps(state), encoding="utf-8")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, subkey) as key:
        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, owned)
    owner = lock_holder(tmp_path)
    watchdog = None
    try:
        watchdog = subprocess.Popen(
            [
                rust_binary, "--watchdog", str(owner.pid), str(state_path),
                str(log_path), "HKCU\\" + subkey, "old-session",
            ],
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        time.sleep(0.15)
        assert watchdog.poll() is None, "父进程仍在时不得还原 PAC"
        expected = prior
        if change == "replaced":
            expected = "http://corp.example/new.pac"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, expected)
        elif change == "deleted":
            expected = None
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "AutoConfigURL")
        elif change == "new-session":
            expected = owned
            state["session"] = "new-session"
            state_path.write_text(json.dumps(state), encoding="utf-8")
        owner.kill()
        owner.wait(timeout=5)
        assert watchdog.wait(timeout=5) == 0
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey) as key:
            try:
                actual = winreg.QueryValueEx(key, "AutoConfigURL")[0]
            except FileNotFoundError:
                actual = None
        assert actual == expected
        assert state_path.exists() == (change == "new-session")
        # 新会话也要留下“跳过”结果，便于诊断旧看门狗为什么没有接管。
        assert "PAC-RESTORED" in log_path.read_text(encoding="utf-8")
    finally:
        if watchdog is not None and watchdog.poll() is None:
            watchdog.kill()
            watchdog.wait(timeout=5)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)


def test_second_copy_fails_before_creating_ca_or_changing_pac(
    rust_binary, lock_holder, tmp_path
):
    user_data = tmp_path / "profile"
    lock_holder(user_data / "winget-accel")
    cfg = {
        "listen": f"127.0.0.1:{free_port()}",
        "accelerators": [{"name": "unused", "template": "http://127.0.0.1:9"}],
        "certDir": str(tmp_path / "certs"),
        "logPath": str(tmp_path / "proxy.log"),
    }
    config = tmp_path / "config.json"
    config.write_text(json.dumps(cfg), encoding="utf-8")
    result = subprocess.run(
        [rust_binary, "--config", str(config)],
        capture_output=True,
        timeout=5,
        env={**os.environ, "LOCALAPPDATA": str(user_data)},
    )
    assert result.returncode != 0
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    assert "PAC 接管锁" in output
    assert not (tmp_path / "certs").exists()
    assert not (user_data / "winget-accel" / "state.json").exists()
