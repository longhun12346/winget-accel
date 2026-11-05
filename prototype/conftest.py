"""rootdir 级 conftest：只放"命令行选项"与"收集钩子"。

为什么必须在这里而不是 tests/conftest.py：
pytest 在**解析命令行参数**时就要知道有哪些自定义选项，
而 tests/ 下的 conftest 要等到收集阶段才加载，那时已知参数太晚。
夹具仍放在 tests/conftest.py。
"""

from __future__ import annotations

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--network",
        action="store_true",
        default=False,
        help="运行需要真实外网与可用加速器的用例",
    )
    parser.addoption(
        "--target-binary",
        default=None,
        metavar="PATH",
        help="用外部可执行文件替代 Python 原型（例如 Rust 版的 winget-accel.exe）",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--network"):
        skip_network = pytest.mark.skip(reason="需要真实网络（用 --network 开启）")
        for item in items:
            if "network" in item.keywords:
                item.add_marker(skip_network)

    # 单元用例测的是 Python 内部实现；跑外部二进制时它们没有意义（Rust 侧有自己的单测）
    if config.getoption("--target-binary"):
        skip_units = pytest.mark.skip(reason="外部二进制模式下由 Rust 单测覆盖")
        for item in items:
            if item.fspath.basename == "test_units.py":
                item.add_marker(skip_units)
