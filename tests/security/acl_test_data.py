"""ACL测试用例数据加载 (YAML数据驱动).

parametrize在用例收集期(module import时)求值, 此时fixture还不存在, 故YAML必须在
测试文件module顶层加载(不能放conftest fixture). 本模块提供lru_cache缓存的加载函数.

范本: 各模块可照此建 tests/<module>/<module>_test_data.py + test_data/<module>/*.yaml.
"""
import os
from functools import lru_cache

import yaml

# test_data/acl/ 绝对路径(本文件在tests/security/, 上溯2级到项目根)
_ACL_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "test_data", "acl"
)


@lru_cache(maxsize=None)
def load_acl_cases(filename: str) -> list:
    """加载 test_data/acl/<filename> 的 cases 列表(lru_cache缓存, 收集期只读一次磁盘).

    Args:
        filename: 如 'protocol_cases.yaml'

    Returns:
        cases列表(list[dict]), 每个dict是一条参数化用例数据
    """
    path = os.path.join(_ACL_DATA_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("cases", [])
