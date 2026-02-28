"""
日志工具模块
"""
import logging
import sys
from datetime import datetime
from typing import Optional


def setup_logger(
    name: str = "ikua_test",
    level: int = logging.INFO,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    设置日志记录器

    Args:
        name: 日志记录器名称
        level: 日志级别
        log_file: 日志文件路径（可选）

    Returns:
        配置好的Logger对象
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # 避免重复添加handler
    if logger.handlers:
        return logger

    # 控制台handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    # 日志格式
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 文件handler（如果指定）
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# 全局日志记录器
_logger: Optional[logging.Logger] = None


def get_logger() -> logging.Logger:
    """获取全局日志记录器"""
    global _logger
    if _logger is None:
        _logger = setup_logger()
    return _logger
