"""
命令行测试运行入口

提供命令行方式运行测试
"""
import argparse
import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_tests(
    test_path: str = "tests/",
    markers: str = None,
    verbose: bool = True,
    html_report: str = None,
    extra_args: list = None
):
    """
    运行测试

    Args:
        test_path: 测试路径
        markers: pytest标记
        verbose: 是否详细输出
        html_report: HTML报告路径
        extra_args: 额外的pytest参数
    """
    import pytest

    args = []

    if verbose:
        args.append("-v")

    if markers:
        args.extend(["-m", markers])

    if html_report:
        args.extend(["--html", html_report, "--self-contained-html"])

    if extra_args:
        args.extend(extra_args)

    args.append(test_path)

    return pytest.main(args)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="爱快路由器4.0自动化测试")

    parser.add_argument(
        "test_path",
        nargs="?",
        default="tests/",
        help="测试路径 (默认: tests/)"
    )

    parser.add_argument(
        "-m", "--markers",
        help="运行指定标记的测试 (如: vlan, network)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="详细输出"
    )

    parser.add_argument(
        "--html",
        help="生成HTML报告的路径"
    )

    parser.add_argument(
        "-k", "--keyword",
        help="运行匹配关键字的测试"
    )

    parser.add_argument(
        "--headless",
        action="store_true",
        help="无头模式运行浏览器"
    )

    args = parser.parse_args()

    # 构建额外参数
    extra_args = []

    if args.keyword:
        extra_args.extend(["-k", args.keyword])

    if args.headless:
        # 设置环境变量或配置
        os.environ["HEADLESS"] = "true"

    # 运行测试
    exit_code = run_tests(
        test_path=args.test_path,
        markers=args.markers,
        verbose=args.verbose,
        html_report=args.html,
        extra_args=extra_args
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
