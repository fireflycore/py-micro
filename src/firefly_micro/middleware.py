"""框架适配层可复用的轻量 middleware 辅助函数。"""

from __future__ import annotations

from collections.abc import Iterable


def should_skip_authz(method: str, skip_methods: Iterable[str] | None = None) -> bool:
    """判断当前入口方法是否跳过 authz 服务上下文验签。"""

    if not method:
        # 缺少方法名时不能命中跳过规则，入口应按默认验签策略处理。
        return False
    # 跳过列表通常来自启动配置，统一 trim 后比较可以降低配置书写差异。
    # Python 版用集合表达 Go middleware 的 skip map 语义，避免重复项影响判断。
    return method.strip() in {item.strip() for item in skip_methods or [] if item.strip()}


def is_grpc_health_check(method: str) -> bool:
    """识别默认不写访问日志的 gRPC health check 方法。"""

    # gRPC health check 使用固定 FullMethod，和 Go middleware 的入口判断保持一致。
    return method.strip() == "/grpc.health.v1.Health/Check"
