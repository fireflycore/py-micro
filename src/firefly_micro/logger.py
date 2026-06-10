"""Firefly 日志上下文字段辅助函数。"""

from __future__ import annotations

from .service_context import ServiceContext


def service_context_fields(ctx: ServiceContext | None) -> dict[str, str]:
    """把服务上下文转换为适合结构化日志的低基数字段。"""

    if ctx is None:
        # 没有上下文时保持日志字段为空，避免调用方额外判空。
        return {}
    # 只选低基数字段，避免把用户列表、token 或完整 JWS 写入日志。
    fields = {
        "service_app_id": ctx.service_app_id,
        "service_instance_id": ctx.service_instance_id,
        "subject_type": ctx.subject_type,
        "invoke_app_id": ctx.invoke_app_id,
        "target_app_id": ctx.target_app_id,
        "decision_id": ctx.decision_id,
        "trace_id": ctx.trace_id,
    }
    # 空字段不输出，避免日志里堆积没有诊断价值的占位键。
    return {key: value for key, value in fields.items() if value}
