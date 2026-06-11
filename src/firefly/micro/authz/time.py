"""authz 内部时间处理辅助。"""

from __future__ import annotations

from datetime import UTC, datetime


def ensure_aware_utc(value: datetime) -> datetime:
    """把调用方时间归一成 UTC aware datetime。"""

    if value.tzinfo is None:
        # 业务测试常传 naive datetime；按 UTC 解释以匹配 Unix 秒比较语义。
        return value.replace(tzinfo=UTC)
    # 统一转 UTC，避免本地时区影响 exp/nbf 或 token 过期判断。
    return value.astimezone(UTC)


def utcnow() -> datetime:
    """返回当前 UTC 时间。"""

    return datetime.now(UTC)
