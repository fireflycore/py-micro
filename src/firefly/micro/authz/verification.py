"""authz 服务侧验签配置解析。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from .keys import load_ed25519_public_key
from .sign import DEFAULT_CLOCK_SKEW, DEFAULT_ISSUER, DEFAULT_KID, AuthzSignVerificationOptions

_DURATION_PATTERN = re.compile(r"^\s*(?P<value>\d+(?:\.\d+)?)(?P<unit>ms|s|m|h)?\s*$")


@dataclass(slots=True)
class VerificationConfig:
    """业务服务如何验签 `x-firefly-authz-sign` 的配置。"""

    kid: str = DEFAULT_KID
    public_key_path: str = ""
    issuer: str = DEFAULT_ISSUER
    clock_skew: str = ""
    skip_methods: list[str] = field(default_factory=list)


@dataclass(slots=True)
class VerificationOptions:
    """服务入口 middleware 可直接消费的验签选项。"""

    authz_verification: AuthzSignVerificationOptions | None = None
    authz_skip_methods: list[str] = field(default_factory=list)


def new_verification_options(config: VerificationConfig | None) -> VerificationOptions:
    """根据启动配置生成 authz 验签选项。"""

    if config is None:
        # nil 配置表示启动层没有启用验签，返回空 options 供调用方显式判断。
        return VerificationOptions()
    # kid 为空时使用 Firefly 当前默认公钥 ID。
    kid = config.kid.strip() or DEFAULT_KID
    # issuer 为空时使用固定签发方，避免业务服务重复写默认值。
    issuer = config.issuer.strip() or DEFAULT_ISSUER
    # 一旦启用验签，公钥路径必须显式配置。
    public_key_path = config.public_key_path.strip()
    if not public_key_path:
        raise ValueError("authz verification public_key_path is required")
    # 启动期加载 PEM 公钥，后续请求热路径只读取已解析对象。
    public_key = load_ed25519_public_key(Path(public_key_path))
    # clock_skew 支持 Go 风格 5s/1m/1h，也允许空值回落默认 5s。
    clock_skew = _parse_clock_skew(config.clock_skew)
    # skip_methods 去空白和空值，避免误配置空字符串导致跳过规则混乱。
    skip_methods = [value.strip() for value in config.skip_methods if value.strip()]
    return VerificationOptions(
        authz_verification=AuthzSignVerificationOptions(
            public_keys={kid: public_key},
            issuer=issuer,
            clock_skew=clock_skew,
        ),
        authz_skip_methods=skip_methods,
    )


def must_new_verification_options(config: VerificationConfig | None) -> VerificationOptions:
    """启动期便捷封装，配置错误直接抛出。"""

    # Python 不需要额外 panic 包装，直接让异常冒泡即可快速失败。
    return new_verification_options(config)


def _parse_clock_skew(value: str) -> timedelta:
    if not value.strip():
        # 未配置时使用 authz 统一默认时钟偏差。
        return DEFAULT_CLOCK_SKEW
    match = _DURATION_PATTERN.match(value)
    if match is None:
        raise ValueError("parse authz verification clock_skew failed")
    amount = float(match.group("value"))
    unit = match.group("unit") or "s"
    if unit == "ms":
        return timedelta(milliseconds=amount)
    if unit == "s":
        return timedelta(seconds=amount)
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    raise ValueError("parse authz verification clock_skew failed")
