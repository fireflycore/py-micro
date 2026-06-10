"""Firefly Python 微服务公共能力。"""

# 对外只重导出首批稳定入口，避免调用方依赖内部辅助函数。
from .authz import (
    AuthzSign,
    AuthzSignVerificationOptions,
    AuthzUserContext,
    CachedServiceAuthorityProvider,
    ServiceAuthorityToken,
    verify_authz_sign,
)
from .service_context import BuildContextOptions, DecisionContext, ServiceContext, UserContext, build_context

# __all__ 明确当前 alpha 的公共 API 面，后续重构内部文件时可保持导入路径稳定。
__all__ = [
    "AuthzSign",
    "AuthzSignVerificationOptions",
    "AuthzUserContext",
    "BuildContextOptions",
    "CachedServiceAuthorityProvider",
    "DecisionContext",
    "ServiceAuthorityToken",
    "ServiceContext",
    "UserContext",
    "build_context",
    "verify_authz_sign",
]
