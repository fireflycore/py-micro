"""Firefly Python 微服务公共能力。"""

# 对外只重导出首批稳定入口，避免调用方依赖内部辅助函数。
from . import constants
from .app import AppConfig
from .authz import (
    AuthzSign,
    AuthzSignVerificationOptions,
    AuthzUserContext,
    CachedServiceAuthorityProvider,
    ServiceAuthorityToken,
    VerificationConfig,
    VerificationOptions,
    new_verification_options,
    verify_authz_sign,
)
from .kernel import KernelConfig
from .service import ServiceConfig
from .service_context import BuildContextOptions, DecisionContext, ServiceContext, UserContext, build_context
from .sys import HostInfo, new_host_info

# __all__ 明确当前 alpha 的公共 API 面，后续重构内部文件时可保持导入路径稳定。
__all__ = [
    "AppConfig",
    "AuthzSign",
    "AuthzSignVerificationOptions",
    "AuthzUserContext",
    "BuildContextOptions",
    "CachedServiceAuthorityProvider",
    "DecisionContext",
    "HostInfo",
    "KernelConfig",
    "ServiceConfig",
    "ServiceAuthorityToken",
    "ServiceContext",
    "UserContext",
    "VerificationConfig",
    "VerificationOptions",
    "build_context",
    "constants",
    "new_host_info",
    "new_verification_options",
    "verify_authz_sign",
]
