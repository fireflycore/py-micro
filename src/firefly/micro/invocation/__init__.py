"""Firefly 远程调用公共入口。"""

from .dns import DNS, RemoteServiceRegistry
from .metadata import DEFAULT_INVOKE_TIMEOUT_SECONDS, prepare_metadata_for_invocation
from .target import Target

__all__ = [
    "DEFAULT_INVOKE_TIMEOUT_SECONDS",
    "DNS",
    "RemoteServiceRegistry",
    "Target",
    "prepare_metadata_for_invocation",
]
