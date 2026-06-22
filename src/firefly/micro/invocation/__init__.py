"""Firefly 远程调用公共入口。"""

from .dns import DNS, RemoteServiceRegistry
from .invoker import InvokeRequest, UnaryInvoker
from .manager import ConnectionManager, ConnectionManagerOptions
from .metadata import DEFAULT_INVOKE_TIMEOUT_SECONDS, prepare_metadata_for_invocation
from .service import RemoteServiceCaller, RemoteServiceManaged
from .target import Target

__all__ = [
    "ConnectionManager",
    "ConnectionManagerOptions",
    "DEFAULT_INVOKE_TIMEOUT_SECONDS",
    "DNS",
    "InvokeRequest",
    "RemoteServiceRegistry",
    "RemoteServiceCaller",
    "RemoteServiceManaged",
    "Target",
    "UnaryInvoker",
    "prepare_metadata_for_invocation",
]
