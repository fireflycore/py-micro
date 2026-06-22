"""远程 unary 调用抽象。"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from ..errors import InvokerDialerMissingError, InvokeMethodEmptyError
from ..metadata import MetadataMapping, NormalizedMetadata
from .manager import ConnectionManager
from .metadata import DEFAULT_INVOKE_TIMEOUT_SECONDS, prepare_metadata_for_invocation
from .target import Target

UnaryInvokeFunc = Callable[[Any, str, object, NormalizedMetadata, float], Any | Awaitable[Any]]


@dataclass(slots=True)
class InvokeRequest:
    """一次远程 unary 调用所需的稳定事实。"""

    target: Target
    method: str
    request: object
    metadata: MetadataMapping | None = None
    timeout_seconds: float = DEFAULT_INVOKE_TIMEOUT_SECONDS


class UnaryInvoker:
    """统一串起连接获取、metadata 准备和底层调用函数。"""

    def __init__(
        self,
        manager: ConnectionManager,
        invoke: UnaryInvokeFunc,
        *,
        authority_provider: object | None = None,
        timeout_seconds: float = DEFAULT_INVOKE_TIMEOUT_SECONDS,
    ) -> None:
        if manager is None:
            # invoker 没有连接管理器时无法发起远程调用。
            raise InvokerDialerMissingError("invoker dialer is nil")
        if invoke is None:
            # 底层调用函数由 py-layout 绑定 grpc.aio 或测试桩。
            raise ValueError("invoke function is required")
        self._manager = manager
        self._invoke = invoke
        self._authority_provider = authority_provider
        # 非正超时回落到统一默认值，避免误配置导致无限等待。
        self._timeout_seconds = timeout_seconds if timeout_seconds > 0 else DEFAULT_INVOKE_TIMEOUT_SECONDS

    async def invoke(self, request: InvokeRequest) -> Any:
        """执行一次标准 unary 调用。"""

        if not request.method.strip():
            raise InvokeMethodEmptyError("invoke method is empty")
        # 出站 metadata 先清理旧 authority，再覆盖当前服务 authority。
        metadata = await prepare_metadata_for_invocation(request.metadata, self._authority_provider)  # type: ignore[arg-type]
        # 连接由 manager 按 target 缓存和复用。
        conn = await self._manager.dial(request.target)
        # 请求级超时优先；未设置时使用 invoker 默认值。
        timeout = request.timeout_seconds if request.timeout_seconds > 0 else self._timeout_seconds
        result = self._invoke(conn, request.method, request.request, metadata, timeout)
        if inspect.isawaitable(result):
            return await result
        return result
