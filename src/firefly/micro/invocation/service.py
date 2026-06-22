"""远程业务服务装配器。"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ..errors import InvokerDialerMissingError, RemoteServiceNotFoundError
from ..metadata import MetadataMapping
from .dns import DNS
from .invoker import InvokeRequest, UnaryInvoker


class RemoteServiceCaller:
    """绑定单个远程业务服务的调用入口。"""

    def __init__(self, invoker: UnaryInvoker, dns: DNS) -> None:
        # caller 只做薄封装，真正调用行为由共享 invoker 处理。
        self._invoker = invoker
        # 保存副本，避免外部继续修改 DNS 影响 caller 后续调用。
        self._dns = replace(dns)

    @property
    def dns(self) -> DNS:
        """返回当前远程服务 DNS 副本。"""

        return replace(self._dns)

    async def invoke(
        self,
        method: str,
        request: object,
        *,
        metadata: MetadataMapping | None = None,
        timeout_seconds: float = 0,
    ) -> Any:
        """向当前绑定的远程业务服务发起一次 unary 调用。"""

        if self._invoker is None:
            raise InvokerDialerMissingError("invoker dialer is nil")
        return await self._invoker.invoke(
            InvokeRequest(
                target=self._dns.target(),
                method=method,
                request=request,
                metadata=metadata,
                timeout_seconds=timeout_seconds,
            )
        )


class RemoteServiceManaged:
    """管理多组远程业务服务 DNS，并复用同一条调用主线。"""

    def __init__(self, invoker: UnaryInvoker, services: list[DNS] | tuple[DNS, ...]) -> None:
        # 多服务管理器只保存共享 invoker，避免每个服务重复创建连接管理链路。
        self._invoker = invoker
        # 服务表按 service 名称索引，空服务名跳过以兼容动态配置。
        self._services: dict[str, DNS] = {}
        for item in services:
            name = item.service.strip()
            if name:
                self._services[name] = replace(item)

    def dns(self, service_name: str) -> DNS:
        """返回指定服务的 DNS 副本。"""

        try:
            return replace(self._services[service_name.strip()])
        except KeyError as exc:
            raise RemoteServiceNotFoundError("remote service not found") from exc

    def caller(self, service_name: str) -> RemoteServiceCaller:
        """为指定服务派生薄 caller。"""

        return RemoteServiceCaller(self._invoker, self.dns(service_name))

    async def invoke(
        self,
        service_name: str,
        method: str,
        request: object,
        *,
        metadata: MetadataMapping | None = None,
        timeout_seconds: float = 0,
    ) -> Any:
        """按业务服务名直接发起一次 unary 调用。"""

        if self._invoker is None:
            raise InvokerDialerMissingError("invoker dialer is nil")
        # 直接取 DNS 后调用共享 invoker，避免先构造 caller 再调用的额外对象。
        dns = self.dns(service_name)
        return await self._invoker.invoke(
            InvokeRequest(
                target=dns.target(),
                method=method,
                request=request,
                metadata=metadata,
                timeout_seconds=timeout_seconds,
            )
        )
