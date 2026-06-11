"""远程服务 DNS 注册表。"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .target import Target


@dataclass(slots=True)
class DNS:
    """Firefly 业务服务 DNS 描述。"""

    service: str
    namespace: str
    service_type: str
    cluster_domain: str
    port: int
    resolver_scheme: str = "dns"

    def host(self) -> str:
        # 四段字段共同组成 Kubernetes Service FQDN，缺一段都不能构造稳定入口。
        fields = [self.service, self.namespace, self.service_type, self.cluster_domain]
        if not all(item.strip() for item in fields):
            raise ValueError("dns fields are required")
        # Go 版 sidecar 注册也使用 service.namespace.type.cluster_domain 作为统一主机名。
        return ".".join(item.strip() for item in fields)

    def target(self) -> Target:
        # DNS 只负责组装稳定入口，真正拨号仍交给上层 gRPC 客户端。
        return Target(host=self.host(), port=self.port, resolver_scheme=self.resolver_scheme)


class RemoteServiceRegistry:
    """管理多组远程业务服务 DNS，并复用统一调用主线。"""

    def __init__(self, services: list[DNS] | None = None) -> None:
        # 注册表按服务名索引 DNS，避免调用方在每次出站前重复拼接目标。
        self._services: dict[str, DNS] = {}
        for item in services or []:
            self.register(item)

    def register(self, dns: DNS) -> None:
        # service 字段是注册表主键，写入前 trim 以匹配 Go 版服务名校验语义。
        name = dns.service.strip()
        if not name:
            raise ValueError("service name is required")
        # 后注册的同名服务覆盖旧值，便于测试或启动配置重载。
        self._services[name] = dns

    def dns(self, service_name: str) -> DNS:
        try:
            # 查询时同样 trim，避免调用方配置空白导致误判服务不存在。
            value = self._services[service_name.strip()]
        except KeyError as exc:
            raise KeyError("remote service not found") from exc
        # 返回新的 dataclass 对象，避免外部修改注册表中的 DNS。
        return replace(value)
