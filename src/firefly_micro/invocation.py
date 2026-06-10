"""远程服务 DNS/target 与出站调用 metadata 准备。"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .metadata import MetadataMapping, NormalizedMetadata, ServiceAuthorityProvider, prepare_outgoing_authority_metadata

DEFAULT_INVOKE_TIMEOUT_SECONDS = 5.0


@dataclass(slots=True)
class Target:
    """最终可拨号的服务目标。"""

    host: str
    port: int
    resolver_scheme: str = "dns"

    def validate(self) -> None:
        if not self.resolver_scheme.strip():
            # resolver scheme 是 gRPC target 的固定组成部分，空值会形成不可拨号地址。
            raise ValueError("target resolver_scheme is required")
        if not self.host.strip():
            # host 为空时无法表达稳定服务入口，和 Go Target.Validate 保持一致拒绝。
            raise ValueError("target host is required")
        if self.port <= 0 or self.port > 65535:
            # Python 使用 int，额外限制到 TCP 端口合法范围。
            raise ValueError("target port is invalid")

    @property
    def address(self) -> str:
        # 每次读取都先校验，避免无效 Target 被传入真实客户端。
        self.validate()
        # Python 版保持 Go 版 host:port 的可读形式，不做实例发现或负载均衡。
        return f"{self.host.strip()}:{self.port}"

    @property
    def grpc_target(self) -> str:
        # grpc target 使用 dns:///host:port 形式，与 Go invocation.Target.GRPCTarget 对齐。
        self.validate()
        return f"{self.resolver_scheme.strip()}:///{self.address}"


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


async def prepare_metadata_for_invocation(
    metadata: MetadataMapping | None,
    provider: ServiceAuthorityProvider | None = None,
) -> NormalizedMetadata:
    """为远程调用准备 Firefly 出站 metadata。"""

    # invocation 层只复用 authz metadata 清理/注入主线，避免两套出站身份规则分叉。
    return await prepare_outgoing_authority_metadata(metadata, provider)
