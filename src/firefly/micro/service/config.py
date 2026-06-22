"""服务发现与调用目标配置。"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..errors import BootstrapConfigError


@dataclass(slots=True)
class ServiceConfig:
    """业务服务在 Firefly 服务治理中的 DNS 与权重事实。"""

    name: str
    type: str = "svc"
    namespace: str = "default"
    cluster_domain: str = "cluster.local"
    port: int = 9090
    weight: int = 100

    def bootstrap(self) -> "ServiceConfig":
        """校验服务名并补齐 Go 侧默认发现字段。"""

        # name 是远程调用和 sidecar 注册的业务服务主键，不允许为空。
        if not self.name.strip():
            raise BootstrapConfigError("service.name is empty")
        # type/namespace/cluster_domain 三段共同组成 Kubernetes Service FQDN。
        service_type = self.type.strip() or "svc"
        namespace = self.namespace.strip() or "default"
        cluster_domain = self.cluster_domain.strip() or "cluster.local"
        # port 为零时按 Go service.Config 默认值 9090 兜底。
        port = self.port or 9090
        if port <= 0 or port > 65535:
            raise BootstrapConfigError("service.port is invalid")
        # weight 为零时按注册默认权重 100 兜底。
        weight = self.weight or 100
        if weight < 0:
            raise BootstrapConfigError("service.weight is invalid")
        # 返回新对象，保证 bootstrap 只做归一化，不产生隐藏副作用。
        return replace(
            self,
            name=self.name.strip(),
            type=service_type,
            namespace=namespace,
            cluster_domain=cluster_domain,
            port=port,
            weight=weight,
        )
