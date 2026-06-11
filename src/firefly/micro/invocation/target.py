"""远程服务 target 模型。"""

from __future__ import annotations

from dataclasses import dataclass


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
