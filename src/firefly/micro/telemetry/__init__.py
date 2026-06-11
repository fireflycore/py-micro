"""Firefly telemetry 配置模型的 Python 公共基线。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class TelemetryConfig:
    """描述服务接入 OpenTelemetry 时的稳定配置入口。"""

    service_name: str
    service_version: str = ""
    environment: str = ""
    otlp_endpoint: str = ""
    resource_attributes: dict[str, str] = field(default_factory=dict)

    def resource(self) -> dict[str, str]:
        """生成 OTel resource 属性，不在公共包里绑定具体 SDK。"""

        # 公共包只产出稳定字段，具体 exporter/provider 由应用框架层装配。
        # 先复制调用方扩展属性，避免 setdefault 修改原始配置。
        values = dict(self.resource_attributes)
        # service.name 是 OTel resource 的核心字段，必须稳定注入。
        values.setdefault("service.name", self.service_name)
        if self.service_version:
            # 调用方已显式设置同名属性时不覆盖，保持本地框架层优先级。
            values.setdefault("service.version", self.service_version)
        if self.environment:
            # 使用当前 OTel 语义约定字段，和 Go 侧 telemetry 配置对齐。
            values.setdefault("deployment.environment.name", self.environment)
        return values


__all__ = ["TelemetryConfig"]
