"""Python 版 Firefly 内核配置。"""

from __future__ import annotations

from dataclasses import dataclass, replace

DEFAULT_LANGUAGE = "Python"
DEFAULT_VERSION = "v0.0.1"


@dataclass(slots=True)
class KernelConfig:
    """当前服务使用的 Firefly Python 内核信息。"""

    language: str = ""
    version: str = ""

    def bootstrap(self) -> "KernelConfig":
        """补齐默认语言与框架版本。"""

        # language 对齐 Go kernel.Config，用于注册和日志中表达服务实现语言。
        language = self.language.strip() or DEFAULT_LANGUAGE
        # version 表达当前 Python Firefly 公共包基线，初始版本从 v0.0.1 开始。
        version = self.version.strip() or DEFAULT_VERSION
        # 返回归一化副本，避免启动装配层不小心修改原始配置对象。
        return replace(self, language=language, version=version)
