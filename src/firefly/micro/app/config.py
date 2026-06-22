"""应用自身身份配置模型。"""

from __future__ import annotations

from dataclasses import dataclass, replace
from uuid import uuid4

from ..errors import BootstrapConfigError


@dataclass(slots=True)
class AppConfig:
    """业务应用在 Firefly 体系中的稳定身份。"""

    id: str
    env: str
    name: str
    secret: str
    version: str
    instance_id: str = ""

    def bootstrap(self) -> "AppConfig":
        """校验必填字段，并补齐当前进程实例 ID。"""

        # app.id 是 authz、配置中心和 sidecar 注册的共同主键，启动期必须存在。
        if not self.id.strip():
            raise BootstrapConfigError("app.id is empty")
        # env 决定配置与注册隔离边界，空值会让不同环境互相串扰。
        if not self.env.strip():
            raise BootstrapConfigError("app.env is empty")
        # name 用于日志、观测和可读注册信息，不允许隐式留空。
        if not self.name.strip():
            raise BootstrapConfigError("app.name is empty")
        # secret 是读取加密配置和服务身份链路的基础材料，首期保持必填。
        if not self.secret.strip():
            raise BootstrapConfigError("app.secret is empty")
        # version 进入 sidecar 注册与 OTel resource，方便回滚和排障。
        if not self.version.strip():
            raise BootstrapConfigError("app.version is empty")
        # Python 3.12 stdlib 尚无 uuid7，这里先用 uuid4 表达进程唯一实例身份。
        instance_id = self.instance_id.strip() or str(uuid4())
        # 返回新对象而不是原地修改，让配置对象更容易在测试和装配层复用。
        return replace(
            self,
            id=self.id.strip(),
            env=self.env.strip(),
            name=self.name.strip(),
            secret=self.secret.strip(),
            version=self.version.strip(),
            instance_id=instance_id,
        )
