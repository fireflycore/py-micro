"""服务进程内上下文模型。"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import constants
from ..authz import AuthzSign, AuthzSignVerificationOptions


@dataclass(slots=True)
class UserContext:
    """服务进程内可读取的用户身份上下文。"""

    user_id: str = ""
    app_id: str = ""
    tenant_id: str = ""
    session: str = ""
    org_ids: list[str] = field(default_factory=list)
    post_ids: list[str] = field(default_factory=list)
    role_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DecisionContext:
    """服务进程内可读取的 authz 判定结果。"""

    subject_type: str = ""
    invoke_app_id: str = ""
    target_app_id: str = ""
    api_method: str = ""
    api_path: str = ""
    decision_id: str = ""


@dataclass(slots=True)
class ServiceContext:
    """请求在服务进程内流转时使用的统一主上下文。"""

    service_app_id: str = ""
    service_instance_id: str = ""
    app_language: str = ""
    session: str = ""
    user_id: str = ""
    app_id: str = ""
    tenant_id: str = ""
    org_ids: list[str] = field(default_factory=list)
    post_ids: list[str] = field(default_factory=list)
    role_ids: list[str] = field(default_factory=list)
    subject_type: str = ""
    invoke_app_id: str = ""
    target_app_id: str = ""
    api_method: str = ""
    api_path: str = ""
    decision_id: str = ""
    authz_sign_jws: str = ""
    verified_authz_sign: AuthzSign | None = None
    trace_id: str = ""
    user_context: UserContext | None = None
    invoke_service_app_id: str = ""
    target_service_app_id: str = ""
    decision_context: DecisionContext | None = None

    def rebuild_derived_contexts(self) -> None:
        """根据平铺字段重建用户上下文和决策上下文。"""

        if any([self.user_id, self.app_id, self.tenant_id, self.session, self.org_ids, self.post_ids, self.role_ids]):
            # 只有存在用户相关字段时才构造 UserContext，保持 Go 版 nil/空上下文的语义差异。
            self.user_context = UserContext(
                user_id=self.user_id,
                app_id=self.app_id,
                tenant_id=self.tenant_id,
                session=self.session,
                # 列表字段复制一份，避免派生上下文和主上下文之间共享可变列表。
                org_ids=list(self.org_ids),
                post_ids=list(self.post_ids),
                role_ids=list(self.role_ids),
            )
        else:
            # 没有用户事实时显式清空派生上下文，避免复用对象残留上一请求状态。
            self.user_context = None

        # 服务主体的调用方服务身份来自 invoke_app_id；
        # 但只在 subject_type=service 时表达该语义。
        self.invoke_service_app_id = self.invoke_app_id if self.subject_type == constants.SUBJECT_TYPE_SERVICE else ""
        # target_service_app_id 在 Python 公共包内按目标应用语义折叠，
        # 供日志和决策上下文读取。
        self.target_service_app_id = self.target_app_id if self.target_app_id else ""
        # 用户/服务身份更新后，决策上下文也要同步重建，避免派生字段不一致。
        self.rebuild_decision_context()

    def rebuild_decision_context(self) -> None:
        if any([self.subject_type, self.invoke_app_id, self.target_app_id, self.api_method, self.api_path, self.decision_id]):
            # 决策上下文只承载 authz 判定事实，不夹带用户身份字段。
            self.decision_context = DecisionContext(
                subject_type=self.subject_type,
                invoke_app_id=self.invoke_app_id,
                target_app_id=self.target_app_id,
                api_method=self.api_method,
                api_path=self.api_path,
                decision_id=self.decision_id,
            )
        else:
            # 没有任何判定事实时保持 None，
            # 业务可据此区分“未授权上下文”和“空字段上下文”。
            self.decision_context = None

    def apply_verified_authz_sign(self, authz_sign: AuthzSign) -> None:
        """用已验签 payload 覆盖普通 metadata，避免信任客户端伪造字段。"""

        # 保留完整已验签 payload，便于业务或日志读取原始判定信息。
        self.verified_authz_sign = authz_sign
        # 下面的身份和授权字段全部来自签名 payload，优先级高于入站普通 metadata。
        self.user_id = authz_sign.user_id
        self.app_id = authz_sign.app_id
        self.session = authz_sign.session
        self.tenant_id = authz_sign.tenant_id
        self.subject_type = authz_sign.subject_type
        self.invoke_app_id = authz_sign.invoke_app_id
        self.target_app_id = authz_sign.target_app_id
        self.api_method = authz_sign.api_method
        self.api_path = authz_sign.api_path
        self.decision_id = authz_sign.decision_id
        # 复制列表字段，避免业务修改 ServiceContext 时影响 AuthzSign 的可信快照。
        self.org_ids = list(authz_sign.org_ids)
        self.post_ids = list(authz_sign.post_ids)
        self.role_ids = list(authz_sign.role_ids)
        if authz_sign.user_context is not None:
            # user_context 也从已验签结构重建，保证进程内两种读取入口一致。
            self.user_context = UserContext(
                user_id=authz_sign.user_context.user_id,
                app_id=authz_sign.user_context.app_id,
                tenant_id=authz_sign.user_context.tenant_id,
                session=authz_sign.user_context.session,
                org_ids=list(authz_sign.user_context.org_ids),
                post_ids=list(authz_sign.user_context.post_ids),
                role_ids=list(authz_sign.user_context.role_ids),
            )
        else:
            # 匿名或服务主体没有用户上下文，不能沿用普通 metadata 中的用户字段。
            self.user_context = None
        # 服务身份字段来自 authz 对 service authority/route 的解析结果。
        self.invoke_service_app_id = authz_sign.invoke_service_app_id
        self.target_service_app_id = authz_sign.target_service_app_id
        # 签名 payload 覆盖完毕后同步重建决策上下文。
        self.rebuild_decision_context()


@dataclass(slots=True)
class BuildContextOptions:
    """构建服务主上下文时的本地运行信息与可选验签规则。"""

    service_app_id: str = ""
    service_instance_id: str = ""
    authz_verification: AuthzSignVerificationOptions | None = None
