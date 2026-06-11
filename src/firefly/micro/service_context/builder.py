"""入站 metadata 到 Firefly 服务上下文的映射。"""

from __future__ import annotations

from .. import constants
from ..authz import verify_authz_sign
from ..errors import AuthzSignInvalidClaimsError
from ..metadata import MetadataMapping, first_metadata_value, metadata_values
from .models import BuildContextOptions, ServiceContext


def build_context(metadata: MetadataMapping | None, options: BuildContextOptions | None = None) -> ServiceContext:
    """从入站 metadata 与运行时信息构造服务主上下文。"""

    # 未传 options 时仅按 metadata 构造普通上下文，保持轻量调用路径可用。
    options = options or BuildContextOptions()
    # 先从入站 metadata 构造基础上下文；这些字段在未验签模式下只是传输事实。
    value = ServiceContext(
        # 当前服务自身身份来自本地配置，不能由上游 metadata 覆盖。
        service_app_id=options.service_app_id,
        service_instance_id=options.service_instance_id,
        app_language=first_metadata_value(metadata, constants.APP_LANGUAGE),
        session=first_metadata_value(metadata, constants.SESSION),
        user_id=first_metadata_value(metadata, constants.USER_ID),
        app_id=first_metadata_value(metadata, constants.APP_ID),
        tenant_id=first_metadata_value(metadata, constants.TENANT_ID),
        org_ids=metadata_values(metadata, constants.ORG_IDS),
        post_ids=metadata_values(metadata, constants.POST_IDS),
        role_ids=metadata_values(metadata, constants.ROLE_IDS),
        subject_type=first_metadata_value(metadata, constants.SUBJECT_TYPE),
        invoke_app_id=first_metadata_value(metadata, constants.INVOKE_APP_ID),
        target_app_id=first_metadata_value(metadata, constants.TARGET_APP_ID),
        api_method=first_metadata_value(metadata, constants.API_METHOD),
        api_path=first_metadata_value(metadata, constants.API_PATH),
        decision_id=first_metadata_value(metadata, constants.DECISION_ID),
        authz_sign_jws=first_metadata_value(metadata, constants.AUTHZ_SIGN),
    )
    # 平铺 metadata 读取完成后立即补齐 UserContext/DecisionContext 派生视图。
    value.rebuild_derived_contexts()

    if options.authz_verification is None:
        # 没有配置验签时返回普通上下文，是否允许由框架层或业务入口决定。
        return value

    # 配置了验签时，authz_sign_jws 是唯一可信身份来源。
    authz_sign = verify_authz_sign(value.authz_sign_jws, options.authz_verification)
    if not options.service_app_id or authz_sign.target_app_id != options.service_app_id:
        # 当前服务 app_id 必须与签名中的目标 app_id 一致，防止授权结果跨服务复用。
        raise AuthzSignInvalidClaimsError("authz sign claims are invalid")
    # 验签和目标服务校验通过后，再覆盖普通 metadata 派生出的字段。
    value.apply_verified_authz_sign(authz_sign)
    return value
