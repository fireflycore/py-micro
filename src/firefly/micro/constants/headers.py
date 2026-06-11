"""Firefly 微服务通信中稳定使用的 HTTP header / gRPC metadata key。"""

# 所有 Firefly 自定义 header/metadata 都使用统一前缀，便于跨 HTTP/gRPC 网关清洗。
HEADER_PREFIX = "x-firefly-"

# 代理和 W3C trace 头不参与权限判定，但需要在出站白名单中保留。
X_REAL_IP = "x-real-ip"
X_FORWARDED_FOR = "x-forwarded-for"
TRACE_PARENT = "traceparent"
TRACE_STATE = "tracestate"
BAGGAGE = "baggage"

# 客户端运行环境信息用于日志和下游观测，不作为 authz 主体来源。
APP_LANGUAGE = HEADER_PREFIX + "app-language"
APP_VERSION = HEADER_PREFIX + "app-version"

# authz 判定相关字段，AUTHZ_SIGN 是跨进程可信身份的唯一签名载体。
SUBJECT_TYPE = HEADER_PREFIX + "subject-type"
DECISION_ID = HEADER_PREFIX + "decision-id"
AUTHZ_SIGN = HEADER_PREFIX + "authz-sign"

# 系统/客户端事实来自入口或 SDK，用于访问日志和链路诊断。
SYSTEM_TYPE = HEADER_PREFIX + "system-type"
SYSTEM_NAME = HEADER_PREFIX + "system-name"
SYSTEM_VERSION = HEADER_PREFIX + "system-version"
CLIENT_TYPE = HEADER_PREFIX + "client-type"
CLIENT_NAME = HEADER_PREFIX + "client-name"
CLIENT_VERSION = HEADER_PREFIX + "client-version"

# authority 原文需要沿调用链传递，但每一跳的 service authority 必须被当前服务覆盖。
USER_AUTHORITY = HEADER_PREFIX + "user-authority"
SERVICE_AUTHORITY = HEADER_PREFIX + "service-authority"

# 当前服务自身身份来自本地配置，只应在本进程入口上下文使用。
SERVICE_APP_ID = HEADER_PREFIX + "service-app-id"
SERVICE_INSTANCE_ID = HEADER_PREFIX + "service-instance-id"

# 用户身份字段是普通 metadata 视图；启用验签后必须由 AuthzSign 覆盖。
USER_ID = HEADER_PREFIX + "user-id"
SESSION = HEADER_PREFIX + "session"
ORG_IDS = HEADER_PREFIX + "org-ids"
POST_IDS = HEADER_PREFIX + "post-ids"
ROLE_IDS = HEADER_PREFIX + "role-ids"
APP_ID = HEADER_PREFIX + "app-id"
TENANT_ID = HEADER_PREFIX + "tenant-id"

# invoke/target 表达 authz 判定中的调用方和被访问应用。
INVOKE_APP_ID = HEADER_PREFIX + "invoke-app-id"
TARGET_APP_ID = HEADER_PREFIX + "target-app-id"

# api_method/api_path 表达授权动作与资源，gRPC 场景 api_path 对应 FullMethod。
API_METHOD = HEADER_PREFIX + "api-method"
API_PATH = HEADER_PREFIX + "api-path"

# 主体类型字符串与 Go constant 保持一致，避免跨语言 claim 值分叉。
SUBJECT_TYPE_ANONYMOUS = "anonymous"
SUBJECT_TYPE_USER = "user"
SUBJECT_TYPE_SERVICE = "service"

# 出站链路只允许这些字段继续跨进程传播，避免把上一跳普通身份字段带到下一跳。
OUTGOING_AUTHORITY_METADATA_ALLOWLIST = frozenset(
    {
        USER_AUTHORITY,
        AUTHZ_SIGN,
        TRACE_PARENT,
        TRACE_STATE,
        BAGGAGE,
        X_REAL_IP,
        X_FORWARDED_FOR,
        APP_LANGUAGE,
        APP_VERSION,
        SYSTEM_TYPE,
        SYSTEM_NAME,
        SYSTEM_VERSION,
        CLIENT_TYPE,
        CLIENT_NAME,
        CLIENT_VERSION,
    }
)
