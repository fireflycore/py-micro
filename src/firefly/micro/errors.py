"""Firefly micro 公共错误类型。"""


class FireflyMicroError(Exception):
    """公共包根错误，便于调用方统一捕获。"""


# authz sign 错误按 Go 版语义拆分，方便入口 middleware 映射成明确状态码。
class AuthzSignMissingError(FireflyMicroError):
    """入口请求没有携带 authz compact JWS。"""


class AuthzSignMalformedError(FireflyMicroError):
    """authz compact JWS 格式或 JSON 内容不合法。"""


class AuthzSignPublicKeyMissingError(FireflyMicroError):
    """无法根据 kid 或单公钥配置找到 Ed25519 公钥。"""


class AuthzSignUnsupportedAlgError(FireflyMicroError):
    """JWS alg 不是 Firefly 当前允许的 EdDSA。"""


class AuthzSignInvalidSignatureError(FireflyMicroError):
    """JWS 签名验证失败。"""


class AuthzSignInvalidClaimsError(FireflyMicroError):
    """JWS claim 缺少必要字段或与本地期望不一致。"""


class AuthzSignExpiredError(FireflyMicroError):
    """JWS 已经过期。"""


class AuthzSignNotYetValidError(FireflyMicroError):
    """JWS 尚未到允许使用时间。"""


# service authority 错误独立分层，调用方可以区分配置错误、刷新失败和热路径不可用。
class ServiceAuthorityFetchMissingError(FireflyMicroError):
    """启用 service authority 时未配置取 token 函数。"""


class ServiceTokenUnavailableError(FireflyMicroError):
    """当前进程还没有可用于出站调用的 service token。"""


class ServiceAuthorityTokenMissingError(FireflyMicroError):
    """取到的 service token 为空，不能写入出站请求。"""


class ServiceAuthorityTokenExpiresAtMissingError(FireflyMicroError):
    """service token 没有明确过期时间，无法做动态轮换。"""


class ServiceAuthorityTokenExpiredError(FireflyMicroError):
    """取到的 service token 已经过期。"""


# 配置错误保留在 micro 包内，供 py-consul 或其它后端复用统一模型。
class InvalidConfigKeyError(FireflyMicroError):
    """配置 Key 缺少必要字段。"""


class InvalidRawConfigError(FireflyMicroError):
    """配置 Raw 内容不满足持久化契约。"""


# 运行时配置错误独立保留，方便 py-layout 启动期把配置问题映射为快速失败。
class BootstrapConfigError(FireflyMicroError):
    """应用、内核或服务启动配置不满足 Firefly 基线。"""


# 配置客户端错误用于统一表达公共配置抽象的装配问题。
class ConfigStoreMissingError(FireflyMicroError):
    """配置客户端缺少底层 Store 实现。"""


# invocation 错误按 Go 版命名拆分，便于调用方做精确告警和降级处理。
class ConnectionManagerClosedError(FireflyMicroError):
    """连接管理器已经关闭，不能再创建新连接。"""


class InvokerDialerMissingError(FireflyMicroError):
    """调用器缺少连接获取依赖。"""


class InvokeMethodEmptyError(FireflyMicroError):
    """远程调用方法名为空。"""


class RemoteServiceNotFoundError(FireflyMicroError):
    """未找到指定远程业务服务。"""
