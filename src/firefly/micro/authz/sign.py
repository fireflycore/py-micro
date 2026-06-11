"""authz compact JWS 验签与 claim 归一化。"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .. import constants
from ..errors import (
    AuthzSignExpiredError,
    AuthzSignInvalidClaimsError,
    AuthzSignInvalidSignatureError,
    AuthzSignMalformedError,
    AuthzSignMissingError,
    AuthzSignNotYetValidError,
    AuthzSignPublicKeyMissingError,
    AuthzSignUnsupportedAlgError,
)
from .keys import resolve_public_key
from .time import ensure_aware_utc, utcnow

DEFAULT_KID = "default"
DEFAULT_ISSUER = "firefly-authz"
DEFAULT_CLOCK_SKEW = timedelta(seconds=5)


@dataclass(slots=True)
class AuthzUserContext:
    """JWS payload 中 user_context 的结构化用户身份。"""

    user_id: str = ""
    app_id: str = ""
    tenant_id: str = ""
    session: str = ""
    org_ids: list[str] = field(default_factory=list)
    post_ids: list[str] = field(default_factory=list)
    role_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> "AuthzUserContext | None":
        if not raw:
            # Go 版在 user_context 缺失时保留 nil，匿名和服务主体都不应伪造用户身份。
            return None
        # 列表字段保持副本，避免业务侧修改 claim 对象时影响调用方原始数据。
        return cls(
            # 字符串字段按 Go 零值语义兜底为空串，避免 None 泄露给业务层。
            user_id=str(raw.get("user_id") or ""),
            app_id=str(raw.get("app_id") or ""),
            tenant_id=str(raw.get("tenant_id") or ""),
            session=str(raw.get("session") or ""),
            org_ids=_string_list(raw.get("org_ids")),
            post_ids=_string_list(raw.get("post_ids")),
            role_ids=_string_list(raw.get("role_ids")),
        )


@dataclass(slots=True)
class AuthzSign:
    """`x-firefly-authz-sign` compact JWS 验签通过后的可信 payload。"""

    key_id: str = ""
    issuer: str = ""
    subject_id: str = ""
    subject_type: str = ""
    user_id: str = ""
    app_id: str = ""
    session: str = ""
    tenant_id: str = ""
    org_ids: list[str] = field(default_factory=list)
    post_ids: list[str] = field(default_factory=list)
    role_ids: list[str] = field(default_factory=list)
    invoke_app_id: str = ""
    target_app_id: str = ""
    api_method: str = ""
    api_path: str = ""
    decision: str = ""
    decision_id: str = ""
    trace_id: str = ""
    user_context: AuthzUserContext | None = None
    invoke_service_app_id: str = ""
    target_service_app_id: str = ""
    issued_at: int = 0
    not_before: int = 0
    expires_at: int = 0

    @classmethod
    def from_claims(cls, key_id: str, claims: Mapping[str, Any]) -> "AuthzSign":
        # user_context 是 authz 当前约定的用户身份来源，平铺字段只在验签后派生。
        user_context = AuthzUserContext.from_mapping(claims.get("user_context"))
        # 只读取 JWS payload 中的稳定 claim，保持与 Go AuthzSign JSON tag 的跨语言契约一致。
        value = cls(
            key_id=key_id,
            issuer=str(claims.get("iss") or ""),
            subject_id=str(claims.get("sub") or ""),
            subject_type=str(claims.get("subject_type") or ""),
            invoke_app_id=str(claims.get("invoke_app_id") or ""),
            target_app_id=str(claims.get("target_app_id") or ""),
            api_method=str(claims.get("api_method") or ""),
            api_path=str(claims.get("api_path") or ""),
            decision=str(claims.get("decision") or ""),
            decision_id=str(claims.get("decision_id") or ""),
            trace_id=str(claims.get("trace_id") or ""),
            user_context=user_context,
            invoke_service_app_id=str(claims.get("invoke_service_app_id") or ""),
            target_service_app_id=str(claims.get("target_service_app_id") or ""),
            issued_at=_int_claim(claims.get("iat")),
            not_before=_int_claim(claims.get("nbf")),
            expires_at=_int_claim(claims.get("exp")),
        )
        # 将结构化用户身份投影为进程内便利字段，业务层无需直接解析 user_context。
        value.normalize()
        return value

    def normalize(self) -> None:
        """从结构化 user_context 派生进程内读取便利字段。"""

        if self.user_context is None:
            # 服务和匿名主体没有用户上下文，保持平铺用户字段为空值。
            return
        # 以下字段只从已验签的 user_context 派生，避免继续接受旧版平铺身份 claim。
        self.user_id = self.user_context.user_id
        self.app_id = self.user_context.app_id
        self.tenant_id = self.user_context.tenant_id
        self.session = self.user_context.session
        # 列表字段复制一份，避免调用方改 AuthzSign 时反向污染 user_context。
        self.org_ids = list(self.user_context.org_ids)
        self.post_ids = list(self.user_context.post_ids)
        self.role_ids = list(self.user_context.role_ids)


@dataclass(slots=True)
class AuthzSignVerificationOptions:
    """服务侧本地验签 `x-firefly-authz-sign` 的规则。"""

    public_key: Ed25519PublicKey | bytes | None = None
    public_keys: Mapping[str, Ed25519PublicKey | bytes] = field(default_factory=dict)
    issuer: str = ""
    expected_api_method: str = ""
    expected_api_path: str = ""
    clock_skew: timedelta = DEFAULT_CLOCK_SKEW
    now: Callable[[], datetime] | None = None


def verify_authz_sign(raw: str, options: AuthzSignVerificationOptions) -> AuthzSign:
    """校验 authz compact JWS，并返回可信 claim。"""

    # 先裁剪外部 header/metadata 值，避免首尾空白影响 compact JWS 分段。
    raw = (raw or "").strip()
    if not raw:
        # 缺少 JWS 由入口策略决定是否可跳过；本函数只表达验签失败原因。
        raise AuthzSignMissingError("authz sign is missing")

    # compact JWS 固定为 header.payload.signature 三段，任何空段都直接拒绝。
    parts = raw.split(".")
    if len(parts) != 3 or not all(parts):
        raise AuthzSignMalformedError("authz sign is malformed")

    # 先解析 header，拿到 alg/kid 后才能判断算法和选择公钥。
    header = _decode_json_segment(parts[0])
    alg = str(header.get("alg") or "")
    kid = str(header.get("kid") or "")
    if alg != constants.JWS_ALGORITHM_EDDSA:
        # Firefly authz 当前只允许 EdDSA/Ed25519，拒绝算法降级或替换。
        raise AuthzSignUnsupportedAlgError("authz sign alg is unsupported")

    # 多公钥模式通过 kid 选钥；单公钥模式用于简单部署和测试。
    public_key = resolve_public_key(kid, options.public_key, options.public_keys)
    # Ed25519 的签名输入必须保持原始 base64url header.payload，不能重新序列化 JSON。
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    # signature 段使用 JWS base64url 编码，解码失败统一视为格式错误。
    signature = _decode_segment(parts[2])
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        # 签名失败说明 payload 不可信，后续 claim 校验不能继续。
        raise AuthzSignInvalidSignatureError("authz sign signature is invalid") from exc

    # 签名通过后再解析 payload，避免在未可信数据上做业务 claim 处理。
    claims = _decode_json_segment(parts[1])
    # 将 JSON claim 归一成稳定结构，并保留 header kid 方便排障。
    value = AuthzSign.from_claims(kid, claims)
    # 最后校验 issuer、主体、时间窗口和当前入口方法/路径事实。
    _validate_authz_sign_claims(value, options)
    return value


def _validate_authz_sign_claims(claims: AuthzSign, options: AuthzSignVerificationOptions) -> None:
    if options.issuer and claims.issuer != options.issuer:
        # 配置了 issuer 时必须严格匹配，防止其他签发方 token 混入。
        raise AuthzSignInvalidClaimsError("authz sign claims are invalid")
    if not all([claims.subject_id, claims.subject_type, claims.target_app_id, claims.api_method, claims.api_path]):
        # 主体、目标应用、授权动作和资源路径是进入业务服务的最小可信 claim。
        raise AuthzSignInvalidClaimsError("authz sign claims are invalid")
    if claims.subject_type != constants.SUBJECT_TYPE_ANONYMOUS and not claims.invoke_app_id:
        # 非匿名请求必须有调用方 app_id；匿名公共接口允许为空。
        raise AuthzSignInvalidClaimsError("authz sign claims are invalid")
    if claims.subject_type == constants.SUBJECT_TYPE_USER:
        if claims.user_context is None or not claims.user_context.user_id or not claims.user_context.app_id:
            # 用户主体必须携带结构化 user_context，避免旧平铺身份 claim 被接受。
            raise AuthzSignInvalidClaimsError("authz sign claims are invalid")
        if claims.invoke_app_id != claims.user_context.app_id:
            # 用户主体的权限主体来自 user_context.app_id，不能被平铺 invoke_app_id 篡改。
            raise AuthzSignInvalidClaimsError("authz sign claims are invalid")
    if claims.subject_type == constants.SUBJECT_TYPE_SERVICE:
        if not claims.invoke_service_app_id or claims.invoke_app_id != claims.invoke_service_app_id:
            # 服务主体必须由 service authority 解析结果确认，不能只靠 invoke_app_id。
            raise AuthzSignInvalidClaimsError("authz sign claims are invalid")
    if not claims.target_service_app_id or claims.target_app_id != claims.target_service_app_id:
        # target_app_id 必须与 route 映射出的目标服务 app_id 一致，避免授权结果跨服务复用。
        raise AuthzSignInvalidClaimsError("authz sign claims are invalid")
    if claims.decision != "allow":
        # authz 只会把 allow 结果注入业务服务，非 allow 或缺失 decision 都拒绝。
        raise AuthzSignInvalidClaimsError("authz sign claims are invalid")

    # 默认使用当前 UTC 时间，测试可通过 options.now 注入固定时钟。
    now = ensure_aware_utc(options.now()) if options.now else utcnow()
    # clock_skew 只用于容忍小范围机器时钟偏差，不改变 exp/nbf 的基础语义。
    skew = options.clock_skew or timedelta(0)
    if claims.expires_at <= 0 or now - skew >= datetime.fromtimestamp(claims.expires_at, UTC):
        # exp 是必需字段；超过可容忍窗口后 token 立即失效。
        raise AuthzSignExpiredError("authz sign is expired")
    if claims.not_before > 0 and now + skew < datetime.fromtimestamp(claims.not_before, UTC):
        # nbf 可选；写入时表示 token 在该时间前不可使用。
        raise AuthzSignNotYetValidError("authz sign is not yet valid")
    if options.expected_api_method and claims.api_method.upper() != options.expected_api_method.upper():
        # 授权动作必须匹配当前入口；gRPC 入口通常要求 GRPC。
        raise AuthzSignInvalidClaimsError("authz sign claims are invalid")
    if options.expected_api_path and claims.api_path != options.expected_api_path:
        # 资源路径必须匹配当前 HTTP path 或 gRPC FullMethod，防止跨接口复用。
        raise AuthzSignInvalidClaimsError("authz sign claims are invalid")


def _decode_json_segment(segment: str) -> dict[str, Any]:
    try:
        # header 和 payload 都是 base64url(JSON)，解码链路保持 JWS 标准顺序。
        payload = _decode_segment(segment)
        raw = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthzSignMalformedError("authz sign is malformed") from exc
    if not isinstance(raw, dict):
        # Firefly claim/header 必须是 JSON object，数组或标量没有可验签语义。
        raise AuthzSignMalformedError("authz sign is malformed")
    return raw


def _decode_segment(segment: str) -> bytes:
    try:
        # Python base64 需要补齐 padding；JWS compact 传输本身仍保持无 padding。
        padding = "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise AuthzSignMalformedError("authz sign is malformed") from exc


def _string_list(value: Any) -> list[str]:
    if value is None:
        # Go JSON 反序列化缺失切片时等价于 nil，Python 对外返回空列表更易用。
        return []
    if isinstance(value, list | tuple):
        # 复制并过滤 None，避免无效 claim 值进入进程内上下文。
        return [str(item) for item in value if item is not None]
    # 兼容上游偶发单值写法，仍归一为 metadata/claim 使用的列表语义。
    return [str(value)]


def _int_claim(value: Any) -> int:
    if value in (None, ""):
        # 可选 Unix 秒字段缺失时按 Go 零值处理，后续 claim 校验决定是否允许。
        return 0
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        # 时间 claim 不能转成整数时说明 JWS payload 本身格式不合法。
        raise AuthzSignMalformedError("authz sign is malformed") from exc
