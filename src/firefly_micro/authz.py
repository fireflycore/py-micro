"""Firefly authz compact JWS 验签和 service authority 缓存刷新。"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import constants
from .errors import (
    AuthzSignExpiredError,
    AuthzSignInvalidClaimsError,
    AuthzSignInvalidSignatureError,
    AuthzSignMalformedError,
    AuthzSignMissingError,
    AuthzSignNotYetValidError,
    AuthzSignPublicKeyMissingError,
    AuthzSignUnsupportedAlgError,
    ServiceAuthorityFetchMissingError,
    ServiceAuthorityTokenExpiredError,
    ServiceAuthorityTokenExpiresAtMissingError,
    ServiceAuthorityTokenMissingError,
    ServiceTokenUnavailableError,
)

DEFAULT_KID = "default"
DEFAULT_ISSUER = "firefly-authz"
DEFAULT_CLOCK_SKEW = timedelta(seconds=5)
DEFAULT_SERVICE_AUTHORITY_REFRESH_BEFORE = timedelta(minutes=1)
DEFAULT_SERVICE_AUTHORITY_RETRY_BASE_INTERVAL = timedelta(minutes=1)
DEFAULT_SERVICE_AUTHORITY_RETRY_MAX_INTERVAL = timedelta(hours=1)


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
    public_key = _resolve_public_key(kid, options)
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


def load_ed25519_public_key(path: str | Path) -> Ed25519PublicKey:
    """从 PEM 文件加载 Ed25519 公钥。"""

    # 与 Go LoadEd25519PublicKey 一样，只接受 PEM 公钥文件作为启动期配置输入。
    data = Path(path).read_bytes()
    public_key = serialization.load_pem_public_key(data)
    if not isinstance(public_key, Ed25519PublicKey):
        # authz JWS 固定使用 Ed25519，其他算法即使能解析也不能参与验签。
        raise ValueError(f"expected Ed25519 public key: {path}")
    return public_key


@dataclass(slots=True)
class ServiceAuthorityToken:
    """auth 服务签发的服务身份凭证及过期时间。"""

    token: str
    expires_at: datetime


ServiceAuthorityFetch = Callable[[], ServiceAuthorityToken | Awaitable[ServiceAuthorityToken]]


class CachedServiceAuthorityProvider:
    """进程内缓存 service token，并在过期前主动刷新。"""

    def __init__(
        self,
        fetch: ServiceAuthorityFetch,
        *,
        refresh_before: timedelta = DEFAULT_SERVICE_AUTHORITY_REFRESH_BEFORE,
        retry_base_interval: timedelta = DEFAULT_SERVICE_AUTHORITY_RETRY_BASE_INTERVAL,
        retry_max_interval: timedelta = DEFAULT_SERVICE_AUTHORITY_RETRY_MAX_INTERVAL,
    ) -> None:
        if fetch is None:
            # provider 一旦被构造就必须能刷新服务 token，否则出站身份不可用。
            raise ServiceAuthorityFetchMissingError("authz service authority fetch function is missing")
        self._fetch = fetch
        # 非正刷新窗口没有业务意义，按 Go 版默认值兜底。
        self._refresh_before = refresh_before if refresh_before > timedelta(0) else DEFAULT_SERVICE_AUTHORITY_REFRESH_BEFORE
        # 测试可缩短退避间隔；生产默认保持 1 分钟基础间隔。
        self._retry_base_interval = retry_base_interval if retry_base_interval > timedelta(0) else DEFAULT_SERVICE_AUTHORITY_RETRY_BASE_INTERVAL
        # 最大退避不能小于基础退避，避免配置导致失败重试立即忙等。
        self._retry_max_interval = max(retry_max_interval, self._retry_base_interval)
        # token 缓存初始为空，Start 后由后台任务立即刷新。
        self._token = ""
        self._expires_at: datetime | None = None
        # 记录最近一次刷新失败，热路径可返回可诊断的不可用错误。
        self._last_refresh_error: BaseException | None = None
        # Python 版用 asyncio task/event 表达 Go 版后台协程和 cancel 语义。
        self._task: asyncio.Task[None] | None = None
        self._stop_event: asyncio.Event | None = None

    async def start(self) -> None:
        """启动后台刷新任务；首次 token 获取由后台任务立即执行。"""

        if self._task is not None and not self._task.done():
            # 已有刷新任务时直接复用，避免同一 provider 启动多个刷新循环。
            return
        self._stop_event = asyncio.Event()
        # 后台任务负责刷新，热路径只读缓存，避免每次出站调用都访问 auth 服务。
        self._task = asyncio.create_task(self._refresh_loop())

    async def stop(self) -> None:
        """停止后台刷新任务，不撤销已经签发的 token。"""

        if self._stop_event is not None:
            # 唤醒刷新循环，让它自然退出而不是取消到未知 await 点。
            self._stop_event.set()
        if self._task is not None:
            # 聚合异常后吞掉，保持 Stop 的幂等清理语义。
            await asyncio.gather(self._task, return_exceptions=True)
        # 清空生命周期状态，允许后续重新 start。
        self._task = None
        self._stop_event = None

    async def refresh_once(self) -> None:
        """立即刷新一次，适合启动期显式等待或测试使用。"""

        # fetch 可同步也可异步，方便业务方复用现有 SDK 或测试桩。
        token = self._fetch()
        if inspect.isawaitable(token):
            token = await token
        # 接受 token 前完成完整校验，避免把空值或过期值写入缓存。
        self._accept_token(token)
        # 成功刷新后清除旧错误，热路径恢复正常读取缓存。
        self._last_refresh_error = None

    async def service_authority(self) -> str:
        """返回当前可用 service token；不可用时不在热路径同步刷新。"""

        # 热路径只返回未过期缓存，保持与 Go 版“不在调用时同步 fetch”一致。
        if self._token and self._expires_at is not None and _utcnow() < self._expires_at:
            return self._token
        if self._expires_at is not None and _utcnow() >= self._expires_at:
            # 曾经有 token 但现在过期，要明确区分为过期而不是普通不可用。
            raise ServiceAuthorityTokenExpiredError("authz service authority token is expired")
        if self._last_refresh_error is not None:
            # 首次或后续刷新失败时保留原异常链，便于定位 auth 服务/网络问题。
            raise ServiceTokenUnavailableError("authz service token is unavailable") from self._last_refresh_error
        # 尚未刷新成功且没有具体错误时，统一表达当前没有可用服务身份。
        raise ServiceTokenUnavailableError("authz service token is unavailable")

    async def _refresh_loop(self) -> None:
        # 只统计连续失败次数，成功后必须清零以恢复正常刷新窗口。
        retry_count = 0
        assert self._stop_event is not None
        while not self._stop_event.is_set():
            try:
                # 每轮开头立即尝试刷新，所以 start 后会尽快获取首个 token。
                await self.refresh_once()
                retry_count = 0
                delay = self._next_refresh_delay()
            except BaseException as exc:  # noqa: BLE001 - 后台刷新要记录所有失败并继续退避。
                # 后台任务不能因一次 fetch 失败退出，记录错误后按 Go 版规则退避重试。
                self._last_refresh_error = exc
                retry_count += 1
                delay = self._retry_delay(retry_count)
            try:
                # 等待期间若 stop_event 被设置则提前退出；超时则进入下一轮刷新。
                await asyncio.wait_for(self._stop_event.wait(), timeout=delay.total_seconds())
            except TimeoutError:
                continue

    def _accept_token(self, token: ServiceAuthorityToken) -> None:
        if token is None or not token.token:
            # 空 token 不能写入出站 X-Firefly-Service-Authority。
            raise ServiceAuthorityTokenMissingError("authz service authority token is missing")
        if token.expires_at is None:
            # service token 必须可轮换；缺少过期时间会让后台刷新无法计算窗口。
            raise ServiceAuthorityTokenExpiresAtMissingError("authz service authority token expires_at is missing")
        expires_at = _ensure_aware_utc(token.expires_at)
        if _utcnow() >= expires_at:
            # auth 服务若返回已经过期的 token，不能被缓存到热路径。
            raise ServiceAuthorityTokenExpiredError("authz service authority token is expired")
        # 只有通过所有校验后才同时更新 token 和过期时间，保持缓存状态一致。
        self._token = token.token
        self._expires_at = expires_at

    def _next_refresh_delay(self) -> timedelta:
        assert self._expires_at is not None
        # 下一轮刷新点是 exp - refresh_before，避免临界过期 token 被继续使用。
        delay = self._expires_at - _utcnow() - self._refresh_before
        # token 已接近刷新窗口时立即进入下一轮，避免把临界 token 写入出站请求。
        return max(delay, timedelta(0))

    def _retry_delay(self, retry_count: int) -> timedelta:
        # 与 Go 版固定规则保持一致：base * 连续失败次数 * 10，最大值封顶。
        raw = self._retry_base_interval * retry_count * 10
        return min(raw, self._retry_max_interval)


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
    now = _ensure_aware_utc(options.now()) if options.now else _utcnow()
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


def _resolve_public_key(kid: str, options: AuthzSignVerificationOptions) -> Ed25519PublicKey:
    if options.public_keys:
        # 多公钥模式优先，用于密钥轮换期间同时接受新旧 kid。
        key = options.public_keys.get(kid)
        if key is None:
            raise AuthzSignPublicKeyMissingError("authz sign public key is missing")
        return _coerce_public_key(key)
    if options.public_key is not None:
        # 单公钥模式不依赖 kid，适合简单部署或测试。
        return _coerce_public_key(options.public_key)
    raise AuthzSignPublicKeyMissingError("authz sign public key is missing")


def _coerce_public_key(value: Ed25519PublicKey | bytes) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        # cryptography 公钥对象可直接用于 verify。
        return value
    if isinstance(value, bytes) and len(value) == 32:
        # Ed25519 原始公钥固定 32 字节，和 Go ed25519.PublicKeySize 保持一致。
        return Ed25519PublicKey.from_public_bytes(value)
    raise AuthzSignPublicKeyMissingError("authz sign public key is missing")


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


def _ensure_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        # 业务测试常传 naive datetime；按 UTC 解释以匹配 Unix 秒比较语义。
        return value.replace(tzinfo=UTC)
    # 统一转 UTC，避免本地时区影响 exp/nbf 或 token 过期判断。
    return value.astimezone(UTC)


def _utcnow() -> datetime:
    return datetime.now(UTC)
