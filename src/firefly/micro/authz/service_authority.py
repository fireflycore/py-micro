"""authz service authority token 缓存刷新。"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from ..errors import (
    ServiceAuthorityFetchMissingError,
    ServiceAuthorityTokenExpiredError,
    ServiceAuthorityTokenExpiresAtMissingError,
    ServiceAuthorityTokenMissingError,
    ServiceTokenUnavailableError,
)
from .time import ensure_aware_utc, utcnow

DEFAULT_SERVICE_AUTHORITY_REFRESH_BEFORE = timedelta(minutes=1)
DEFAULT_SERVICE_AUTHORITY_RETRY_BASE_INTERVAL = timedelta(minutes=1)
DEFAULT_SERVICE_AUTHORITY_RETRY_MAX_INTERVAL = timedelta(hours=1)


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
        if self._token and self._expires_at is not None and utcnow() < self._expires_at:
            return self._token
        if self._expires_at is not None and utcnow() >= self._expires_at:
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
        expires_at = ensure_aware_utc(token.expires_at)
        if utcnow() >= expires_at:
            # auth 服务若返回已经过期的 token，不能被缓存到热路径。
            raise ServiceAuthorityTokenExpiredError("authz service authority token is expired")
        # 只有通过所有校验后才同时更新 token 和过期时间，保持缓存状态一致。
        self._token = token.token
        self._expires_at = expires_at

    def _next_refresh_delay(self) -> timedelta:
        assert self._expires_at is not None
        # 下一轮刷新点是 exp - refresh_before，避免临界过期 token 被继续使用。
        delay = self._expires_at - utcnow() - self._refresh_before
        # token 已接近刷新窗口时立即进入下一轮，避免把临界 token 写入出站请求。
        return max(delay, timedelta(0))

    def _retry_delay(self, retry_count: int) -> timedelta:
        # 与 Go 版固定规则保持一致：base * 连续失败次数 * 10，最大值封顶。
        raw = self._retry_base_interval * retry_count * 10
        return min(raw, self._retry_max_interval)
