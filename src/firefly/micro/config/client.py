"""统一配置 Store 与 Client 抽象。"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, TypeVar

from ..errors import ConfigStoreMissingError
from .model import ConfigKey, RawConfig
from .payload import decode_payload

T = TypeVar("T")


class Store(Protocol):
    """配置存储协议，由 Consul、Kubernetes 或测试实现承接。"""

    async def get(self, key: ConfigKey) -> RawConfig:
        """按配置键读取当前配置。"""

    async def put(self, key: ConfigKey, raw: RawConfig) -> None:
        """写入当前配置。"""

    async def delete(self, key: ConfigKey) -> None:
        """删除当前配置。"""


class Client(Protocol):
    """聚合缓存与 Store 的统一配置读取入口。"""

    async def get(self, key: ConfigKey) -> RawConfig:
        """读取当前可用配置，调用方不感知是否命中缓存。"""


class WatchMode:
    """配置客户端 watch 开关。"""

    # 关闭 watch 时只依赖直接读取或 TTL 缓存，首期 Python 版默认使用该模式。
    OFF = "off"
    # 开启 watch 的具体后端由 py-consul 或 k8s 适配层实现，micro 只保留配置枚举。
    ON = "on"


class WatchScope:
    """共享 watch 聚合粒度。"""

    # per_key 表示每条配置独立监听，适合低频关键配置。
    PER_KEY = "per_key"
    # group 表示按配置组聚合监听，是 Go 版当前默认口径。
    GROUP = "group"
    # app 表示按应用聚合监听，适合 watch 后端成本较高的场景。
    APP = "app"


@dataclass(slots=True)
class ClientOptions:
    """统一配置 Client 的运行参数。"""

    timeout: float = 5.0
    enable_cache: bool = True
    cache_max_entries: int = 1024
    cache_ttl: timedelta = timedelta(seconds=30)
    watch_mode: str = WatchMode.OFF
    watch_scope: str = WatchScope.GROUP
    watch_buffer: int = 8

    def normalized(self) -> "ClientOptions":
        """按 Go 版默认值补齐非法或空配置。"""

        # 非正 timeout 没有意义，回落到启动层默认 5 秒。
        timeout = self.timeout if self.timeout > 0 else 5.0
        # 缓存容量必须为正，否则会导致启用缓存后无法写入任何条目。
        cache_max_entries = self.cache_max_entries if self.cache_max_entries > 0 else 1024
        # TTL 非正时回落到 30 秒，避免缓存永不过期或立即失效的误配置。
        cache_ttl = self.cache_ttl if self.cache_ttl > timedelta(0) else timedelta(seconds=30)
        # watch buffer 非正时回落到 Go 版默认缓冲区大小。
        watch_buffer = self.watch_buffer if self.watch_buffer > 0 else 8
        return ClientOptions(
            timeout=timeout,
            enable_cache=self.enable_cache,
            cache_max_entries=cache_max_entries,
            cache_ttl=cache_ttl,
            watch_mode=self.watch_mode or WatchMode.OFF,
            watch_scope=self.watch_scope or WatchScope.GROUP,
            watch_buffer=watch_buffer,
        )


@dataclass(slots=True)
class _CacheEntry:
    """本地配置缓存条目。"""

    raw: RawConfig
    expires_at: datetime


class StoreClient:
    """基于 Store 的轻量配置 Client，首期只实现 TTL 缓存。"""

    def __init__(self, store: Store, options: ClientOptions | None = None) -> None:
        if store is None:
            # Client 没有 Store 就无法读取配置，启动期应明确失败。
            raise ConfigStoreMissingError("config store is missing")
        # 底层 Store 由 py-consul 等包注入，micro 不绑定具体后端。
        self._store = store
        # 归一化 options 后再使用，避免热路径反复处理默认值。
        self._options = (options or ClientOptions()).normalized()
        # 缓存按 ConfigKey 的规范化 tuple 存储，避免 dataclass 可变字段影响 hash。
        self._cache: dict[tuple[str, str, str, str, str], _CacheEntry] = {}

    async def get(self, key: ConfigKey) -> RawConfig:
        """读取配置，启用缓存时优先返回未过期副本。"""

        # 入口先校验 key，防止底层 Store 收到非法主键。
        key.validate()
        cache_key = _cache_key(key)
        if self._options.enable_cache:
            # 命中缓存且未过期时直接返回 RawConfig 副本，避免外部修改缓存对象。
            entry = self._cache.get(cache_key)
            if entry is not None and datetime.now(UTC) < entry.expires_at:
                return _clone_raw(entry.raw)
        # 缓存未命中时读取底层 Store。
        raw = await self._store.get(key)
        if self._options.enable_cache:
            # 写入缓存前做容量控制，首期采用简单 FIFO 式淘汰。
            self._prune_cache_if_needed()
            self._cache[cache_key] = _CacheEntry(_clone_raw(raw), datetime.now(UTC) + self._options.cache_ttl)
        # 对外始终返回副本，避免调用方修改影响后续读取。
        return _clone_raw(raw)

    def invalidate(self, key: ConfigKey | None = None) -> None:
        """清理指定 key 或全部本地缓存。"""

        if key is None:
            # watch 断线或批量配置切换时可直接清空缓存。
            self._cache.clear()
            return
        # 删除指定 key 的缓存，下一次 get 会回源读取。
        self._cache.pop(_cache_key(key), None)

    def _prune_cache_if_needed(self) -> None:
        if len(self._cache) < self._options.cache_max_entries:
            # 容量未满时不做额外工作，保持热路径轻量。
            return
        # dict 在 Python 3.7+ 保持插入顺序，首个 key 可作为最早写入条目。
        oldest = next(iter(self._cache), None)
        if oldest is not None:
            self._cache.pop(oldest, None)


class MemoryStore:
    """内存 Store 实现，供单测和本地样板使用。"""

    def __init__(self, values: dict[tuple[str, str, str, str, str], RawConfig] | None = None) -> None:
        # 初始化时复制配置，避免测试传入字典后继续修改内部状态。
        self._values = {key: _clone_raw(value) for key, value in (values or {}).items()}

    async def get(self, key: ConfigKey) -> RawConfig:
        """读取内存配置。"""

        # key.validate 保持和真实 Store 一致的主键校验。
        key.validate()
        try:
            return _clone_raw(self._values[_cache_key(key)])
        except KeyError as exc:
            # micro 包不定义具体后端的 NotFound 类型，这里用 KeyError 保持轻量。
            raise KeyError("config resource not found") from exc

    async def put(self, key: ConfigKey, raw: RawConfig) -> None:
        """写入内存配置。"""

        key.validate()
        # 写入副本，避免调用方后续修改 RawConfig 时影响 Store 中的值。
        self._values[_cache_key(key)] = _clone_raw(raw)

    async def delete(self, key: ConfigKey) -> None:
        """删除内存配置。"""

        key.validate()
        # 删除缺失 key 时保持幂等，和多数配置后端删除语义一致。
        self._values.pop(_cache_key(key), None)


@dataclass(slots=True)
class StoreParams:
    """从 Store 读取并解析一条结构化配置所需的参数。"""

    key: ConfigKey
    app_secret: bytes = b""
    decoder: Callable[[dict[str, Any]], T] | None = None
    client: Client | None = None


async def load_store_config(params: StoreParams) -> Any:
    """从配置 Client 读取 RawConfig，并按 JSON payload 解析目标结构。"""

    if params.client is None:
        # Go 版 LoadStoreConfig 在 store 为空时快速失败；Python 版同样避免隐藏 None。
        raise ConfigStoreMissingError("config store is missing")
    # RawConfig.content 保存的是 encode_payload 输出的字符串 bytes。
    raw = await params.client.get(params.key)
    content = raw.content.decode("utf-8")
    # 统一按 payload 流程还原 JSON bytes，密文场景需要调用方后续传入 encryptor 扩展。
    decoded = decode_payload(content, encrypted=raw.encrypted, secret=params.app_secret)
    payload = json.loads(decoded.decode("utf-8"))
    if params.decoder is None:
        # 未提供 decoder 时直接返回 dict/list 等 JSON 原生结构，适合配置桥接层使用。
        return payload
    if not isinstance(payload, dict):
        # decoder 接口约定接受 JSON object，避免把 list/str 误交给 Pydantic/dataclass 构造器。
        raise TypeError("config payload must be a JSON object")
    # decoder 可以是 Pydantic model_validate，也可以是 dataclass/自定义函数。
    return params.decoder(payload)


def _cache_key(key: ConfigKey) -> tuple[str, str, str, str, str]:
    # 主键字段统一 trim，确保缓存键和 Store 路径语义一致。
    return (
        key.namespace.strip(),
        key.env.strip(),
        key.app_id.strip(),
        key.group.strip(),
        key.key.strip(),
    )


def _clone_raw(raw: RawConfig) -> RawConfig:
    # RawConfig 是可变对象，对外返回或缓存时都复制一份，避免共享状态。
    return RawConfig(
        content=bytes(raw.content),
        meta=dict(raw.meta),
        version=raw.version,
        encrypted=raw.encrypted,
        created_at=raw.created_at,
        updated_at=raw.updated_at,
        updated_by=raw.updated_by,
    )
