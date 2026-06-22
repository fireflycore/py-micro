"""远程连接缓存管理。"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..errors import ConnectionManagerClosedError
from .target import Target


class Closable(Protocol):
    """底层连接可选关闭协议。"""

    def close(self) -> object:
        """关闭连接资源。"""


class AsyncClosable(Protocol):
    """底层连接可选异步关闭协议。"""

    async def aclose(self) -> object:
        """异步关闭连接资源。"""


DialFunc = Callable[[Target], Any | Awaitable[Any]]


@dataclass(slots=True)
class ConnectionManagerOptions:
    """连接管理器配置。"""

    dial: DialFunc
    # 额外选项保留给 py-layout 绑定 grpc.aio.Channel 时使用，micro 不解释具体含义。
    options: dict[str, object] = field(default_factory=dict)


class ConnectionManager:
    """按最终 Target 缓存底层连接对象。"""

    def __init__(self, options: ConnectionManagerOptions) -> None:
        if options.dial is None:
            # 没有 dial 函数就无法创建任何连接，启动装配层应立即失败。
            raise ValueError("dial function is required")
        # dial 函数由应用层提供，可能返回 grpc channel、HTTP client 或测试桩。
        self._dial = options.dial
        # 连接缓存键使用最终 grpc target，和 Go 版 ConnectionManager 对齐。
        self._connections: dict[str, Any] = {}
        # 关闭标记防止 close 后继续创建新连接。
        self._closed = False

    async def dial(self, target: Target) -> Any:
        """获取或创建指定 target 的连接。"""

        if self._closed:
            raise ConnectionManagerClosedError("connection manager is closed")
        # Target 自己负责校验 host/port/resolver，缓存键保持唯一且可读。
        key = target.grpc_target
        if key in self._connections:
            # 缓存命中时直接复用底层连接，避免重复建连。
            return self._connections[key]
        # dial 可能是同步工厂，也可能是 async 工厂，公共包统一 await 兼容。
        conn = self._dial(target)
        if inspect.isawaitable(conn):
            conn = await conn
        if self._closed:
            # 拨号过程中如果管理器被关闭，要尽力释放刚创建的连接。
            await _close_connection(conn)
            raise ConnectionManagerClosedError("connection manager is closed")
        # 只在拨号成功后写入缓存，失败由调用方直接看到原始异常。
        self._connections[key] = conn
        return conn

    async def close(self) -> None:
        """关闭所有缓存连接，方法幂等。"""

        if self._closed:
            return
        # 先标记关闭，避免关闭过程中又有新 dial 写入缓存。
        self._closed = True
        # 拷贝 values 后清空缓存，关闭失败也不保留半关闭对象。
        connections = list(self._connections.values())
        self._connections.clear()
        first_error: BaseException | None = None
        for conn in connections:
            try:
                await _close_connection(conn)
            except BaseException as exc:  # noqa: BLE001 - close 要尽力处理全部连接。
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            # 保留第一条错误，便于调用方在 shutdown 阶段记录根因。
            raise first_error


async def _close_connection(conn: Any) -> None:
    if conn is None:
        # None 连接没有资源需要释放。
        return
    if hasattr(conn, "aclose"):
        # httpx.AsyncClient 等对象使用 aclose。
        result = conn.aclose()
    elif hasattr(conn, "close"):
        # grpc.aio.Channel.close 可能返回 awaitable，普通对象 close 可能同步完成。
        result = conn.close()
    else:
        # 没有关闭协议的测试桩直接忽略。
        return
    if inspect.isawaitable(result):
        await result
