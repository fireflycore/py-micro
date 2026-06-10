"""Firefly 配置中心公共模型与 payload 编解码。"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from .errors import InvalidConfigKeyError, InvalidRawConfigError


class Compressor(Protocol):
    """配置 payload 压缩器协议。"""

    def compress(self, data: bytes) -> bytes: ...

    def decompress(self, data: bytes) -> bytes: ...


class Encryptor(Protocol):
    """配置 payload 加解密器协议。"""

    def encrypt(self, data: bytes, secret: bytes) -> bytes: ...

    def decrypt(self, data: bytes, secret: bytes) -> bytes: ...


class IdentityCompressor:
    """默认不压缩实现，便于纯 Python 首版直接使用统一流程。"""

    def compress(self, data: bytes) -> bytes:
        # 返回 bytes 副本，保持 compressor 接口“输入不可被原地修改”的使用预期。
        return bytes(data)

    def decompress(self, data: bytes) -> bytes:
        # 解压路径同样返回副本，方便测试默认流程时不引入额外压缩依赖。
        return bytes(data)


@dataclass(slots=True)
class ConfigKey:
    """一条配置在存储中的业务主键。"""

    env: str
    app_id: str
    group: str
    key: str
    namespace: str = ""

    def validate(self) -> None:
        if not all([self.env.strip(), self.app_id.strip(), self.group.strip(), self.key.strip()]):
            # env/app_id/group/key 是存储主键的最小字段；namespace 允许为空以兼容默认命名空间。
            raise InvalidConfigKeyError("config key is invalid")


@dataclass(slots=True)
class RawConfig:
    """一条可发布、可读取的配置内容。"""

    content: bytes
    meta: dict[str, str] = field(default_factory=dict)
    version: str = ""
    encrypted: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None
    updated_by: str = ""

    def to_json_bytes(self) -> bytes:
        if self.content is None:
            # content 是 RawConfig 的核心内容，缺失时无法满足 Go Raw.Content 的持久化契约。
            raise InvalidRawConfigError("config raw is invalid")
        # 构造与 Go Raw JSON 标签一致的对象，方便跨语言读写同一配置记录。
        payload = {
            "meta": dict(self.meta),
            "version": self.version,
            # Go 的 []byte JSON 表示是 base64 字符串；Python 版显式保持该契约。
            "content": base64.b64encode(self.content).decode("ascii"),
            "encrypted": self.encrypted,
            "created_at": _format_datetime(self.created_at),
            "updated_at": _format_datetime(self.updated_at),
            "updated_by": self.updated_by,
        }
        # 紧凑 JSON 便于作为配置中心 payload 传输；ensure_ascii=False 保留业务原文。
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "RawConfig":
        # 输入来自统一 UTF-8 JSON payload，先还原 object 再做字段级归一化。
        raw = json.loads(data.decode("utf-8"))
        # Go []byte JSON 对应 base64 字符串，Python 读取时必须显式解码回 bytes。
        content = base64.b64decode(raw.get("content") or b"")
        return cls(
            content=content,
            # meta key/value 都归一为字符串，避免不同 JSON 编码器产生类型差异。
            meta={str(k): str(v) for k, v in dict(raw.get("meta") or {}).items()},
            version=str(raw.get("version") or ""),
            encrypted=bool(raw.get("encrypted")),
            created_at=_parse_datetime(raw.get("created_at")),
            updated_at=_parse_datetime(raw.get("updated_at")),
            updated_by=str(raw.get("updated_by") or ""),
        )


class EventType(StrEnum):
    """配置变更事件类型。"""

    PUT = "put"
    DELETE = "delete"


@dataclass(slots=True)
class WatchEvent:
    """配置 watch 通知事件。"""

    type: EventType
    key: ConfigKey
    raw: RawConfig | None = None


def encode_payload(
    content: bytes,
    *,
    encrypted: bool = False,
    secret: bytes = b"",
    compressor: Compressor | None = None,
    encryptor: Encryptor | None = None,
) -> str:
    """按压缩、可选加密、Base64 的顺序编码配置内容。"""

    # 未传 compressor 时使用 identity 实现，保持 Go 流程顺序但不强制压缩依赖。
    compressor = compressor or IdentityCompressor()
    # 编码顺序固定先压缩，保证加密对象是压缩后的完整配置内容。
    data = compressor.compress(content)
    if encrypted:
        if encryptor is None:
            # 标记 encrypted 时必须提供 encryptor，否则无法生成可被读取方解密的内容。
            raise InvalidRawConfigError("config encryptor is required")
        # 加密 secret 由调用方管理，公共包只定义处理顺序。
        data = encryptor.encrypt(data, secret)
    # 最终持久化字符串使用标准 Base64，与 Go base64.StdEncoding 保持一致。
    return base64.b64encode(data).decode("ascii")


def decode_payload(
    content: str,
    *,
    encrypted: bool = False,
    secret: bytes = b"",
    compressor: Compressor | None = None,
    encryptor: Encryptor | None = None,
) -> bytes:
    """按 Base64、可选解密、解压的顺序还原配置内容。"""

    # 解码路径必须使用与 encode_payload 相反的顺序。
    compressor = compressor or IdentityCompressor()
    # 持久化层只保存 ASCII Base64 字符串，先还原为二进制内容。
    data = base64.b64decode(content.encode("ascii"))
    if encrypted:
        if encryptor is None:
            # encrypted 内容没有 decryptor 时无法还原，必须明确失败。
            raise InvalidRawConfigError("config encryptor is required")
        # 先解密再解压，和 Go DecodePayload 顺序一致。
        data = encryptor.decrypt(data, secret)
    # 最后返回原始配置 bytes，由调用方决定如何反序列化。
    return compressor.decompress(data)


def marshal_payload(value: Mapping[str, object] | list[object] | str | int | float | bool | None, **kwargs: object) -> str:
    """把结构化对象编码成统一持久化字符串。"""

    # 先转成紧凑 UTF-8 JSON，再复用统一 payload 编码链路。
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return encode_payload(data, **kwargs)


def unmarshal_payload(content: str, **kwargs: object) -> object:
    """把统一持久化字符串解码回 JSON 对象。"""

    # 先按统一链路还原 bytes，再按 JSON 解出业务对象。
    return json.loads(decode_payload(content, **kwargs).decode("utf-8"))


def _format_datetime(value: datetime | None) -> str | None:
    if value is None:
        # Go 零值时间在 Python 公共包中用 None 表达，JSON 中保留 null。
        return None
    if value.tzinfo is None:
        # naive datetime 按 UTC 解释，避免本地时区影响跨语言时间戳含义。
        value = value.replace(tzinfo=UTC)
    # 统一输出 UTC ISO 字符串，便于不同语言配置客户端比较和展示。
    return value.astimezone(UTC).isoformat()


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        # 空字符串或 null 都表示没有时间值，和 RawConfig 可选字段语义一致。
        return None
    # 兼容常见 Z 后缀，同时保留 fromisoformat 对偏移量的解析能力。
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
