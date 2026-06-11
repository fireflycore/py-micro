"""配置 payload 编解码。"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping

from ..errors import InvalidRawConfigError
from .model import Compressor, Encryptor, IdentityCompressor


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
