"""Firefly authority metadata 的清洗、复制和注入。"""

from __future__ import annotations

import inspect
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from . import constants
from .errors import ServiceAuthorityTokenMissingError

MetadataValue = str | Sequence[str]
MetadataMapping = Mapping[str, MetadataValue]
NormalizedMetadata = dict[str, list[str]]


class ServiceAuthorityProvider(Protocol):
    """出站调用热路径获取当前服务 authority 的最小协议。"""

    async def service_authority(self) -> str:
        """返回当前服务身份 token。"""


def normalize_metadata(metadata: MetadataMapping | None) -> NormalizedMetadata:
    """把 HTTP header / gRPC metadata 规范化为小写 key 和独立 value 列表。"""

    if not metadata:
        # 空输入返回新字典，调用方可直接继续写入出站 metadata。
        return {}

    normalized: NormalizedMetadata = {}
    for key, value in metadata.items():
        # Firefly metadata 与 gRPC header 都按大小写不敏感处理，统一小写后匹配常量。
        clean_key = str(key).strip().lower()
        if not clean_key:
            # 空 key 无法跨协议传播，直接丢弃避免污染下游上下文。
            continue
        # 每个 key 的 value 都复制成新列表，避免调用方继续修改原始 metadata 影响上下文。
        normalized[clean_key] = _coerce_values(value)
    return normalized


def first_metadata_value(metadata: MetadataMapping | None, key: str) -> str:
    """读取约定的第一个 metadata value，不存在时返回空字符串。"""

    # Go 版 metadata.Get 常用于读取首值；Python 版保持相同的“缺失为空串”语义。
    values = normalize_metadata(metadata).get(key.lower(), [])
    return values[0] if values else ""


def metadata_values(metadata: MetadataMapping | None, key: str) -> list[str]:
    """读取一个 metadata key 的全部 value，并返回独立列表。"""

    # 多值 metadata 用于 org_ids/post_ids/role_ids 等身份列表，返回副本避免外部共享。
    return list(normalize_metadata(metadata).get(key.lower(), []))


def filter_outgoing_authority_metadata(metadata: MetadataMapping | None) -> NormalizedMetadata:
    """按 Firefly 出站白名单重建 metadata，清理普通身份字段和未知 header。"""

    # 只用新 dict 承载出站字段，避免在调用方传入的 metadata 上产生副作用。
    filtered: NormalizedMetadata = {}
    for key, values in normalize_metadata(metadata).items():
        # Go 版按小写 key 匹配白名单；Python 版沿用相同跨协议语义。
        if key not in constants.OUTGOING_AUTHORITY_METADATA_ALLOWLIST:
            continue
        # value 列表继续复制，保证出站清理结果可以独立修改。
        filtered[key] = list(values)
    return filtered


async def prepare_outgoing_authority_metadata(
    metadata: MetadataMapping | None,
    provider: ServiceAuthorityProvider | None = None,
) -> NormalizedMetadata:
    """清理出站 metadata，并按当前这一跳覆盖 service authority。"""

    # 先清理上一跳普通身份字段和未知 header，再考虑注入当前服务身份。
    prepared = filter_outgoing_authority_metadata(metadata)
    if provider is None:
        # 无 provider 时只做白名单清理，适合 authz 自身或启动期取 token 链路。
        return prepared

    # provider 可返回协程或字符串，兼容异步 token 管理器和测试桩。
    token = provider.service_authority()
    if inspect.isawaitable(token):
        token = await token
    if not token:
        # 空 service authority 等同于身份不可用，不能写入下一跳请求。
        raise ServiceAuthorityTokenMissingError("authz service authority token is missing")

    # service authority 每一跳都必须由当前服务覆盖，不能继承上游服务身份。
    prepared[constants.SERVICE_AUTHORITY] = [str(token)]
    return prepared


def _coerce_values(value: Any) -> list[str]:
    if value is None:
        # None 表示缺失值，保持为空列表而不是字符串 "None"。
        return []
    if isinstance(value, str):
        # 字符串是最常见 header 值，不能被 Sequence 分支拆成字符列表。
        return [value]
    if isinstance(value, Sequence):
        # gRPC metadata 天然支持多值；过滤 None 后统一转字符串。
        return [str(item) for item in value if item is not None]
    # 非序列值兜底成单值字符串，兼容测试或框架适配层传入的标量。
    return [str(value)]
