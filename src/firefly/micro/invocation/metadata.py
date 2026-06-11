"""出站调用 metadata 准备。"""

from __future__ import annotations

from ..metadata import MetadataMapping, NormalizedMetadata, ServiceAuthorityProvider, prepare_outgoing_authority_metadata

DEFAULT_INVOKE_TIMEOUT_SECONDS = 5.0


async def prepare_metadata_for_invocation(
    metadata: MetadataMapping | None,
    provider: ServiceAuthorityProvider | None = None,
) -> NormalizedMetadata:
    """为远程调用准备 Firefly 出站 metadata。"""

    # invocation 层只复用 authz metadata 清理/注入主线，避免两套出站身份规则分叉。
    return await prepare_outgoing_authority_metadata(metadata, provider)
