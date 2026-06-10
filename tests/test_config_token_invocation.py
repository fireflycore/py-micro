from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from firefly_micro.authz import CachedServiceAuthorityProvider, ServiceAuthorityToken
from firefly_micro.config import RawConfig, decode_payload, encode_payload, marshal_payload, unmarshal_payload
from firefly_micro.invocation import DNS, RemoteServiceRegistry


def test_payload_round_trip() -> None:
    encoded = encode_payload(b'{"hello":"world"}')

    assert decode_payload(encoded) == b'{"hello":"world"}'
    assert unmarshal_payload(marshal_payload({"hello": "world"})) == {"hello": "world"}


def test_raw_config_json_uses_base64_content() -> None:
    raw = RawConfig(content=b"demo", meta={"format": "json"}, updated_by="tester")

    restored = RawConfig.from_json_bytes(raw.to_json_bytes())

    assert restored.content == b"demo"
    assert restored.meta == {"format": "json"}
    assert restored.updated_by == "tester"


@pytest.mark.asyncio
async def test_cached_service_authority_provider_refresh_once() -> None:
    async def fetch() -> ServiceAuthorityToken:
        return ServiceAuthorityToken("service-token", datetime.now(UTC) + timedelta(minutes=5))

    provider = CachedServiceAuthorityProvider(fetch, retry_base_interval=timedelta(milliseconds=1))
    await provider.refresh_once()

    assert await provider.service_authority() == "service-token"


def test_dns_registry_returns_copy() -> None:
    registry = RemoteServiceRegistry([DNS("order", "default", "svc", "cluster.local", 50051)])

    dns = registry.dns("order")

    assert dns.target().grpc_target == "dns:///order.default.svc.cluster.local:50051"
