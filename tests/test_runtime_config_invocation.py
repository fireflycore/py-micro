from __future__ import annotations

from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from firefly.micro.app import AppConfig
from firefly.micro.authz import VerificationConfig, new_verification_options
from firefly.micro.config import ConfigKey, MemoryStore, RawConfig, StoreClient, StoreParams, encode_payload, load_store_config
from firefly.micro.invocation import (
    ConnectionManager,
    ConnectionManagerOptions,
    DNS,
    RemoteServiceManaged,
    UnaryInvoker,
)
from firefly.micro.kernel import KernelConfig
from firefly.micro.service import ServiceConfig


def test_runtime_configs_bootstrap_defaults() -> None:
    app = AppConfig("app-order", "dev", "order", "secret", "0.0.1").bootstrap()
    kernel = KernelConfig().bootstrap()
    service = ServiceConfig("order").bootstrap()

    assert app.instance_id
    assert kernel.language == "Python"
    assert kernel.version == "v0.0.1"
    assert service.namespace == "default"
    assert service.port == 9090


@pytest.mark.asyncio
async def test_store_client_loads_json_payload_from_memory_store() -> None:
    key = ConfigKey(env="dev", app_id="app-order", group="bootstrap", key="db")
    store = MemoryStore()
    await store.put(key, RawConfig(content=encode_payload(b'{"driver":"mysql"}').encode("utf-8")))

    client = StoreClient(store)
    loaded = await load_store_config(StoreParams(key=key, client=client))

    assert loaded == {"driver": "mysql"}


@pytest.mark.asyncio
async def test_remote_service_managed_reuses_connection() -> None:
    created: list[str] = []
    calls: list[tuple[str, dict[str, list[str]]]] = []

    async def dial(target):
        created.append(target.grpc_target)
        return {"target": target.grpc_target}

    async def invoke(conn, method, request, metadata, timeout):
        calls.append((method, metadata))
        return {"conn": conn["target"], "request": request, "timeout": timeout}

    manager = ConnectionManager(ConnectionManagerOptions(dial=dial))
    invoker = UnaryInvoker(manager, invoke)
    services = RemoteServiceManaged(invoker, [DNS("auth", "default", "svc", "cluster.local", 50051)])

    first = await services.invoke("auth", "/auth.Auth/Ping", {"ok": True}, metadata={"traceparent": "00-demo"})
    second = await services.caller("auth").invoke("/auth.Auth/Ping", {"ok": True})

    assert first["conn"] == "dns:///auth.default.svc.cluster.local:50051"
    assert second["conn"] == "dns:///auth.default.svc.cluster.local:50051"
    assert created == ["dns:///auth.default.svc.cluster.local:50051"]
    assert calls[0][1] == {"traceparent": ["00-demo"]}


def test_verification_config_loads_public_key_and_skip_methods(tmp_path) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_path = tmp_path / "authz.pem"
    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    options = new_verification_options(
        VerificationConfig(
            public_key_path=str(public_key_path),
            clock_skew="10s",
            skip_methods=[" ", "/grpc.health.v1.Health/Check"],
        )
    )

    assert options.authz_verification is not None
    assert options.authz_verification.clock_skew == timedelta(seconds=10)
    assert options.authz_skip_methods == ["/grpc.health.v1.Health/Check"]
