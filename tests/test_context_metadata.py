from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from firefly.micro import constants
from firefly.micro.authz import AuthzSignVerificationOptions
from firefly.micro.metadata import prepare_outgoing_authority_metadata
from firefly.micro.service_context import BuildContextOptions, build_context


class Provider:
    async def service_authority(self) -> str:
        return "service-token"


@pytest.mark.asyncio
async def test_prepare_outgoing_authority_metadata_filters_and_injects_service_authority() -> None:
    metadata = {
        constants.USER_AUTHORITY: "user-token",
        constants.SERVICE_AUTHORITY: "old-service-token",
        constants.USER_ID: "spoofed-user",
        constants.TRACE_PARENT: "00-trace",
        "x-unknown": "drop",
    }

    prepared = await prepare_outgoing_authority_metadata(metadata, Provider())

    assert prepared[constants.USER_AUTHORITY] == ["user-token"]
    assert prepared[constants.TRACE_PARENT] == ["00-trace"]
    assert prepared[constants.SERVICE_AUTHORITY] == ["service-token"]
    assert constants.USER_ID not in prepared
    assert "x-unknown" not in prepared


def test_build_context_uses_verified_claims_over_metadata() -> None:
    private_key = Ed25519PrivateKey.generate()
    now = datetime(2026, 6, 10, tzinfo=UTC)
    token = _sign(
        private_key,
        {
            "iss": "firefly-authz",
            "sub": "app-user",
            "subject_type": constants.SUBJECT_TYPE_USER,
            "invoke_app_id": "app-user",
            "target_app_id": "app-order",
            "target_service_app_id": "app-order",
            "api_method": "GRPC",
            "api_path": "/order.v1.OrderService/List",
            "decision": "allow",
            "decision_id": "trusted-decision",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "user_context": {"user_id": "trusted-user", "app_id": "app-user"},
        },
    )
    metadata = {
        constants.AUTHZ_SIGN: token,
        constants.USER_ID: "spoofed-user",
        constants.TARGET_APP_ID: "app-order",
    }

    ctx = build_context(
        metadata,
        BuildContextOptions(
            service_app_id="app-order",
            authz_verification=AuthzSignVerificationOptions(public_key=private_key.public_key(), now=lambda: now),
        ),
    )

    assert ctx.user_id == "trusted-user"
    assert ctx.decision_id == "trusted-decision"
    assert ctx.verified_authz_sign is not None


def _sign(private_key: Ed25519PrivateKey, claims: dict[str, object]) -> str:
    header = {"alg": "EdDSA", "kid": "default", "typ": "JWT"}
    head = _b64(json.dumps(header, separators=(",", ":")).encode())
    body = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signature = private_key.sign(f"{head}.{body}".encode())
    return f"{head}.{body}.{_b64(signature)}"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
