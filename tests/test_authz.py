from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from firefly.micro import constants
from firefly.micro.authz import AuthzSignVerificationOptions, verify_authz_sign
from firefly.micro.errors import AuthzSignExpiredError, AuthzSignInvalidClaimsError


def test_verify_authz_sign_user_claims() -> None:
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
            "api_method": "GRPC",
            "api_path": "/order.v1.OrderService/List",
            "decision": "allow",
            "decision_id": "decision-1",
            "target_service_app_id": "app-order",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "user_context": {
                "user_id": "u1",
                "app_id": "app-user",
                "tenant_id": "t1",
                "session": "s1",
                "org_ids": ["o1"],
            },
        },
    )

    value = verify_authz_sign(
        token,
        AuthzSignVerificationOptions(
            public_key=private_key.public_key(),
            issuer="firefly-authz",
            expected_api_method="grpc",
            expected_api_path="/order.v1.OrderService/List",
            now=lambda: now,
        ),
    )

    assert value.user_id == "u1"
    assert value.app_id == "app-user"
    assert value.target_app_id == "app-order"
    assert value.org_ids == ["o1"]


def test_verify_authz_sign_rejects_expired_token() -> None:
    private_key = Ed25519PrivateKey.generate()
    now = datetime(2026, 6, 10, tzinfo=UTC)
    token = _sign(
        private_key,
        {
            "iss": "firefly-authz",
            "sub": "anonymous",
            "subject_type": constants.SUBJECT_TYPE_ANONYMOUS,
            "target_app_id": "app-order",
            "target_service_app_id": "app-order",
            "api_method": "GET",
            "api_path": "/healthz",
            "decision": "allow",
            "decision_id": "decision-1",
            "iat": int((now - timedelta(minutes=10)).timestamp()),
            "exp": int((now - timedelta(minutes=1)).timestamp()),
        },
    )

    with pytest.raises(AuthzSignExpiredError):
        verify_authz_sign(token, AuthzSignVerificationOptions(public_key=private_key.public_key(), now=lambda: now))


def test_verify_authz_sign_rejects_mismatched_service_claims() -> None:
    private_key = Ed25519PrivateKey.generate()
    now = datetime(2026, 6, 10, tzinfo=UTC)
    token = _sign(
        private_key,
        {
            "iss": "firefly-authz",
            "sub": "svc-a",
            "subject_type": constants.SUBJECT_TYPE_SERVICE,
            "invoke_app_id": "svc-a",
            "invoke_service_app_id": "svc-b",
            "target_app_id": "svc-c",
            "target_service_app_id": "svc-c",
            "api_method": "GRPC",
            "api_path": "/demo.v1.Demo/Ping",
            "decision": "allow",
            "decision_id": "decision-1",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
    )

    with pytest.raises(AuthzSignInvalidClaimsError):
        verify_authz_sign(token, AuthzSignVerificationOptions(public_key=private_key.public_key(), now=lambda: now))


def _sign(private_key: Ed25519PrivateKey, claims: dict[str, object]) -> str:
    header = {"alg": "EdDSA", "kid": "default", "typ": "JWT"}
    head = _b64(json.dumps(header, separators=(",", ":")).encode())
    body = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signature = private_key.sign(f"{head}.{body}".encode())
    return f"{head}.{body}.{_b64(signature)}"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
