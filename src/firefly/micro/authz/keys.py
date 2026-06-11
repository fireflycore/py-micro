"""authz Ed25519 公钥加载与选择。"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..errors import AuthzSignPublicKeyMissingError


def load_ed25519_public_key(path: str | Path) -> Ed25519PublicKey:
    """从 PEM 文件加载 Ed25519 公钥。"""

    # 与 Go LoadEd25519PublicKey 一样，只接受 PEM 公钥文件作为启动期配置输入。
    data = Path(path).read_bytes()
    public_key = serialization.load_pem_public_key(data)
    if not isinstance(public_key, Ed25519PublicKey):
        # authz JWS 固定使用 Ed25519，其他算法即使能解析也不能参与验签。
        raise ValueError(f"expected Ed25519 public key: {path}")
    return public_key


def resolve_public_key(
    kid: str,
    public_key: Ed25519PublicKey | bytes | None,
    public_keys: Mapping[str, Ed25519PublicKey | bytes],
) -> Ed25519PublicKey:
    """按 kid 或单公钥配置选择用于验签的 Ed25519 公钥。"""

    if public_keys:
        # 多公钥模式优先，用于密钥轮换期间同时接受新旧 kid。
        value = public_keys.get(kid)
        if value is None:
            raise AuthzSignPublicKeyMissingError("authz sign public key is missing")
        return _coerce_public_key(value)
    if public_key is not None:
        # 单公钥模式不依赖 kid，适合简单部署或测试。
        return _coerce_public_key(public_key)
    raise AuthzSignPublicKeyMissingError("authz sign public key is missing")


def _coerce_public_key(value: Ed25519PublicKey | bytes) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        # cryptography 公钥对象可直接用于 verify。
        return value
    if isinstance(value, bytes) and len(value) == 32:
        # Ed25519 原始公钥固定 32 字节，和 Go ed25519.PublicKeySize 保持一致。
        return Ed25519PublicKey.from_public_bytes(value)
    raise AuthzSignPublicKeyMissingError("authz sign public key is missing")
