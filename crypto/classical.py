"""
crypto/classical.py
====================
X25519 key exchange and HKDF key derivation.

Public API
----------
generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]
    Generate a fresh X25519 keypair. Returns the private key object and the
    raw 32-byte public key.

x25519_exchange(private_key, peer_public_bytes) -> bytes
    Perform the X25519 DH exchange. Returns the 32-byte shared secret.

hkdf_derive(secret_classical, secret_pqc, info, length=32) -> bytes
    Combine the two shared secrets (classical + PQC) with HKDF-SHA-256 into a
    single session key. IKM = secret_classical || secret_pqc.
    Neither secret alone is sufficient — security holds even if one scheme is
    later broken.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Generate a fresh X25519 keypair.

    Returns
    -------
    private_key : X25519PrivateKey
        The private key object. Keep secret.
    public_bytes : bytes
        Raw 32-byte little-endian public key to share with the peer.
    """
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def x25519_exchange(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """Compute the X25519 shared secret.

    Parameters
    ----------
    private_key : X25519PrivateKey
        Our X25519 private key.
    peer_public_bytes : bytes
        Peer's raw 32-byte public key.

    Returns
    -------
    bytes
        32-byte shared secret. Both sides must arrive at the same value.
    """
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret


def hkdf_derive(
    secret_classical: bytes,
    secret_pqc: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """Derive a session key by combining both shared secrets with HKDF-SHA-256.

    IKM = secret_classical || secret_pqc
    This is the hybrid construction: security holds even if only one of the two
    underlying schemes (X25519 or ML-KEM) is broken.

    Parameters
    ----------
    secret_classical : bytes
        Output of x25519_exchange().
    secret_pqc : bytes
        Output of kem_decapsulate() / kem_encapsulate().
    info : bytes
        Context string bound to this usage (e.g. b"pqctunnel-session-v1").
    length : int
        Desired output length in bytes. Default 32 (AES-256 key size).

    Returns
    -------
    bytes
        Derived session key of ``length`` bytes.
    """
    ikm = secret_classical + secret_pqc
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(ikm)
