"""
crypto/symmetric.py
====================
AES-256-GCM authenticated encryption.

Public API
----------
encrypt(key, plaintext, aad=b"")
    -> (nonce_bytes, ciphertext_bytes, tag_bytes)

decrypt(key, nonce, ciphertext, tag, aad=b"")
    -> plaintext_bytes  (raises DecryptionError on tag mismatch)

Exceptions
----------
DecryptionError
    Raised when the GCM authentication tag does not match — i.e., the
    ciphertext has been tampered with (or the key/nonce is wrong).
    The message is the structured reason string: "GCM auth tag mismatch".

Notes
-----
- Nonce: 96-bit (12-byte) random, freshly generated per encryption.
- Tag: 128-bit (16-byte) GCM authentication tag.
- Key: must be exactly 32 bytes (AES-256).
- AAD: additional authenticated data, authenticated but not encrypted.
  Used in Step 3+ to bind the sequence number to the ciphertext.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Custom exceptions ────────────────────────────────────────────────────────

class DecryptionError(Exception):
    """Raised when AES-256-GCM authentication fails (tag mismatch).

    The message attribute contains the structured reason string shown in the
    Eve attack-result console: "GCM auth tag mismatch".
    """


# ── Constants ────────────────────────────────────────────────────────────────

_NONCE_SIZE = 12   # 96-bit nonce, standard for GCM
_TAG_SIZE   = 16   # 128-bit authentication tag


# ── Encrypt ──────────────────────────────────────────────────────────────────

def encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Parameters
    ----------
    key : bytes
        32-byte AES-256 session key derived by HKDF.
    plaintext : bytes
        Arbitrary-length plaintext to encrypt.
    aad : bytes
        Additional authenticated data (authenticated but not encrypted).
        Defaults to empty. In the full protocol, pass the sequence number here.

    Returns
    -------
    nonce : bytes
        12-byte random nonce. Send along with ciphertext.
    ciphertext : bytes
        Encrypted payload (same length as plaintext, without the tag).
    tag : bytes
        16-byte GCM authentication tag. Send along with ciphertext.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)} bytes")

    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)

    # cryptography's AESGCM.encrypt returns ciphertext || tag concatenated
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad if aad else None)

    # Split: last 16 bytes are the tag
    ciphertext = ct_with_tag[:-_TAG_SIZE]
    tag = ct_with_tag[-_TAG_SIZE:]

    return nonce, ciphertext, tag


# ── Decrypt ──────────────────────────────────────────────────────────────────

def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """Decrypt and verify an AES-256-GCM ciphertext.

    Parameters
    ----------
    key : bytes
        32-byte AES-256 session key.
    nonce : bytes
        12-byte nonce returned by encrypt().
    ciphertext : bytes
        Encrypted payload returned by encrypt().
    tag : bytes
        16-byte GCM tag returned by encrypt().
    aad : bytes
        Must match the aad used at encryption time.

    Returns
    -------
    bytes
        Decrypted plaintext.

    Raises
    ------
    DecryptionError
        If the GCM tag does not authenticate — meaning the ciphertext, tag,
        nonce, key, or AAD has been tampered with.
        Message: "GCM auth tag mismatch"
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)} bytes")

    aesgcm = AESGCM(key)
    # Reconstruct the concatenated form that cryptography expects
    ct_with_tag = ciphertext + tag

    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, aad if aad else None)
    except Exception:
        # cryptography raises InvalidTag on authentication failure.
        # We normalise it to our structured DecryptionError.
        raise DecryptionError("GCM auth tag mismatch")

    return plaintext
