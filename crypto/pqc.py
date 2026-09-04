"""
crypto/pqc.py
==============
Post-quantum cryptography via liboqs-python 0.16.0.

Algorithms used
---------------
- ML-KEM-768  (NIST FIPS 203, formerly Kyber-768) for key encapsulation.
- ML-DSA-65   (NIST FIPS 204, formerly Dilithium3) for signing.

Both names are the standardized NIST identifiers used since liboqs 0.11.0.
The old Kyber*/Dilithium* aliases were removed in liboqs 0.11.x.

Public API
----------
KEM
  kem_generate_keypair()      -> (public_key_bytes, secret_key_bytes)
  kem_encapsulate(pk_bytes)   -> (ciphertext_bytes, shared_secret_bytes)
  kem_decapsulate(sk, ct)     -> shared_secret_bytes

Signing
  sign_generate_keypair()         -> (public_key_bytes, secret_key_bytes)
  sign_message(sk, message)       -> signature_bytes
  verify_signature(pk, message, signature) -> None  (raises on failure)

Exceptions
----------
SignatureVerificationError
    Raised by verify_signature() when verification fails.
    The exception message contains the specific reason string.
"""

from __future__ import annotations

import oqs

# ── Algorithm identifiers ────────────────────────────────────────────────────
_KEM_ALG = "ML-KEM-768"
_SIG_ALG = "ML-DSA-65"


# ── Custom exceptions ────────────────────────────────────────────────────────

class SignatureVerificationError(Exception):
    """Raised when ML-DSA signature verification fails.

    The message attribute contains the specific structured reason string
    displayed in Eve's attack-result console.
    """


# ── KEM: ML-KEM-768 ─────────────────────────────────────────────────────────

def kem_generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-KEM-768 keypair.

    Returns
    -------
    public_key_bytes : bytes
        1184-byte public key. Share with the encapsulating party.
    secret_key_bytes : bytes
        2400-byte secret key. Keep private.
    """
    with oqs.KeyEncapsulation(_KEM_ALG) as kem:
        public_key_bytes = kem.generate_keypair()
        secret_key_bytes = kem.export_secret_key()
    return public_key_bytes, secret_key_bytes


def kem_encapsulate(peer_public_key_bytes: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret for the peer's ML-KEM-768 public key.

    Parameters
    ----------
    peer_public_key_bytes : bytes
        The peer's ML-KEM-768 public key.

    Returns
    -------
    ciphertext_bytes : bytes
        1088-byte ciphertext to send to the peer.
    shared_secret_bytes : bytes
        32-byte shared secret. Do not transmit.
    """
    with oqs.KeyEncapsulation(_KEM_ALG) as kem:
        ciphertext_bytes, shared_secret_bytes = kem.encap_secret(
            peer_public_key_bytes
        )
    return ciphertext_bytes, shared_secret_bytes


def kem_decapsulate(secret_key_bytes: bytes, ciphertext_bytes: bytes) -> bytes:
    """Decapsulate to recover the shared secret.

    Parameters
    ----------
    secret_key_bytes : bytes
        Our ML-KEM-768 secret key.
    ciphertext_bytes : bytes
        Ciphertext received from the encapsulating party.

    Returns
    -------
    bytes
        32-byte shared secret. Must equal the encapsulator's shared_secret.
    """
    with oqs.KeyEncapsulation(_KEM_ALG, secret_key=secret_key_bytes) as kem:
        shared_secret_bytes = kem.decap_secret(ciphertext_bytes)
    return shared_secret_bytes


# ── Signatures: ML-DSA-65 ────────────────────────────────────────────────────

def sign_generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-DSA-65 signing keypair.

    Returns
    -------
    public_key_bytes : bytes
        1952-byte public key. Distribute to verifiers.
    secret_key_bytes : bytes
        4032-byte secret key. Keep private.
    """
    with oqs.Signature(_SIG_ALG) as signer:
        public_key_bytes = signer.generate_keypair()
        secret_key_bytes = signer.export_secret_key()
    return public_key_bytes, secret_key_bytes


def sign_message(secret_key_bytes: bytes, message: bytes) -> bytes:
    """Sign an arbitrary message with ML-DSA-65.

    Parameters
    ----------
    secret_key_bytes : bytes
        Our ML-DSA-65 secret key.
    message : bytes
        The message to sign (typically a handshake transcript hash).

    Returns
    -------
    bytes
        ML-DSA-65 signature (variable length, ≤ 3309 bytes for ML-DSA-65).
    """
    with oqs.Signature(_SIG_ALG, secret_key=secret_key_bytes) as signer:
        signature = signer.sign(message)
    return signature


def verify_signature(
    public_key_bytes: bytes,
    message: bytes,
    signature: bytes,
) -> None:
    """Verify an ML-DSA-65 signature.

    Raises
    ------
    SignatureVerificationError
        If verification fails. The exception message is the structured reason
        string shown to Eve in the attack-result console, e.g.:
            "ML-DSA signature verification failed: transcript hash mismatch"

    Returns
    -------
    None
        Returns normally (implicitly None) on success.
    """
    with oqs.Signature(_SIG_ALG) as verifier:
        valid = verifier.verify(message, signature, public_key_bytes)
    if not valid:
        raise SignatureVerificationError(
            "ML-DSA signature verification failed: transcript hash mismatch"
        )
