import hashlib


def sha512(data: bytes) -> bytes:
    """Compute SHA-512 hash of the input using hashlib."""
    return hashlib.sha512(data).digest()

def shake256(data: bytes, outlen: int) -> bytes:
    """Compute SHAKE-256 hash of the input using hashlib."""
    shake = hashlib.shake_256()
    shake.update(data)
    return shake.digest(outlen)
