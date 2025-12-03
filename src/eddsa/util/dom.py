from typing import Optional


def dom2(phflag: int, context: Optional[bytes]) -> bytes:
    """Create the DOM2 prefix for EdDSA signatures."""
    if context is None:
        return b""
    if len(context) > 255:
        raise ValueError("Context length must be at most 255 bytes.")
    return (b"SigEd25519 no Ed25519 collisions" + bytes([phflag]) + bytes([len(context)]) + context)


def dom4(phflag: int, context: bytes) -> bytes:
    """Create the DOM4 prefix for EdDSA signatures."""
    if len(context) > 255:
        raise ValueError("Context length must be at most 255 bytes.")
    return (b"SigEd448" + bytes([phflag]) + bytes([len(context)]) + context)
