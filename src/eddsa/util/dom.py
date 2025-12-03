from typing import Optional


def dom2(phflag: int, context: Optional[bytes]) -> bytes:
    """Create the DOM2 prefix for EdDSA signatures."""
    if context is None:
        context = b""
    if len(context) > 255:
        raise ValueError("Context length must be at most 255 bytes.")
    return (b"SigEd25519 no Ed25519 collisions" + bytes([phflag]) + bytes([len(context)]) + context)