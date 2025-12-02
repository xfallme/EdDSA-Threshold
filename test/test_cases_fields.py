def case_ed25519():
    """Inputs for ed25519 fields ops tests"""
    import eddsa.curves.ed25519.field_ops as ed25519

    return ed25519.Ed25519FieldOps()


def case_ed448():
    """Inputs for ed448 fields ops tests"""
    import eddsa.curves.ed448.field_ops as ed448

    return ed448.Ed448FieldOps()
