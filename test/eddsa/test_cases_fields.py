from eddsa_threshold.eddsa.curves.base.field_ops import FieldOps


def case_ed25519() -> FieldOps:
    """Inputs for ed25519 field_ops tests"""
    import eddsa_threshold.eddsa.curves.ed25519.field_ops as ed25519

    return ed25519.Ed25519FieldOps()


def case_ed448() -> FieldOps:
    """Inputs for ed448 field_ops tests"""
    import eddsa_threshold.eddsa.curves.ed448.field_ops as ed448

    return ed448.Ed448FieldOps()
