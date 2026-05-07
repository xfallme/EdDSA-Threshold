from eddsa_threshold.eddsa.curves.base.scalar_ops import ScalarOps


def case_ed25519() -> ScalarOps:
    """Inputs for standalone secret sharing tests with ed25519"""
    import eddsa_threshold.eddsa.curves.ed25519.scalar_ops as ed25519

    return ed25519.Ed25519ScalarOps()


def case_ed448() -> ScalarOps:
    """Inputs for standalone secret sharing tests with ed448"""
    import eddsa_threshold.eddsa.curves.ed448.scalar_ops as ed448

    return ed448.Ed448ScalarOps()
