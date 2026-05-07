"""
Constants for Ed25519

These values are taken from RFC 8032.
RFC: https://datatracker.ietf.org/doc/html/rfc8032
"""

# Finite field modulus p
p = 2**255 - 19

# Bit size of the field
b = 256

# base 2 logarithm of cofactor
c = 3

n = 254

# Curve Parameters d/a
# d = -121665 * pow(121666, -1, p) % p
d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
a = -1

# Base point of the curve
BASE_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BASE_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
BASE = (BASE_X, BASE_Y)
IDENTITY = (0, 1)

# Order of ed25519
L = 2**252+27742317777372353535851937790883648493

# Encoding sizes (in bytes)
SCALAR_SIZE = 32      # size of private scalar
PUBLIC_KEY_SIZE = 32  # size of encoded public key
SIGNATURE_SIZE = 64   # R || S
SEED_SIZE = 32        # seed length specified by RFC 8032
