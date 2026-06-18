# EdDSA (Threshold)

> [!CAUTION]
> This project is a strictly educational implementation of the EdDSA standard and FROST algorithm. This means it is NOT PRODUCTION READY at the moment. 
> And will likely never be.

This repository contains two different but linked implementations. The first is a "normal" single- party DSA, in this case EdDSA. The second is a multi-party threshold signature scheme, namely FROST.

## EdDSA

Although this implementation is strictly educational, it follows the standard for EdDSA as specified in [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032).

## FROST

FROST is a bit different, there is no standard (yet) and the [RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591) is strictly informational. 
Also, the RFC defines multiple instantiations for FROST, however this package only implements the version compatible with [Ed25519](https://datatracker.ietf.org/doc/html/rfc9591#name-frosted25519-sha-512) and [Ed448](https://datatracker.ietf.org/doc/html/rfc9591#name-frosted448-shake256) since the focus of the corresponding Master Thesis is on backwards compatibility in regards to the verification.
