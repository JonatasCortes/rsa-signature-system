from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class RSAPublicKey:
    modulus: int
    public_exponent: int
