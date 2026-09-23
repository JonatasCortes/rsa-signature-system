from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class RSAPublicKey:
    modulus: int
    public_exponent: int


@dataclass(slots=True, frozen=True)
class RSAPrivateKey:
    modulus: int
    public_exponent: int
    private_exponent: int
    first_prime: int
    second_prime: int
