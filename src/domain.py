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


@dataclass(slots=True, frozen=True)
class SignedPackage:
    payload: bytes
    digest_algorithm: str
    signature: str
    salt_length: int
    public_key_fingerprint: str
