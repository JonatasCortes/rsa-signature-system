import pytest

from src.domain import RSAPublicKey, RSAPrivateKey
from src.exceptions import KeySerializationError
from src.packaging import export_key_to_pem


def test_export_public_key():
    key = RSAPublicKey(modulus=3233, public_exponent=65537)
    expected = (
        "-----BEGIN RSA PUBLIC KEY-----\n"
        "modulus: DKE=\n"
        "public_exponent: AQAB\n"
        "-----END RSA PUBLIC KEY-----\n"
    )
    assert export_key_to_pem(key) == expected


def test_export_private_key():
    key = RSAPrivateKey(
        modulus=3233,
        public_exponent=17,
        private_exponent=2753,
        first_prime=61,
        second_prime=53,
    )
    expected = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "modulus: DKE=\n"
        "public_exponent: EQ==\n"
        "private_exponent: CsE=\n"
        "first_prime: PQ==\n"
        "second_prime: NQ==\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    assert export_key_to_pem(key) == expected


def test_export_rejects_non_key():
    with pytest.raises(KeySerializationError):
        export_key_to_pem("isso não é uma chave")  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_modulus", [-5, 0])
def test_export_rejects_invalid_value(bad_modulus):
    key = RSAPublicKey(modulus=bad_modulus, public_exponent=65537)
    with pytest.raises(KeySerializationError):
        export_key_to_pem(key)
