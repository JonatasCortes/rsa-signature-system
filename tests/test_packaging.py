import pytest

from src.domain import RSAPublicKey, RSAPrivateKey
from src.exceptions import KeySerializationError
from src.packaging import export_key_to_pem, import_key_from_pem


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
        export_key_to_pem("this is not a key")  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_modulus", [-5, 0])
def test_export_rejects_invalid_value(bad_modulus):
    key = RSAPublicKey(modulus=bad_modulus, public_exponent=65537)
    with pytest.raises(KeySerializationError):
        export_key_to_pem(key)


PUBLIC_PEM = (
    "-----BEGIN RSA PUBLIC KEY-----\n"
    "modulus: DKE=\n"
    "public_exponent: AQAB\n"
    "-----END RSA PUBLIC KEY-----\n"
)


def _private_key():
    return RSAPrivateKey(
        modulus=3233,
        public_exponent=17,
        private_exponent=2753,
        first_prime=61,
        second_prime=53,
    )


def test_roundtrip_public_key():
    key = RSAPublicKey(modulus=3233, public_exponent=65537)
    assert import_key_from_pem(export_key_to_pem(key)) == key


def test_roundtrip_private_key():
    key = _private_key()
    assert import_key_from_pem(export_key_to_pem(key)) == key


def test_roundtrip_large_numbers():
    key = RSAPublicKey(modulus=(1 << 2047) + 12345, public_exponent=65537)
    assert import_key_from_pem(export_key_to_pem(key)) == key


def test_import_returns_correct_type():
    assert isinstance(import_key_from_pem(PUBLIC_PEM), RSAPublicKey)
    assert isinstance(import_key_from_pem(
        export_key_to_pem(_private_key())), RSAPrivateKey)


def test_import_tolerates_blank_lines_and_crlf():
    messy = "\n  " + PUBLIC_PEM.replace("\n", "  \r\n\r\n")
    assert import_key_from_pem(messy) == RSAPublicKey(
        modulus=3233, public_exponent=65537)


@pytest.mark.parametrize(
    "bad_pem",
    [
        "",
        "random garbage with no format",
        "modulus: DKE=\npublic_exponent: AQAB\n",
        PUBLIC_PEM.replace("-----END RSA PUBLIC KEY-----\n", ""),
        PUBLIC_PEM.replace("END RSA PUBLIC KEY", "END RSA PRIVATE KEY"),
        PUBLIC_PEM.replace("RSA PUBLIC KEY", "EC PUBLIC KEY"),
        PUBLIC_PEM.replace("modulus: DKE=", "modulus: !!!!"),
        PUBLIC_PEM.replace("modulus: DKE=", "modulus:"),
        PUBLIC_PEM.replace("modulus: DKE=", "modulus DKE="),
        PUBLIC_PEM.replace("public_exponent: AQAB", "public_exponent: AA=="),
        PUBLIC_PEM.replace("public_exponent: AQAB\n", ""),
        PUBLIC_PEM.replace("public_exponent: AQAB\n",
                           "public_exponent: AQAB\nfoo: AQAB\n"),
        PUBLIC_PEM.replace("public_exponent: AQAB\n",
                           "public_exponent: AQAB\nmodulus: DKE=\n"),
        PUBLIC_PEM.replace("PUBLIC", "PRIVATE"),
    ],
    ids=[
        "empty", "garbage", "no_headers", "no_footer", "mismatched_footer",
        "unknown_label", "invalid_base64", "empty_value", "missing_colon",
        "zero_value", "missing_field", "extra_field", "duplicate_field",
        "private_header_public_fields",
    ],
)
def test_import_rejects_corrupted_pem(bad_pem):
    with pytest.raises(KeySerializationError):
        import_key_from_pem(bad_pem)


@pytest.mark.parametrize("not_a_string", [None, 123, b"bytes"])
def test_import_rejects_non_string(not_a_string):
    with pytest.raises(KeySerializationError):
        import_key_from_pem(not_a_string)  # type: ignore[arg-type]
