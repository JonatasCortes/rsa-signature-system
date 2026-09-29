import base64
import json
import pytest

from src.domain import RSAPrivateKey, RSAPublicKey
from src.exceptions import (
    KeySerializationError,
    PackageParsingError,
    PSSVerificationError,
)
from src.packaging import (
    _compute_fingerprint,
    create_signed_package,
    export_key_to_pem,
    import_key_from_pem,
    verify_signed_package,
)


# ==========================================
# Fixtures
# ==========================================
@pytest.fixture
def keys():
    p = 9518937716437086579525574626553539436527811976271436757628327284357895625164767602128960432609602000999443908630907494022120458687218329356867614189925017
    q = 10750733966809282649287804883137164312186120721122245017144234864622035252245144825791533673176304447880663638728459192661534777927974936086659689997610703
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    public_a = RSAPublicKey(modulus=n, public_exponent=e)
    private_a = RSAPrivateKey(
        modulus=n,
        public_exponent=e,
        private_exponent=d,
        first_prime=p,
        second_prime=q,
    )

    public_b = RSAPublicKey(modulus=n + 2, public_exponent=e)

    return {"pub_a": public_a, "priv_a": private_a, "pub_b": public_b}
# ==========================================
# 1. PEM Export Tests
# ==========================================
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
# ==========================================
# 2. Fingerprint Tests
# ==========================================
def test_compute_fingerprint_deterministic(keys):
    """Ensure identical public keys yield identical 64-character hexadecimal digests."""
    fp1 = _compute_fingerprint(keys["pub_a"])
    fp2 = _compute_fingerprint(keys["pub_a"])

    assert fp1 == fp2
    assert len(fp1) == 64
    assert isinstance(fp1, str)


def test_compute_fingerprint_distinct_keys(keys):
    """Ensure distinct public keys generate different fingerprints."""
    fp_a = _compute_fingerprint(keys["pub_a"])
    fp_b = _compute_fingerprint(keys["pub_b"])

    assert fp_a != fp_b


# ==========================================
# 3. Happy Path (Create and Verify)
# ==========================================
def test_create_and_verify_valid_package(keys):
    """Verify that an untampered signed package validates successfully."""
    payload = b"Confidential course project payload"

    package_json = create_signed_package(
        payload=payload,
        private_key=keys["priv_a"],
        public_key=keys["pub_a"],
        salt_length=32,
    )

    assert verify_signed_package(package_json, keys["pub_a"]) is True


def test_create_signed_package_structure(keys):
    """Validate that the generated JSON contains all required fields and correct values."""
    payload = b"Hello, World!"
    package_json = create_signed_package(
        payload=payload,
        private_key=keys["priv_a"],
        public_key=keys["pub_a"],
    )

    data = json.loads(package_json)
    expected_fields = {
        "payload",
        "digest_algorithm",
        "signature",
        "salt_length",
        "public_key_fingerprint",
    }
    assert expected_fields.issubset(data.keys())
    assert data["digest_algorithm"] == "SHA3-256"
    assert data["salt_length"] == 32
    assert data["payload"] == base64.b64encode(payload).decode("utf-8")


# ==========================================
# 4. Error and Tampering Tests
# ==========================================
def test_verify_fails_with_wrong_public_key(keys):
    """Raise PSSVerificationError when public key fingerprint does not match package."""
    payload = b"Confidential payload"
    package_json = create_signed_package(
        payload=payload,
        private_key=keys["priv_a"],
        public_key=keys["pub_a"],
    )

    with pytest.raises(PSSVerificationError):
        verify_signed_package(package_json, keys["pub_b"])


def test_verify_fails_on_tampered_payload(keys):
    """Raise PSSVerificationError if the payload content is tampered with inside the JSON."""
    payload = b"Transfer $10.00"
    package_json = create_signed_package(
        payload=payload,
        private_key=keys["priv_a"],
        public_key=keys["pub_a"],
    )

    data = json.loads(package_json)
    data["payload"] = base64.b64encode(b"Transfer $1,000,000.00").decode("utf-8")
    tampered_json = json.dumps(data)

    with pytest.raises(PSSVerificationError):
        verify_signed_package(tampered_json, keys["pub_a"])


def test_verify_fails_on_tampered_signature(keys):
    """Raise PSSVerificationError if the signature data has been altered."""
    payload = b"Authentic document"
    package_json = create_signed_package(
        payload=payload,
        private_key=keys["priv_a"],
        public_key=keys["pub_a"],
    )

    data = json.loads(package_json)
    data["signature"] = base64.b64encode(b"invalid_signature_bytes").decode("utf-8")
    tampered_json = json.dumps(data)

    with pytest.raises(PSSVerificationError):
        verify_signed_package(tampered_json, keys["pub_a"])


def test_verify_fails_on_invalid_json(keys):
    """Raise PackageParsingError when input is not valid JSON."""
    corrupted_json = '{"payload": "abc", "digest_algorithm": "SHA3-256"'

    with pytest.raises(PackageParsingError):
        verify_signed_package(corrupted_json, keys["pub_a"])


def test_verify_fails_on_missing_required_field(keys):
    """Raise PackageParsingError if any mandatory field is missing from JSON structure."""
    payload = b"Incomplete structure test"
    package_json = create_signed_package(
        payload=payload,
        private_key=keys["priv_a"],
        public_key=keys["pub_a"],
    )

    data = json.loads(package_json)
    del data["public_key_fingerprint"]
    incomplete_json = json.dumps(data)

    with pytest.raises(PackageParsingError):
        verify_signed_package(incomplete_json, keys["pub_a"])


def test_verify_fails_on_corrupted_base64_payload(keys):
    """Raise PackageParsingError when the Base64 payload cannot be decoded."""
    payload = b"Base64 corruption test"
    package_json = create_signed_package(
        payload=payload,
        private_key=keys["priv_a"],
        public_key=keys["pub_a"],
    )

    data = json.loads(package_json)
    data["payload"] = "!!!InvalidBase64Characters!!!"
    invalid_b64_json = json.dumps(data)

    with pytest.raises(PackageParsingError):
        verify_signed_package(invalid_b64_json, keys["pub_a"])


@pytest.mark.parametrize("bad_salt_length", ["32", 32.5, True, None])
def test_verify_fails_on_invalid_salt_length_type(keys, bad_salt_length):
    """Raise PackageParsingError if salt_length is not strictly an integer."""
    fake_package = {
        "payload": "dGVzdGU=",
        "digest_algorithm": "SHA3-256",
        "signature": "c2lnbmF0dXJl",
        "salt_length": bad_salt_length,
        "public_key_fingerprint": _compute_fingerprint(keys["pub_a"]),
    }
    bad_type_json = json.dumps(fake_package)

    with pytest.raises(PackageParsingError):
        verify_signed_package(bad_type_json, keys["pub_a"])
