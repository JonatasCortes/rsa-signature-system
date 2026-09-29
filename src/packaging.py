import hashlib
import json
import base64
from src.pss import rsa_pss_sign, rsa_pss_verify
from src.exceptions import PackageParsingError, PSSVerificationError, KeySerializationError
from src.domain import RSAPublicKey, RSAPrivateKey, SignedPackage


def _int_to_b64(n: int) -> str:
    if not isinstance(n, int) or isinstance(n, bool) or n <= 0:
        raise KeySerializationError("Key parameter must be a positive integer")
    length = (n.bit_length() + 7) // 8
    data = n.to_bytes(length, "big")
    codified = base64.b64encode(data)
    return codified.decode("ascii")


def _b64_to_int(text: str) -> int:
    try:
        data = base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise KeySerializationError("Invalid Base64 in key field") from exc
    converted_int = int.from_bytes(data, "big")
    if converted_int == 0:
        message_error = "Key parameter must be a positive integer"
        raise KeySerializationError(message_error)
    return converted_int


def export_key_to_pem(key: RSAPublicKey | RSAPrivateKey) -> str:
    """
    Export an RSA public or private key to a PEM-formatted string using Base64 encoding.

    Args:
        key (RSAPublicKey | RSAPrivateKey): The key object to export.

    Returns:
        str: The PEM-formatted string representation of the key.

    Raises:
        KeySerializationError: If the key structure is invalid or export fails.
    """
    if isinstance(key, RSAPublicKey):
        label = "RSA PUBLIC KEY"
        fields = ("modulus", "public_exponent")
    elif isinstance(key, RSAPrivateKey):
        label = "RSA PRIVATE KEY"
        fields = ("modulus", "public_exponent", "private_exponent",
                  "first_prime", "second_prime")
    else:
        message_error = "Key structure is invalid"
        raise KeySerializationError(message_error)

    try:
        lines = [f"-----BEGIN {label}-----"]
        for name in fields:
            number = getattr(key, name)
            b64 = _int_to_b64(number)
            lines.append(f"{name}: {b64}")
        lines.append(f"-----END {label}-----")
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise KeySerializationError("Failed to export key") from exc

    return "\n".join(lines) + "\n"


def import_key_from_pem(pem_data: str) -> RSAPublicKey | RSAPrivateKey:
    """
    Import an RSA public or private key from a PEM-formatted string.

    Args:
        pem_data (str): The PEM-formatted string containing key parameters.

    Returns:
        RSAPublicKey | RSAPrivateKey: The reconstructed key domain object.

    Raises:
        KeySerializationError: If the PEM data is malformed or unreadable.
    """
    if not isinstance(pem_data, str):
        message_error = "invalid pem_data type"
        raise KeySerializationError(message_error)

    lines: list[str] = []
    for line in pem_data.splitlines():
        clean = line.strip()
        if clean:
            lines.append(clean)

    if len(lines) < 3:
        raise KeySerializationError("PEM data is too short")

    key_types = (
        ("RSA PUBLIC KEY",
         ("modulus", "public_exponent"),
         RSAPublicKey),
        ("RSA PRIVATE KEY",
         ("modulus", "public_exponent", "private_exponent",
          "first_prime", "second_prime"),
         RSAPrivateKey),
    )

    for label, fields, key_class in key_types:
        if lines[0] == f"-----BEGIN {label}-----":
            break
    else:
        raise KeySerializationError("Missing or unknown PEM header")

    if lines[-1] != f"-----END {label}-----":
        raise KeySerializationError("Missing or mismatched PEM footer")

    values: dict[str, int] = {}
    for line in lines[1:-1]:
        name, sep, b64 = line.partition(":")
        name = name.strip()
        b64 = b64.strip()
        if not sep or not b64:
            raise KeySerializationError("Malformed PEM field line")
        if name not in fields:
            raise KeySerializationError(f"Unexpected PEM field: {name}")
        if name in values:
            raise KeySerializationError(f"Duplicate PEM field: {name}")
        values[name] = _b64_to_int(b64)

    if set(values) != set(fields):
        raise KeySerializationError("PEM fields do not match the key type")

    try:
        return key_class(**values)
    except (TypeError, ValueError) as exc:
        raise KeySerializationError(
            "Could not build key from PEM data") from exc


def _compute_fingerprint(public_key: RSAPublicKey) -> str:
    """
    Compute the hexadecimal fingerprint of the public key using SHA3-256
    over the concatenation of the string values of modulus and public exponent.
    """
    data = f"{public_key.modulus}:{public_key.public_exponent}".encode("ascii")
    return hashlib.sha3_256(data).hexdigest()


def create_signed_package(
    payload: bytes,
    private_key: RSAPrivateKey,
    public_key: RSAPublicKey,
    salt_length: int = 32,
) -> str:
    """
    Create a complete signed package JSON string containing the payload,
    Base64 signature, and necessary metadata.

    Args:
        payload (bytes): The original message or file contents.
        private_key (RSAPrivateKey): The key used to generate the signature.
        public_key (RSAPublicKey): The corresponding public key for fingerprinting.
        salt_length (int, optional): The salt length used in PSS. Defaults to 32.

    Returns:
        str: A serialized JSON string representing the SignedPackage.
    """

    # 1. Compute fingerprint
    fingerprint = _compute_fingerprint(public_key)

    # 2. Generate RSA-PSS signature (returns Base64 string)
    signature_b64 = rsa_pss_sign(payload, private_key, salt_length)

    # 3. Encode payload bytes to Base64 string
    payload_b64 = base64.b64encode(payload).decode("utf-8")

    # 4. Construct dictionary directly to preserve typing contracts
    package_dict = {
        "payload": payload_b64,
        "digest_algorithm": "SHA3-256",
        "signature": signature_b64,
        "salt_length": salt_length,
        "public_key_fingerprint": fingerprint,
    }

    return json.dumps(package_dict, ensure_ascii=False)


def verify_signed_package(
    package_data: str,
    public_key: RSAPublicKey,
) -> bool:
    """
    Parse a signed package JSON string and verify its cryptographic signature and integrity.

    Args:
        package_data (str): The serialized JSON string of the package.
        public_key (RSAPublicKey): The public key used to verify the signature.

    Returns:
        bool: True if the package is fully authentic and untampered.

    Raises:
        PackageParsingError: If the package structure cannot be parsed.
        PSSVerificationError: If the signature is invalid or tampered with.
    """

    # 1. Parse JSON structure
    try:
        data = json.loads(package_data)
    except (json.JSONDecodeError, TypeError) as exc:
        raise PackageParsingError(f"Failed to parse package as JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise PackageParsingError("Package content is not a valid JSON object.")

    # 2. Field presence & strict type validations
    required_fields = {
        "payload",
        "digest_algorithm",
        "signature",
        "salt_length",
        "public_key_fingerprint",
    }
    if not required_fields.issubset(data.keys()):
        raise PackageParsingError("Incomplete JSON package: missing required fields.")

    if not isinstance(data["payload"], str):
        raise PackageParsingError("Field 'payload' must be a string.")
    if not isinstance(data["signature"], str):
        raise PackageParsingError("Field 'signature' must be a string.")
    # Exclude bool since bool is an instance of int in Python
    if not isinstance(data["salt_length"], int) or isinstance(data["salt_length"], bool):
        raise PackageParsingError("Field 'salt_length' must be an integer.")
    if not isinstance(data["public_key_fingerprint"], str):
        raise PackageParsingError("Field 'public_key_fingerprint' must be a string.")

    payload_b64 = data["payload"]
    signature_b64 = data["signature"]
    salt_length = data["salt_length"]
    package_fingerprint = data["public_key_fingerprint"]

    # 3. Validate public key fingerprint (fail-fast)
    expected_fingerprint = _compute_fingerprint(public_key)
    if package_fingerprint != expected_fingerprint:
        raise PSSVerificationError(
            "Provided public key fingerprint does not match the signed package."
        )

    # 4. Decode Base64 payload
    try:
        original_payload = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise PackageParsingError(f"Corrupted or invalid Base64 payload: {exc}") from exc

    # 5. Cryptographic RSA-PSS verification
    try:
        is_valid = rsa_pss_verify(
            message=original_payload,
            signature=signature_b64,
            public_key=public_key,
            salt_length=salt_length,
        )
    except PSSVerificationError:
        raise
    except Exception as exc:
        raise PSSVerificationError(f"Signature verification failed: {exc}") from exc

    if not is_valid:
        raise PSSVerificationError("Invalid signature: content or signature has been tampered with.")

    return True
