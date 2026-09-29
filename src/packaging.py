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
    ...


def _compute_fingerprint(public_key: RSAPublicKey) -> str:
    """
    Compute the hexadecimal fingerprint of the public key using SHA3-256
    over the concatenation of the string values of modulus and public exponent.
    """
    data = str(public_key.modulus).encode("utf-8") + \
        str(public_key.public_exponent).encode("utf-8")
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

    # 1. Compute the public key fingerprint
    fingerprint = _compute_fingerprint(public_key)

    # 2. Generate digital signature via RSA-PSS (returns Base64 string)
    signature_b64 = rsa_pss_sign(payload, private_key, salt_length)

    # 3. Convert the original payload bytes to Base64
    payload_b64 = base64.b64encode(payload).decode("utf-8")

    # 4. Instantiate SignedPackage object or equivalent dictionary
    # If SignedPackage is a dataclass or standard class:
    package = SignedPackage(
        payload=payload_b64,
        digest_algorithm="SHA3-256",
        signature=signature_b64,
        salt_length=salt_length,
        public_key_fingerprint=fingerprint,
    )

    # 5. Serialize package to JSON
    # If SignedPackage has a .to_dict() method or __dict__:
    if hasattr(package, "__dict__"):
        package_dict = package.__dict__
    else:
        package_dict = {
            "payload": package.payload,
            "digest_algorithm": package.digest_algorithm,
            "signature": package.signature,
            "salt_length": package.salt_length,
            "public_key_fingerprint": package.public_key_fingerprint,
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

    # 1. JSON parsing and structural validation
    try:
        data = json.loads(package_data)
        if not isinstance(data, dict):
            raise PackageParsingError(
                "Package content is not a valid JSON object.")

        required_fields = {
            "payload",
            "digest_algorithm",
            "signature",
            "salt_length",
            "public_key_fingerprint",
        }
        if not required_fields.issubset(data.keys()):
            raise PackageParsingError(
                "Incomplete JSON package: missing required fields.")

        payload_b64 = data["payload"]
        signature_b64 = data["signature"]
        salt_length = data["salt_length"]
        package_fingerprint = data["public_key_fingerprint"]

    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise PackageParsingError(f"Failed to parse package: {exc}") from exc

    # 2. Public key fingerprint validation
    expected_fingerprint = _compute_fingerprint(public_key)
    if package_fingerprint != expected_fingerprint:
        raise PSSVerificationError(
            "Provided public key fingerprint does not match the signed package."
        )

    # 3. Decode Base64 payload back to bytes
    try:
        original_payload = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise PackageParsingError(
            f"Corrupted or invalid Base64 payload: {exc}") from exc

    # 4. RSA-PSS signature verification
    # rsa_pss_verify validates whether the signature matches the payload
    is_valid = rsa_pss_verify(
        payload=original_payload,
        signature=signature_b64,
        public_key=public_key,
        salt_length=salt_length,
    )

    if not is_valid:
        raise PSSVerificationError(
            "Invalid signature: content or signature has been tampered with.")

    return True
