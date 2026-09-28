from src.domain import RSAPublicKey, RSAPrivateKey, SignedPackage

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
    ...


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
    ...


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
    ...