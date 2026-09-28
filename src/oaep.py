from hashlib import sha3_256
import secrets
from src.domain import RSAPrivateKey, RSAPublicKey
from src.exceptions import MessageTooLongError


def rsa_oaep_encrypt(
    message: bytes,
    public_key: RSAPublicKey,
    label: bytes = b"",
) -> bytes:
    """Encrypt a short message with RSA-OAEP, using the given public key.

    Pads the message using the OAEP scheme before applying the RSA encryption
    operation, so that encrypting the same message twice produces different
    ciphertexts and any tampering with the ciphertext is detectable at
    decryption time.

    Args:
        message (bytes): The message to encrypt. Must be short enough to fit
          the OAEP padding structure for the given key size.
        public_key (RSAPublicKey): The recipient's public key.
        label (bytes, optional): An optional label bound to the ciphertext.
          Defaults to an empty byte sequence.

    Returns:
        bytes: The encrypted message, with the same byte length as the
        modulus of public_key.

    Raises:
        MessageTooLongError: If message does not fit the OAEP padding structure
          for the given key size.
    """
    modulus_byte_len = calculate_modulus_byte_length(public_key)
    hash_output_len = sha3_256().digest_size

    validate_length(message, modulus_byte_len, hash_output_len)

    label_hash = sha3_256(label).digest()


def rsa_oaep_decrypt(
    ciphertext: bytes,
    private_key: RSAPrivateKey,
    label: bytes = b"",
) -> bytes:
    """Decrypt an RSA-OAEP ciphertext, using the given private key.

    Reverses the RSA encryption operation and validates the resulting OAEP
    padding structure.

    Args:
        ciphertext (bytes): The encrypted message.
        private_key (RSAPrivateKey): The recipient's private key.
        label (bytes, optional): The label used at encryption time.
          Defaults to an empty byte sequence.

    Returns:
        bytes: The original decrypted message.

    Raises:
        OAEPPaddingError: If ciphertext does not decode into a structurally
          valid OAEP padded message.
    """
    ...


def calculate_modulus_byte_length(key: RSAPrivateKey | RSAPublicKey) -> int:
    bits = key.modulus.bit_length()
    return (bits + 7) // 8


def validate_length(message: bytes, modulus_byte_len: int, hash_output_len: int) -> None:
    max_length = modulus_byte_len - (2 * hash_output_len) - 2
    if len(message) > max_length:
        error_message = "message length exceeded maximum"
        raise MessageTooLongError(error_message)
