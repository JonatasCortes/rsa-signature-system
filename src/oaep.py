from hashlib import sha3_256
import secrets
from src.domain import RSAPrivateKey, RSAPublicKey
from src.hashing import mask_generation_function
from src.exceptions import MessageTooLongError, OAEPPaddingError


def rsa_oaep_encrypt(message: bytes, public_key: RSAPublicKey, label: bytes = b"") -> bytes:
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

    modulus_byte_len = _calculate_modulus_byte_length(public_key)
    hash_output_len = sha3_256().digest_size
    data_block_len = modulus_byte_len - hash_output_len - 1

    _validate_message_length(message, modulus_byte_len, hash_output_len)

    label_hash = sha3_256(label).digest()
    data_block = _assemble_data_block(label_hash, message, data_block_len)

    seed = secrets.token_bytes(hash_output_len)
    masked_data_block = _mask_data(data_block, seed, len(data_block))
    masked_seed = _mask_data(seed, masked_data_block, hash_output_len)

    encoded_message = b'\x00' + masked_seed + masked_data_block
    ciphertext = _rsa_encoding(encoded_message, public_key, modulus_byte_len)

    return ciphertext


def rsa_oaep_decrypt(ciphertext: bytes, private_key: RSAPrivateKey, label: bytes = b"",) -> bytes:
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

    modulus_byte_len = _calculate_modulus_byte_length(private_key)
    hash_output_len = sha3_256().digest_size

    if len(ciphertext) != modulus_byte_len:
        raise OAEPPaddingError("invalid message format")

    message = _rsa_decoding(ciphertext, private_key, modulus_byte_len)

    control_byte = message[0:1]
    masked_seed = message[1:hash_output_len+1]
    masked_data_block = message[hash_output_len+1:]

    seed = _mask_data(masked_seed, masked_data_block, hash_output_len)
    data_block = _mask_data(masked_data_block, seed, len(masked_data_block))

    expected_label_hash = sha3_256(label).digest()
    retrieved_label_hash = data_block[:hash_output_len]

    remaining_data_block = data_block[hash_output_len:]
    remaining_data_block = remaining_data_block.lstrip(b'\x00')

    original_message = remaining_data_block[1:]

    failed = (control_byte != b'\x00' or
              retrieved_label_hash != expected_label_hash or
              remaining_data_block[0:1] != b'\x01')

    if failed:
        raise OAEPPaddingError("invalid message format")

    return original_message

# ========================== *
# PRIVATE AUXILIAR FUNCTIONS *
# ========================== *


def _calculate_modulus_byte_length(key: RSAPrivateKey | RSAPublicKey) -> int:
    bits = key.modulus.bit_length()
    return (bits + 7) // 8


def _validate_message_length(message: bytes, modulus_byte_len: int, hash_output_len: int) -> None:
    max_length = modulus_byte_len - (2 * hash_output_len) - 2
    if len(message) > max_length:
        error_message = f"message length ({len(message)}) exceeded maximum ({max_length})"
        raise MessageTooLongError(error_message)


def _assemble_data_block(label_hash: bytes, message: bytes, data_block_len: int) -> bytes:
    padding_len = data_block_len - len(label_hash + b'\x01' + message)
    return label_hash + padding_len*b'\x00' + b'\x01' + message


def _mask_data(data: bytes, mask_seed: bytes, mask_length: int):
    mask = mask_generation_function(mask_seed, mask_length)
    return bytes(b1 ^ b2 for b1, b2 in zip(data, mask))


def _rsa_encoding(message: bytes, public_key: RSAPublicKey, modulus_byte_length: int) -> bytes:
    integer_encoded_message = int.from_bytes(message, byteorder="big")
    integer_ciphertext = pow(integer_encoded_message,
                             public_key.public_exponent,
                             public_key.modulus)
    return integer_ciphertext.to_bytes(modulus_byte_length, byteorder="big")


def _rsa_decoding(ciphertext: bytes, private_key: RSAPrivateKey, modulus_byte_length: int) -> bytes:
    integer_ciphertext = int.from_bytes(ciphertext, byteorder="big")
    integer_message = pow(integer_ciphertext,
                          private_key.private_exponent,
                          private_key.modulus)
    return integer_message.to_bytes(modulus_byte_length, byteorder="big")
