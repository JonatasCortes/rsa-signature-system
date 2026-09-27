"""RSA-PSS digital signatures using SHA3-256 and MGF1."""

import base64
import binascii
import hmac
import secrets
from hashlib import sha3_256

from src.domain import RSAPrivateKey, RSAPublicKey
from src.exceptions import PSSVerificationError, RSASystemError
from src.hashing import mask_generation_function


_HASH_LENGTH = 32
_TRAILING_BYTE = b"\xbc"


def rsa_pss_sign(
	message: bytes,
	private_key: RSAPrivateKey,
	salt_length: int = _HASH_LENGTH,
) -> str:
	"""Generate an RSA-PSS signature for ``message``.

	SHA3-256 is used for both message hashing and MGF1. The signature is
	returned as Base64 containing exactly one RSA modulus-sized byte string.

	Raises:
		RSASystemError: If the key, message, salt length, or modulus is invalid.
	"""
	_validate_message(message)
	_validate_salt_length(salt_length)
	modulus, private_exponent = _validate_private_key(private_key)
	encoded_message, _ = _encode_message(message, modulus, salt_length)

	signature_integer = pow(
		int.from_bytes(encoded_message, byteorder="big"),
		private_exponent,
		modulus,
	)
	modulus_length = (modulus.bit_length() + 7) // 8
	signature = signature_integer.to_bytes(modulus_length, byteorder="big")
	return base64.b64encode(signature).decode("ascii")


def rsa_pss_verify(
	message: bytes,
	signature: str,
	public_key: RSAPublicKey,
	salt_length: int = _HASH_LENGTH,
) -> bool:
	"""Verify an RSA-PSS signature for ``message``.

	Raises:
		PSSVerificationError: If the signature, key, or PSS encoding is invalid.
	"""
	try:
		_validate_message(message)
		_validate_salt_length(salt_length)
		modulus, public_exponent = _validate_public_key(public_key)
		signature_bytes = _decode_signature(signature, modulus)

		signature_integer = int.from_bytes(signature_bytes, byteorder="big")
		if signature_integer >= modulus:
			raise PSSVerificationError("Signature representative is out of range")

		encoded_integer = pow(signature_integer, public_exponent, modulus)
		encoded_length = (modulus.bit_length() - 1 + 7) // 8
		encoded_message = encoded_integer.to_bytes(encoded_length, byteorder="big")
		return _verify_encoded_message(
			message, encoded_message, modulus.bit_length() - 1, salt_length
		)
	except PSSVerificationError:
		raise
	except (TypeError, ValueError, OverflowError) as error:
		raise PSSVerificationError("Invalid RSA-PSS signature") from error


def _encode_message(
	message: bytes,
	modulus: int,
	salt_length: int,
) -> tuple[bytes, bytes]:
	encoded_length = (modulus.bit_length() - 1 + 7) // 8
	maximum_salt_length = encoded_length - _HASH_LENGTH - 2
	if maximum_salt_length < 0 or salt_length > maximum_salt_length:
		raise RSASystemError("Salt length is too large for the RSA modulus")

	message_hash = sha3_256(message).digest()
	salt = secrets.token_bytes(salt_length)
	hash_input = b"\x00" * 8 + message_hash + salt
	message_hash_prime = sha3_256(hash_input).digest()
	padding_length = encoded_length - _HASH_LENGTH - salt_length - 2
	data_block = b"\x00" * padding_length + b"\x01" + salt
	masked_data_block = _xor_bytes(
		data_block,
		mask_generation_function(message_hash_prime, len(data_block)),
	)
	unused_bits = 8 * encoded_length - (modulus.bit_length() - 1)
	masked_data_block = _clear_unused_bits(masked_data_block, unused_bits)
	return masked_data_block + message_hash_prime + _TRAILING_BYTE, salt


def _verify_encoded_message(
	message: bytes,
	encoded_message: bytes,
	encoded_bits: int,
	salt_length: int,
) -> bool:
	if len(encoded_message) < _HASH_LENGTH + salt_length + 2:
		raise PSSVerificationError("Encoded message is too short")
	if encoded_message[-1:] != _TRAILING_BYTE:
		raise PSSVerificationError("Invalid PSS trailer byte")

	unused_bits = 8 * len(encoded_message) - encoded_bits
	if unused_bits and encoded_message[0] & (0xFF << (8 - unused_bits)):
		raise PSSVerificationError("Non-zero unused bits in encoded message")

	masked_data_block = encoded_message[: -( _HASH_LENGTH + 1)]
	stored_hash = encoded_message[-(_HASH_LENGTH + 1) : -1]
	mask = mask_generation_function(stored_hash, len(masked_data_block))
	data_block = _xor_bytes(masked_data_block, mask)
	unused_bits = 8 * len(encoded_message) - encoded_bits
	data_block = _clear_unused_bits(data_block, unused_bits)

	separator_index = len(data_block) - salt_length - 1
	if separator_index < 0 or data_block[separator_index] != 1:
		raise PSSVerificationError("Missing PSS separator")
	if any(data_block[:separator_index]):
		raise PSSVerificationError("Invalid PSS zero padding")

	salt = data_block[-salt_length:] if salt_length else b""
	message_hash = sha3_256(message).digest()
	recalculated_hash = sha3_256(b"\x00" * 8 + message_hash + salt).digest()
	if not hmac.compare_digest(recalculated_hash, stored_hash):
		raise PSSVerificationError("RSA-PSS message hash mismatch")
	return True


def _decode_signature(signature: str, modulus: int) -> bytes:
	if not isinstance(signature, str):
		raise PSSVerificationError("Signature must be a Base64 string")
	try:
		decoded = base64.b64decode(signature, validate=True)
	except ValueError as error:
		raise PSSVerificationError("Signature is not valid Base64") from error
	expected_length = (modulus.bit_length() + 7) // 8
	if len(decoded) != expected_length:
		raise PSSVerificationError("Signature has an invalid length")
	return decoded


def _clear_unused_bits(value: bytes, unused_bits: int) -> bytes:
	if not unused_bits:
		return value
	first_byte = value[0] & (0xFF >> unused_bits)
	return bytes([first_byte]) + value[1:]


def _xor_bytes(left: bytes, right: bytes) -> bytes:
	return bytes(first ^ second for first, second in zip(left, right, strict=True))


def _validate_message(message: bytes) -> None:
	if not isinstance(message, bytes):
		raise RSASystemError("Message must be bytes")


def _validate_salt_length(salt_length: int) -> None:
	if not isinstance(salt_length, int) or isinstance(salt_length, bool):
		raise RSASystemError("Salt length must be a non-negative integer")
	if salt_length < 0:
		raise RSASystemError("Salt length cannot be negative")


def _validate_private_key(key: RSAPrivateKey) -> tuple[int, int]:
	if not isinstance(key, RSAPrivateKey) or key.modulus <= 0 or key.private_exponent <= 0:
		raise RSASystemError("Invalid RSA private key")
	return key.modulus, key.private_exponent


def _validate_public_key(key: RSAPublicKey) -> tuple[int, int]:
	if not isinstance(key, RSAPublicKey) or key.modulus <= 0 or key.public_exponent <= 0:
		raise PSSVerificationError("Invalid RSA public key")
	return key.modulus, key.public_exponent
