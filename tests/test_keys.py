from unittest.mock import patch

import pytest

from src.exceptions import KeyGenerationError, PrimeGenerationError
from src.keys import PUBLIC_EXPONENT, generate_key_pair


def test_generate_key_pair_rejects_small_modulus():
	with pytest.raises(KeyGenerationError):
		generate_key_pair(bit_length=1024)


def test_generate_key_pair_returns_matching_keys():
	public_key, private_key = generate_key_pair(bit_length=2048)

	assert public_key.modulus == private_key.modulus
	assert public_key.modulus.bit_length() == 2048
	assert public_key.public_exponent == PUBLIC_EXPONENT
	assert private_key.public_exponent == PUBLIC_EXPONENT


def test_generate_key_pair_supports_rsa_round_trip():
	public_key, private_key = generate_key_pair(bit_length=2048)
	message = 42

	encrypted = pow(message, public_key.public_exponent, public_key.modulus)
	decrypted = pow(encrypted, private_key.private_exponent, private_key.modulus)

	assert decrypted == message


def test_generate_key_pair_creates_different_moduli():
	first_public_key, _ = generate_key_pair(bit_length=2048)
	second_public_key, _ = generate_key_pair(bit_length=2048)

	assert first_public_key.modulus != second_public_key.modulus


def test_generate_key_pair_retries_when_public_exponent_has_no_inverse():
	with patch(
		"src.keys.generate_prime_number",
		side_effect=[5, 7, 11, 13],
	):
		with pytest.raises(KeyGenerationError):
			generate_key_pair(bit_length=2048, max_attempts=2)


def test_generate_key_pair_wraps_prime_generation_failure():
	with patch(
		"src.keys.generate_prime_number",
		side_effect=PrimeGenerationError("generation failed"),
	):
		with pytest.raises(KeyGenerationError):
			generate_key_pair(bit_length=2048)
