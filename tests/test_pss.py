import base64

import pytest

from src.domain import RSAPrivateKey
from src.exceptions import PSSVerificationError, RSASystemError
from src.keys import generate_key_pair
from src.pss import rsa_pss_sign, rsa_pss_verify


@pytest.fixture(scope="module")
def rsa_keys():
	"""Provide one RSA key pair for the PSS behavior tests."""
	return generate_key_pair()


def test_rsa_pss_sign_and_verify_returns_true(rsa_keys):
	"""A signature verifies with the public key that matches its private key."""
	public_key, private_key = rsa_keys
	message = b"RSA-PSS protects this message."

	signature = rsa_pss_sign(message, private_key)

	assert rsa_pss_verify(message, signature, public_key)


def test_rsa_pss_signatures_are_probabilistic(rsa_keys):
	"""Signing the same message twice uses a fresh random salt."""
	_, private_key = rsa_keys
	message = b"The salt must make signatures distinct."

	first_signature = rsa_pss_sign(message, private_key)
	second_signature = rsa_pss_sign(message, private_key)

	assert first_signature != second_signature


def test_rsa_pss_supports_custom_salt_length(rsa_keys):
	"""A signature verifies when both sides use a custom salt length."""
	public_key, private_key = rsa_keys
	message = b"RSA-PSS with a custom salt length."

	signature = rsa_pss_sign(message, private_key, salt_length=16)

	assert rsa_pss_verify(message, signature, public_key, salt_length=16)


def test_rsa_pss_rejects_mismatched_salt_length(rsa_keys):
	"""Verification fails when the expected salt length differs from signing."""
	public_key, private_key = rsa_keys
	message = b"The salt length is part of the verification parameters."
	signature = rsa_pss_sign(message, private_key, salt_length=16)

	with pytest.raises(PSSVerificationError):
		rsa_pss_verify(message, signature, public_key, salt_length=32)


def test_rsa_pss_rejects_modulus_that_is_too_small():
	"""Signing fails when the modulus cannot fit the default PSS encoding."""
	private_key = RSAPrivateKey(
		modulus=1 << 511,
		public_exponent=65537,
		private_exponent=1,
		first_prime=3,
		second_prime=5,
	)

	with pytest.raises(RSASystemError):
		rsa_pss_sign(b"message", private_key)


def test_rsa_pss_rejects_modified_message(rsa_keys):
	"""Changing one message byte invalidates the PSS hash binding."""
	public_key, private_key = rsa_keys
	signature = rsa_pss_sign(b"original message", private_key)

	with pytest.raises(PSSVerificationError):
		rsa_pss_verify(b"original messagf", signature, public_key)


def test_rsa_pss_rejects_modified_signature(rsa_keys):
	"""Changing one encoded signature character invalidates verification."""
	public_key, private_key = rsa_keys
	signature = rsa_pss_sign(b"signed message", private_key)
	replacement = "A" if signature[0] != "A" else "B"
	modified_signature = replacement + signature[1:]

	with pytest.raises(PSSVerificationError):
		rsa_pss_verify(b"signed message", modified_signature, public_key)


def test_rsa_pss_rejects_modified_signature_in_the_middle(rsa_keys):
	"""Changing a middle Base64 character invalidates verification."""
	public_key, private_key = rsa_keys
	signature = rsa_pss_sign(b"signed message", private_key)
	mutation_index = len(signature) // 2
	replacement = "A" if signature[mutation_index] != "A" else "B"
	modified_signature = (
		signature[:mutation_index] + replacement + signature[mutation_index + 1 :]
	)

	with pytest.raises(PSSVerificationError):
		rsa_pss_verify(b"signed message", modified_signature, public_key)


def test_rsa_pss_rejects_invalid_base64(rsa_keys):
	"""Malformed Base64 input raises the verification-specific exception."""
	public_key, _ = rsa_keys

	with pytest.raises(PSSVerificationError):
		rsa_pss_verify(b"message", "not-a-valid-base64-signature!", public_key)


def test_rsa_pss_rejects_invalid_verification_inputs(rsa_keys):
	"""Invalid message and salt arguments use the verification exception."""
	public_key, _ = rsa_keys

	with pytest.raises(PSSVerificationError):
		rsa_pss_verify("message", "", public_key)  # type: ignore[arg-type]
	with pytest.raises(PSSVerificationError):
		rsa_pss_verify(b"message", "", public_key, salt_length=-1)


def test_rsa_pss_rejects_signature_representative_out_of_range(rsa_keys):
	"""A signature integer equal to the modulus is invalid."""
	public_key, _ = rsa_keys
	modulus_length = (public_key.modulus.bit_length() + 7) // 8
	invalid_signature = public_key.modulus.to_bytes(modulus_length, byteorder="big")
	signature = base64.b64encode(invalid_signature).decode("ascii")

	with pytest.raises(PSSVerificationError):
		rsa_pss_verify(b"message", signature, public_key)


def test_rsa_pss_rejects_different_public_key(rsa_keys):
	"""A signature does not verify with an unrelated public key."""
	_, private_key = rsa_keys
	other_public_key, _ = generate_key_pair()
	message = b"This key must not verify the signature."
	signature = rsa_pss_sign(message, private_key)

	with pytest.raises(PSSVerificationError):
		rsa_pss_verify(message, signature, other_public_key)
