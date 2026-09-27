import pytest

from src.exceptions import PSSVerificationError
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


def test_rsa_pss_rejects_different_public_key(rsa_keys):
	"""A signature does not verify with an unrelated public key."""
	_, private_key = rsa_keys
	other_public_key, _ = generate_key_pair()
	message = b"This key must not verify the signature."
	signature = rsa_pss_sign(message, private_key)

	with pytest.raises(PSSVerificationError):
		rsa_pss_verify(message, signature, other_public_key)
