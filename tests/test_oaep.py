from src.oaep import rsa_oaep_encrypt, rsa_oaep_decrypt
from src.keys import generate_key_pair
from src.exceptions import MessageTooLongError, OAEPPaddingError
from hashlib import sha3_256
import pytest

PUBLIC_KEY, PRIVATE_KEY = generate_key_pair()


def test_decrypt_recovers_original_message_successfully():
    message = b'perfectly normal message'
    ciphertext = rsa_oaep_encrypt(message, PUBLIC_KEY, b'label')
    plain_text = rsa_oaep_decrypt(ciphertext, PRIVATE_KEY, b'label')
    assert message == plain_text


def test_encrypting_same_message_twice_yields_different_ciphertexts():
    message = b'perfectly normal message'
    ciphertext1 = rsa_oaep_encrypt(message, PUBLIC_KEY)
    ciphertext2 = rsa_oaep_encrypt(message, PUBLIC_KEY)
    assert ciphertext1 != ciphertext2


def test_encrypt_exceeding_max_length_raises_message_too_long_error():
    modulus_byte_len = (PUBLIC_KEY.modulus.bit_length() + 7) // 8
    hash_output_len = sha3_256().digest_size
    max_length = modulus_byte_len - (2 * hash_output_len) - 2

    with pytest.raises(MessageTooLongError):
        message = b'\x00' * (max_length + 1)
        rsa_oaep_encrypt(message, PUBLIC_KEY)


def test_decrypt_with_invalid_ciphertext_length_raises_oaep_padding_error():
    invalid_ciphertext = b''
    with pytest.raises(OAEPPaddingError):
        rsa_oaep_decrypt(invalid_ciphertext, PRIVATE_KEY)


def test_decrypt_with_corrupted_ciphertext_raises_oaep_padding_error():
    message = b'perfectly normal message'
    ciphertext = rsa_oaep_encrypt(message, PUBLIC_KEY)
    corrupted_ciphertext = ciphertext[:10] + b'\xFF' + ciphertext[11:]

    with pytest.raises(OAEPPaddingError):
        rsa_oaep_decrypt(corrupted_ciphertext, PRIVATE_KEY)


def test_decrypt_with_incompatible_private_key_raises_oaep_padding_error():
    _, incompatible_private_key = generate_key_pair()

    message = b'perfectly normal message'
    ciphertext = rsa_oaep_encrypt(message, PUBLIC_KEY)

    with pytest.raises(OAEPPaddingError):
        rsa_oaep_decrypt(ciphertext, incompatible_private_key)


def test_decrypt_with_incompatible_labels_raises_oaep_padding_error():
    message = b'perfectly normal message'
    ciphertext = rsa_oaep_encrypt(message, PUBLIC_KEY, b'label')

    with pytest.raises(OAEPPaddingError):
        rsa_oaep_decrypt(ciphertext, PRIVATE_KEY, b'incompatible')
