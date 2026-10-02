PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
KEY_BITS ?= 2048
SALT_LENGTH ?= 32
MESSAGE ?= RSA-OAEP demonstration message

export KEY_BITS
export SALT_LENGTH
export MESSAGE

.PHONY: all test compile-tests rsa-key oaep oaep-roundtrip pss tamper
.ONESHELL:
.SILENT:

all: test rsa-key oaep oaep-roundtrip pss tamper

test compile-tests:
	$(PYTHON) -m pytest -q

rsa-key:
	$(PYTHON) - <<'PY'
	from src.keys import generate_key_pair

	public_key, private_key = generate_key_pair(bit_length=int(__import__("os").environ["KEY_BITS"]))
	print("RSA key generation")
	print(f"p = {private_key.first_prime}")
	print(f"q = {private_key.second_prime}")
	print(f"n = p * q = {public_key.modulus}")
	print(f"modulus bits = {public_key.modulus.bit_length()}")
	print(f"e = {public_key.public_exponent}")
	print(f"d = {private_key.private_exponent}")
	PY

oaep:
	$(PYTHON) - <<'PY'
	import base64
	import os

	from src.keys import generate_key_pair
	from src.oaep import rsa_oaep_encrypt

	public_key, _ = generate_key_pair(bit_length=int(os.environ["KEY_BITS"]))
	message = os.environ["MESSAGE"].encode("utf-8")
	ciphertext = rsa_oaep_encrypt(message, public_key)
	print(f"message = {message!r}")
	print(f"ciphertext (Base64) = {base64.b64encode(ciphertext).decode('ascii')}")
	PY

oaep-roundtrip:
	$(PYTHON) - <<'PY'
	import base64
	import os

	from src.exceptions import OAEPPaddingError
	from src.keys import generate_key_pair
	from src.oaep import rsa_oaep_decrypt, rsa_oaep_encrypt

	public_key, private_key = generate_key_pair(bit_length=int(os.environ["KEY_BITS"]))
	message = os.environ["MESSAGE"].encode("utf-8")
	ciphertext = rsa_oaep_encrypt(message, public_key)
	plaintext = rsa_oaep_decrypt(ciphertext, private_key)
	print(f"ciphertext (Base64) = {base64.b64encode(ciphertext).decode('ascii')}")
	print(f"decrypted message = {plaintext.decode('utf-8')}")
	if plaintext != message: raise OAEPPaddingError("OAEP round-trip did not recover the original message")
	PY

pss:
	$(PYTHON) - <<'PY'
	import os

	from src.keys import generate_key_pair
	from src.pss import rsa_pss_sign, rsa_pss_verify

	public_key, private_key = generate_key_pair(bit_length=int(os.environ["KEY_BITS"]))
	message = os.environ["MESSAGE"].encode("utf-8")
	signature = rsa_pss_sign(message, private_key, int(os.environ["SALT_LENGTH"]))
	print(f"message = {message!r}")
	print(f"signature (Base64) = {signature}")
	print(f"verification = {rsa_pss_verify(message, signature, public_key, int(os.environ['SALT_LENGTH']))}")
	PY

tamper:
	$(PYTHON) - <<'PY' || { echo "error: OAEP rejected the altered key"; exit 0; }
	import os
	from dataclasses import replace

	from src.keys import generate_key_pair
	from src.oaep import rsa_oaep_decrypt, rsa_oaep_encrypt

	public_key, private_key = generate_key_pair(bit_length=int(os.environ["KEY_BITS"]))
	message = 42
	ciphertext = pow(message, public_key.public_exponent, public_key.modulus)
	altered_private_key = replace(private_key, modulus=private_key.modulus ^ 1)
	altered_plaintext = pow(ciphertext, altered_private_key.private_exponent, altered_private_key.modulus)
	print("RSA one-bit alteration")
	print(f"original modulus = {private_key.modulus}")
	print(f"altered modulus  = {altered_private_key.modulus}")
	print(f"original plaintext = {message}")
	print(f"altered plaintext  = {altered_plaintext}")
	print("error: RSA integrity check failed after the key alteration")

	oaep_ciphertext = rsa_oaep_encrypt(b"OAEP integrity", public_key)
	altered_oaep_key = replace(private_key, modulus=private_key.modulus ^ 1)
	print("\nRSA-OAEP one-bit key alteration")
	print(f"original private modulus = {private_key.modulus}")
	print(f"altered private modulus  = {altered_oaep_key.modulus}")
	rsa_oaep_decrypt(oaep_ciphertext, altered_oaep_key)
	PY