# RSA Signature System

An educational RSA system implemented in Python 3.14. The project contains
RSA key generation, Miller-Rabin primality testing, RSA-OAEP encryption,
RSA-PSS signatures, SHA3-256 hashing, key serialization, signed-package
handling, and tampering tests.

The RSA arithmetic, OAEP, MGF1, and PSS implementations are written in the
project source code. OpenSSL and cryptographic libraries are not used to
automatically implement those components.

## Requirements

- Python 3.14
- GNU Make
- A virtual environment is recommended

## Installation

Create and activate a virtual environment from the repository root:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell, use:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the development dependencies:

```bash
python -m pip install -r requirements.txt
```

The Makefile automatically uses `.venv/bin/python` when that interpreter is
available. A different interpreter can be selected with `PYTHON=...`.

## Makefile Commands

Run the complete workflow:

```bash
make all
```

Available targets:

| Command | Description |
| --- | --- |
| `make test` | Run the complete pytest suite. |
| `make compile-tests` | Alias for `make test`. |
| `make rsa-key` | Generate a 2048-bit RSA key pair and print `p`, `q`, `n`, `e`, and `d`. |
| `make oaep` | Encrypt a configurable message with RSA-OAEP and print the Base64 ciphertext. |
| `make oaep-roundtrip` | Encrypt and decrypt a message with RSA-OAEP. |
| `make pss` | Sign a message with RSA-PSS and verify the generated signature. |
| `make tamper` | Alter one bit of RSA keys and demonstrate the resulting integrity errors. |
| `make all` | Run tests and all cryptographic demonstrations. |

The commands generate fresh RSA keys for each demonstration. This is expected
and can take several seconds because the default modulus size is 2048 bits.

## Configurable Demonstrations

The default message, RSA modulus size, and PSS salt length can be overridden
on the command line:

```bash
make oaep MESSAGE="Confidential message"
make oaep-roundtrip MESSAGE="Short binary-safe text"
make pss MESSAGE="Document to sign" SALT_LENGTH=32
make rsa-key KEY_BITS=2048
```

`KEY_BITS` must be at least `2048`, and the OAEP message must fit the selected
RSA modulus and SHA3-256 padding limits.

## Project Structure

```text
src/
	domain.py       RSA key and signed-package data classes
	exceptions.py   Domain-specific exceptions
	hashing.py      SHA3-256 and MGF1 helpers
	keys.py         Miller-Rabin based RSA key generation
	oaep.py         RSA-OAEP encryption and decryption
	packaging.py    PEM keys and JSON signed packages
	primes.py       Probabilistic prime generation
	pss.py          RSA-PSS signing and verification
tests/            Pytest tests, one module per implementation module
Makefile          Automated tests and cryptographic demonstrations
```

## Tests

Run tests directly with pytest or through Make:

```bash
python -m pytest -q
make test
```

The tests cover key generation, RSA round trips, OAEP padding and tampering,
PSS signatures and verification failures, key serialization, signed-package
parsing, and integrity attacks involving the payload, signature, and public
key.

## Security Notes

Textbook RSA must not be used directly because it is deterministic and does
not provide semantic security or robust integrity protection. RSA-OAEP adds
randomized padding for encryption, while RSA-PSS adds a randomized salt and
probabilistic encoding for signatures. These mechanisms are separate because
encryption and digital signatures have different security goals.



