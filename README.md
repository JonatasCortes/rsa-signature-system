# RSA Signature System

An educational RSA system implemented in Python 3.14. The project provides a
command-line interface for RSA key generation, RSA-PSS signatures, RSA-OAEP
encryption, signed-package verification, and integrity testing.

The cryptographic operations are implemented in the project source code using
SHA3-256 and MGF1. External cryptographic libraries are not used to automate
RSA key generation, RSA arithmetic, OAEP, or PSS.

## Requirements

- Python 3.14
- GNU Make
- A virtual environment is recommended

## Installation

From the repository root, create and activate a virtual environment:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

The Makefile automatically uses `.venv/bin/python` when it exists. To use a
different interpreter, pass `PYTHON=...` to `make`.

## Command-Line Interface

The main application is `main.py`:

```bash
python main.py --help
```

Generate a 2048-bit RSA key pair:

```bash
python main.py keygen --out-dir keys --bits 2048
```

Sign and verify a file with RSA-PSS:

```bash
python main.py sign \
	--key keys/private.pem \
	--pub keys/public.pem \
	--file doc.txt \
	--out doc.sig.json

python main.py verify \
	--pub keys/public.pem \
	--package doc.sig.json
```

Encrypt and decrypt a short message with RSA-OAEP:

```bash
python main.py encrypt \
	--pub keys/public.pem \
	--in doc.txt \
	--out doc.enc

python main.py decrypt \
	--key keys/private.pem \
	--in doc.enc \
	--out doc.dec.txt
```

Use `--force` when an operation must overwrite an existing output file.

## Makefile

The Makefile automates the main workflows without changing the implementation
modules.

| Target | Description |
| --- | --- |
| `make help` | List available targets. |
| `make test` | Run the complete pytest suite. |
| `make keygen` | Generate or overwrite the keys in `keys/`. |
| `make sign` | Sign `doc.txt` into `doc.sig.json`. |
| `make verify` | Verify `doc.sig.json` with `keys/public.pem`. |
| `make encrypt` | Encrypt `doc.txt` into `doc.enc`. |
| `make decrypt` | Decrypt `doc.enc` into `doc.dec.txt` and compare the result with `doc.txt`. |
| `make tamper` | Demonstrate verification failure using `keys2/public.pem`. |
| `make all` | Run tests and the complete demonstration workflow. |
| `make clean` | Remove generated encryption and decryption files. |

Run the complete workflow with:

```bash
make all
```

The input and output paths can be customized without editing the Makefile:

```bash
make sign INPUT_FILE=contract.txt PACKAGE_FILE=contract.sig.json
make encrypt INPUT_FILE=message.txt CIPHERTEXT_FILE=message.enc
make decrypt CIPHERTEXT_FILE=message.enc DECRYPTED_FILE=message.dec.txt
```

The RSA key size and key directories are also configurable:

```bash
make keygen KEY_BITS=2048 KEY_DIR=keys
make tamper ALT_KEY_DIR=keys2 PACKAGE_FILE=doc.sig.json
```

## Repository Structure

```text
main.py             Command-line interface
Makefile            Automated build and demonstration workflows
keys/               Primary public and private PEM keys
keys2/              Alternate key pair for tampering tests
doc.txt             Sample input document
doc*.sig.json       Sample signed packages
src/                RSA, OAEP, PSS, hashing, and packaging modules
tests/              Pytest test suite
```

## Tests

Run the complete suite through Make or directly with pytest:

```bash
make test
python -m pytest -q
```

The tests cover prime generation, RSA key generation and round trips, OAEP
padding and decryption failures, PSS signing and verification, key
serialization, signed-package parsing, and tampering with payloads,
signatures, and public keys.

## Security Notes

Textbook RSA is deterministic and does not provide semantic security or robust
integrity protection, so it must not be used directly for messages. RSA-OAEP
adds randomized padding for encryption. RSA-PSS adds a randomized salt and
probabilistic encoding for digital signatures. These schemes address different
security goals and should not be substituted for one another.
# RSA-digital-signature

With python 3.14 installed, run:

```Bash
python -m venv .venv
```

```Bash
.\.venv\Scripts\activate # Windows

source .venv/bin/activate # Linux / Mac
```

```Bash
pip install -r requirements.txt
```



