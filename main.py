"""
Command-line interface for the RSA digital signature system.

Exposes key generation, RSA-PSS signing and verification, and RSA-OAEP
encryption and decryption (all using SHA3-256 and MGF1) as subcommands.

Usage (from the project root):
    python main.py keygen  --out-dir keys
    python main.py sign    --key keys/private.pem --file doc.txt --out doc.sig.json
    python main.py verify  --pub keys/public.pem --package doc.sig.json
    python main.py encrypt --pub keys/public.pem --in msg.txt --out msg.enc
    python main.py decrypt --key keys/private.pem --in msg.enc

Exit codes:
    0: the operation succeeded.
    1: the operation failed (invalid signature, malformed input, etc.).
"""

import argparse
import base64
import sys
from pathlib import Path

from src.domain import RSAPrivateKey, RSAPublicKey
from src.exceptions import PackageParsingError, PSSVerificationError, RSASystemError
from src.keys import generate_key_pair
from src.oaep import rsa_oaep_decrypt, rsa_oaep_encrypt
from src.packaging import (
    create_signed_package,
    export_key_to_pem,
    import_key_from_pem,
    verify_signed_package,
)

EXIT_OK = 0
EXIT_FAIL = 1


def cmd_keygen(args: argparse.Namespace) -> int:
    """
    Generate an RSA key pair and save both keys as PEM files.

    Args:
        args (argparse.Namespace): Parsed arguments (out_dir, bits, force).

    Returns:
        int: EXIT_OK on success.

    Raises:
        RSASystemError: If key generation or serialization fails, or if an
            output file already exists and `force` was not given.
    """
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating a {args.bits}-bit RSA key pair...")
    public_key, private_key = generate_key_pair(bit_length=args.bits)

    _write_text(out_dir / "public.pem",
                export_key_to_pem(public_key), args.force)
    _write_text(out_dir / "private.pem",
                export_key_to_pem(private_key), args.force)

    print(f"Public key:  {out_dir / 'public.pem'}")
    print(f"Private key: {out_dir / 'private.pem'}")
    print("WARNING: the private key is stored without a password. Do not share it.")
    return EXIT_OK


def cmd_sign(args: argparse.Namespace) -> int:
    """
    Sign a file with RSA-PSS and save the signed package as JSON.

    If no public key file is given, the public key is derived from the
    private key (same modulus and public exponent).

    Args:
        args (argparse.Namespace): Parsed arguments (key, pub, file, out,
            salt_length, force).

    Returns:
        int: EXIT_OK on success.

    Raises:
        RSASystemError: If the keys are invalid or signing fails.
    """
    private_key = _load_private_key(args.key)
    if args.pub:
        public_key = _load_public_key(args.pub)
    else:
        public_key = RSAPublicKey(
            private_key.modulus, private_key.public_exponent)

    payload = Path(args.file).read_bytes()
    package = create_signed_package(
        payload, private_key, public_key, salt_length=args.salt_length
    )
    _write_text(Path(args.out), package, args.force)

    print(f"File signed ({len(payload)} bytes). Package saved to {args.out}")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    """
    Verify a signed package with the signer's public key.

    Prints whether the file is intact or the signature is invalid, and
    never raises verification errors to the caller.

    Args:
        args (argparse.Namespace): Parsed arguments (pub, package).

    Returns:
        int: EXIT_OK if the signature is valid, EXIT_FAIL otherwise.

    Raises:
        RSASystemError: If the public key file is invalid.
    """
    public_key = _load_public_key(args.pub)
    package_data = Path(args.package).read_text(encoding="utf-8")

    try:
        verify_signed_package(package_data, public_key)
    except PackageParsingError as error:
        print(f"MALFORMED PACKAGE: {error}")
        return EXIT_FAIL
    except PSSVerificationError as error:
        print(f"INVALID SIGNATURE: {error}")
        return EXIT_FAIL

    print("FILE INTACT: valid RSA-PSS signature.")
    return EXIT_OK


def cmd_encrypt(args: argparse.Namespace) -> int:
    """
    Encrypt a short message with RSA-OAEP and save it as Base64 text.

    Args:
        args (argparse.Namespace): Parsed arguments (pub, infile, out, force).

    Returns:
        int: EXIT_OK on success.

    Raises:
        RSASystemError: If the key is invalid or the message is too long.
    """
    public_key = _load_public_key(args.pub)
    message = Path(args.infile).read_bytes()

    ciphertext = rsa_oaep_encrypt(message, public_key)
    encoded = base64.b64encode(ciphertext).decode("ascii")
    _write_text(Path(args.out), encoded + "\n", args.force)

    print(
        f"Message encrypted with RSA-OAEP. Base64 output saved to {args.out}")
    return EXIT_OK


def cmd_decrypt(args: argparse.Namespace) -> int:
    """
    Decrypt a Base64 RSA-OAEP ciphertext with the recipient's private key.

    Args:
        args (argparse.Namespace): Parsed arguments (key, infile, out).

    Returns:
        int: EXIT_OK on success, EXIT_FAIL if the input is not valid Base64.

    Raises:
        RSASystemError: If the key is invalid or the OAEP padding check
            fails (reported with a single generic message).
    """
    private_key = _load_private_key(args.key)
    text = Path(args.infile).read_text(encoding="ascii").strip()

    try:
        ciphertext = base64.b64decode(text, validate=True)
    except ValueError:
        print("ERROR: input is not valid Base64")
        return EXIT_FAIL

    message = rsa_oaep_decrypt(ciphertext, private_key)

    if args.out:
        Path(args.out).write_bytes(message)
        print(f"Decrypted message saved to {args.out}")
    else:
        sys.stdout.buffer.write(message + b"\n")
    return EXIT_OK


def main() -> int:
    """
    Parse the command line and run the selected subcommand.

    Returns:
        int: EXIT_OK on success, EXIT_FAIL if any expected error occurs.
    """
    args = _build_parser().parse_args()
    try:
        return args.func(args)
    except RSASystemError as error:
        print(f"ERROR: {error}", file=sys.stderr)
    except OSError as error:
        print(f"FILE ERROR: {error}", file=sys.stderr)
    return EXIT_FAIL

# ========================== *
# PRIVATE AUXILIAR FUNCTIONS *
# ========================== *


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RSA-PSS digital signatures and RSA-OAEP encryption (SHA3-256)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser(
        "keygen", help="generate an RSA key pair (PEM)")
    keygen.add_argument("--out-dir", default="keys")
    keygen.add_argument("--bits", type=int, default=2048)
    keygen.add_argument("--force", action="store_true", help="overwrite files")
    keygen.set_defaults(func=cmd_keygen)

    sign = subparsers.add_parser("sign", help="sign a file (RSA-PSS)")
    sign.add_argument("--key", required=True, help="private key (PEM)")
    sign.add_argument(
        "--pub", help="public key (PEM); derived from the private key if omitted")
    sign.add_argument("--file", required=True, help="file to sign")
    sign.add_argument("--out", required=True, help="signed package (JSON)")
    sign.add_argument("--salt-length", type=int, default=32)
    sign.add_argument("--force", action="store_true")
    sign.set_defaults(func=cmd_sign)

    verify = subparsers.add_parser("verify", help="verify a signed package")
    verify.add_argument("--pub", required=True, help="public key (PEM)")
    verify.add_argument("--package", required=True,
                        help="signed package (JSON)")
    verify.set_defaults(func=cmd_verify)

    encrypt = subparsers.add_parser(
        "encrypt", help="encrypt a short message (RSA-OAEP)")
    encrypt.add_argument("--pub", required=True)
    encrypt.add_argument("--in", dest="infile", required=True)
    encrypt.add_argument("--out", required=True)
    encrypt.add_argument("--force", action="store_true")
    encrypt.set_defaults(func=cmd_encrypt)

    decrypt = subparsers.add_parser(
        "decrypt", help="decrypt a message (RSA-OAEP)")
    decrypt.add_argument("--key", required=True)
    decrypt.add_argument("--in", dest="infile", required=True)
    decrypt.add_argument("--out", help="print to stdout if omitted")
    decrypt.set_defaults(func=cmd_decrypt)

    return parser


def _load_public_key(path: str) -> RSAPublicKey:
    key = import_key_from_pem(Path(path).read_text(encoding="utf-8"))
    if not isinstance(key, RSAPublicKey):
        raise RSASystemError(f"{path} does not contain a public key")
    return key


def _load_private_key(path: str) -> RSAPrivateKey:
    key = import_key_from_pem(Path(path).read_text(encoding="utf-8"))
    if not isinstance(key, RSAPrivateKey):
        raise RSASystemError(f"{path} does not contain a private key")
    return key


def _write_text(path: Path, content: str, force: bool = False) -> None:
    if path.exists() and not force:
        raise RSASystemError(
            f"{path} already exists (use --force to overwrite)")
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
