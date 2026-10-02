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

from __future__ import annotations

import argparse
import base64
import sys
from collections.abc import Sequence
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

PUBLIC_KEY_NAME = "public.pem"
PRIVATE_KEY_NAME = "private.pem"
DEFAULT_KEY_DIR = "keys"
DEFAULT_KEY_BITS = 2048
DEFAULT_SALT_LENGTH = 32


# ================= *
# COMMAND HANDLERS  *
# ================= *


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

    public_path = out_dir / PUBLIC_KEY_NAME
    private_path = out_dir / PRIVATE_KEY_NAME

    _write_text(public_path, export_key_to_pem(public_key), args.force)
    _write_text(private_path, export_key_to_pem(private_key), args.force)

    print(f"Public key:  {public_path}")
    print(f"Private key: {private_path}")
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
            private_key.modulus, private_key.public_exponent
        )

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

    print(f"Message encrypted with RSA-OAEP. Base64 output saved to {args.out}")
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


# ================ *
# ARGUMENT PARSER  *
# ================ *


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RSA-PSS digital signatures and RSA-OAEP encryption (SHA3-256)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    _add_keygen_parser(subparsers)
    _add_sign_parser(subparsers)
    _add_verify_parser(subparsers)
    _add_encrypt_parser(subparsers)
    _add_decrypt_parser(subparsers)
    return parser


def _add_force_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--force", action="store_true",
        help="overwrite output files if they already exist",
    )


def _add_keygen_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    p = subparsers.add_parser("keygen", help="generate an RSA key pair (PEM)")
    p.add_argument("--out-dir", default=DEFAULT_KEY_DIR,
                   help="folder where the PEM files are saved")
    p.add_argument("--bits", type=int, default=DEFAULT_KEY_BITS,
                   help="RSA modulus size in bits")
    _add_force_flag(p)
    p.set_defaults(func=cmd_keygen)


def _add_sign_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    p = subparsers.add_parser("sign", help="sign a file (RSA-PSS)")
    p.add_argument("--key", required=True, help="private key (PEM)")
    p.add_argument("--pub",
                   help="public key (PEM); derived from --key if omitted")
    p.add_argument("--file", required=True, help="file to sign")
    p.add_argument("--out", required=True, help="signed package (JSON)")
    p.add_argument("--salt-length", type=int, default=DEFAULT_SALT_LENGTH,
                   help="PSS salt length in bytes")
    _add_force_flag(p)
    p.set_defaults(func=cmd_sign)


def _add_verify_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    p = subparsers.add_parser("verify", help="verify a signed package")
    p.add_argument("--pub", required=True, help="public key (PEM)")
    p.add_argument("--package", required=True, help="signed package (JSON)")
    p.set_defaults(func=cmd_verify)


def _add_encrypt_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    p = subparsers.add_parser("encrypt", help="encrypt a short message (RSA-OAEP)")
    p.add_argument("--pub", required=True, help="recipient's public key (PEM)")
    p.add_argument("--in", dest="infile", required=True,
                   help="file with the message to encrypt")
    p.add_argument("--out", required=True, help="output file (Base64 text)")
    _add_force_flag(p)
    p.set_defaults(func=cmd_encrypt)


def _add_decrypt_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    p = subparsers.add_parser("decrypt", help="decrypt a message (RSA-OAEP)")
    p.add_argument("--key", required=True, help="private key (PEM)")
    p.add_argument("--in", dest="infile", required=True,
                   help="file with the Base64 ciphertext")
    p.add_argument("--out", help="output file; prints to stdout if omitted")
    p.set_defaults(func=cmd_decrypt)


# ============ *
# FILE HELPERS *
# ============ *


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
        raise RSASystemError(f"{path} already exists (use --force to overwrite)")
    path.write_text(content, encoding="utf-8")


# ===== *
# MAIN  *
# ===== *


def main(argv: Sequence[str] | None = None) -> int:
    """
    Parse the command line and run the selected subcommand.

    Args:
        argv (Sequence[str] | None): Arguments to parse. Uses sys.argv[1:]
            when omitted, which lets tests call main(["verify", ...]) directly.

    Returns:
        int: EXIT_OK on success, EXIT_FAIL if any expected error occurs.
    """
    args = _build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RSASystemError as error:
        print(f"ERROR: {error}", file=sys.stderr)
    except OSError as error:
        print(f"FILE ERROR: {error}", file=sys.stderr)
    return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())