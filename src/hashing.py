"""Cryptographic hashing and mask generation functions.

This module provides the Mask Generation Function 1 (MGF1) implementation
based on RFC 8017 (PKCS #1 v2.2), utilizing SHA3-256 as the underlying
digest algorithm.
"""
from hashlib import sha3_256
from src.exceptions import MaskGenerationError

# Tamanho do digest em bytes para o SHA3-256 
_DIGEST_SIZE = 32
_MAX_COUNTER = 2**32


def mask_generation_function(
    seed: bytes,
    mask_length: int
) -> bytes:
    """Generate a mask of the given length from a seed.

    Repeatedly applies hash_function to the seed concatenated with an
    incrementing 4-byte big-endian counter, starting at 0, concatenating
    each resulting digest until the accumulated output has at least
    mask_length bytes, then truncates the result to exactly mask_length
    bytes.

    Args:
        seed (bytes): The input bytes the mask is derived from.
        mask_length (int): The desired length, in bytes, of the output mask.

    Returns:
        bytes: A mask of exactly mask_length bytes.

    Raises:
        MaskGenerationError: If mask_length is negative, or exceeds the maximum
            output length the function can produce, which is the length
            of a single digest multiplied by 2**32 (the number of distinct
            counter values available).
    """
    # Caso o tamanho passado seja negativo
    if mask_length < 0:
        raise MaskGenerationError("mask_length cannot be negative.")

    #  Validacao do limite maximo da RFC 
    max_allowed = _MAX_COUNTER * _DIGEST_SIZE
    if mask_length > max_allowed:
        raise MaskGenerationError(
            f"mask_length ({mask_length}) exceeds maximum allowable length ({max_allowed})."
        )

    #  pedir 0 bytes devolve vazio imediatamente
    if mask_length == 0:
        return b""

    #  Geracao em ciclo
    mask_parts: list[bytes] = []
    generated_bytes = 0
    counter = 0

    while generated_bytes < mask_length:
        # Converte o contador numerico em 4 bytes no formato big-endian
        counter_bytes = counter.to_bytes(4, byteorder="big")

        # Calcula o hash da seed concatenada com o contador
        digest = sha3_256(seed + counter_bytes).digest()

        mask_parts.append(digest)
        generated_bytes += len(digest)
        counter += 1

    # Concatena todos os blocos e trunca no tamanho exato solicitado
    full_mask = b"".join(mask_parts)
    return full_mask[:mask_length]