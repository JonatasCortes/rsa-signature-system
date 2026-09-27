"""RSA key-pair generation utilities."""

from src.domain import RSAPrivateKey, RSAPublicKey
from src.exceptions import KeyGenerationError, PrimeGenerationError
from src.primes import generate_prime_number


PUBLIC_EXPONENT = 65537


def generate_key_pair(
	bit_length: int = 2048, max_attempts: int = 10
) -> tuple[RSAPublicKey, RSAPrivateKey]:
	"""Generate a matching RSA public and private key pair.

	Args:
		bit_length: Required bit length of the RSA modulus. Must be at least
			2048 bits.
		max_attempts: Maximum number of prime-pair generation attempts.

	Returns:
		A public key and its matching private key.

	Raises:
		KeyGenerationError: If the arguments are invalid or no valid key pair
			can be generated within ``max_attempts`` attempts.
	"""
	if bit_length < 2048:
		raise KeyGenerationError("bit_length must be at least 2048")
	if max_attempts < 1:
		raise KeyGenerationError("max_attempts must be at least 1")

	prime_bit_length = bit_length // 2

	for _ in range(max_attempts):
		try:
			first_prime = generate_prime_number(prime_bit_length, max_attempts=1000)
			second_prime = generate_prime_number(prime_bit_length, max_attempts=1000)
		except PrimeGenerationError:
			continue

		if first_prime == second_prime:
			continue

		modulus = first_prime * second_prime
		if modulus.bit_length() != bit_length:
			continue

		totient = (first_prime - 1) * (second_prime - 1)
		try:
			private_exponent = pow(PUBLIC_EXPONENT, -1, totient)
		except ValueError:
			continue

		public_key = RSAPublicKey(
			modulus=modulus,
			public_exponent=PUBLIC_EXPONENT,
		)
		private_key = RSAPrivateKey(
			modulus=modulus,
			public_exponent=PUBLIC_EXPONENT,
			private_exponent=private_exponent,
			first_prime=first_prime,
			second_prime=second_prime,
		)
		return public_key, private_key

	raise KeyGenerationError(
		f"Unable to generate a valid RSA key pair within {max_attempts} attempts"
	)
