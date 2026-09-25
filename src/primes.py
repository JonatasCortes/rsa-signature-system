import random
from src.exceptions import PrimeGenerationError


def is_probable_prime(candidate: int, rounds: int = 50) -> bool:
    """
    Return True if the candidate is a probable prime using the Miller-Rabin primality test.

    The Miller-Rabin test is a probabilistic algorithm that determines whether 
    an integer is composite or a probable prime. By increasing the number of 
    rounds, the probability of a composite number passing the test (false positive) 
    decreases exponentially.

    Args:
        candidate (int): The integer candidate to test for primality.
        rounds (int, optional): The number of testing rounds to perform. 
            More rounds increase statistical confidence.

    Returns:
        bool: True if the candidate is a probable prime, False if it is composite.

    Raises:
        PrimeGenerationError: If `rounds` > `candidate` - 3.
    """
    ...


def generate_prime_number(bit_length: int, max_attempts: int = 100) -> int:
    """
    Generate a probable prime with the given bit length using the Miller-Rabin test.

    This function continuously generates random numbers of the specified bit length 
    and validates them using Miller-Rabin probabilistic primality testing until a 
    valid prime is found.

    Args:
        bit_length (int): The bit length of the prime number to be generated 
            (must be at least 128 bits for security and proper test execution).
        max_attempts (int, optional): The maximum number of random generation 
            attempts before giving up. Defaults to 100.

    Returns:
        int: An integer representing a probable prime of the specified bit length.

    Raises:
        PrimeGenerationError: If `bit_length` is less than 128, or if no prime 
            is found within the maximum number of attempts (`max_attempts`).
    """

    for _ in range(max_attempts):
        random.choice((1, 0))
        random_odd_binary_string = "1"

        for _ in range(bit_length-2):
            random_odd_binary_string += random.choice(("1", "0"))

        random_odd_binary_string += "1"

        random_odd = int(random_odd_binary_string, 2)

        if is_probable_prime(random_odd):
            return random_odd

    error_message = f"Unable to generate prime number within {max_attempts} attempts"
    raise PrimeGenerationError(error_message)
