class RSASystemError(Exception):
    pass


class PrimeGenerationError(RSASystemError):
    pass


class MaskGenerationError(RSASystemError):
    pass


class KeyGenerationError(RSASystemError):
    pass


class KeySerializationError(RSASystemError):
    pass


class OAEPPaddingError(RSASystemError):
    pass


class MessageTooLongError(RSASystemError):
    pass


class PSSVerificationError(RSASystemError):
    pass


class PackageParsingError(RSASystemError):
    pass
