from crypto_engine.blake2.blake2b import blake2b
from crypto_engine.argon2.parameters import Argon2Parameters


def le32(value: int) -> bytes:
    """
    Encode an integer as a 32-bit little-endian value.
    """

    return value.to_bytes(
        4,
        byteorder="little"
    )


def encode_bytes(data: bytes) -> bytes:
    """
    Argon2's length-prefixed byte-string encoding.

    Encodes:

        LE32(length) || data
    """

    return le32(len(data)) + data


def initial_hash(
    password: bytes,
    salt: bytes,
    params: Argon2Parameters
) -> bytes:
    """
    Compute Argon2's initial hash H_0.

    H_0 = BLAKE2b-512(
        LE32(p) ||
        LE32(T) ||
        LE32(m) ||
        LE32(t) ||
        LE32(v) ||
        LE32(y) ||
        P || S || K || X
    )
    """

    params.validate()

    if not isinstance(password, bytes):
        raise TypeError("password must be bytes")

    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")

    input_data = bytearray()

    # --------------------------------------------------
    # Argon2 parameters
    # --------------------------------------------------

    input_data += le32(params.parallelism)
    input_data += le32(params.tag_length)
    input_data += le32(params.memory_cost)
    input_data += le32(params.time_cost)
    input_data += le32(params.version)
    input_data += le32(params.variant)

    # --------------------------------------------------
    # Password P
    # --------------------------------------------------

    input_data += encode_bytes(password)

    # --------------------------------------------------
    # Salt S
    # --------------------------------------------------

    input_data += encode_bytes(salt)

    # --------------------------------------------------
    # Empty secret K
    # --------------------------------------------------

    input_data += le32(0)

    # --------------------------------------------------
    # Empty associated data X
    # --------------------------------------------------

    input_data += le32(0)

    # --------------------------------------------------
    # H_0
    #
    # IMPORTANT:
    # H_0 uses ordinary BLAKE2b-512.
    # It does NOT use H'.
    # --------------------------------------------------

    return blake2b(
        bytes(input_data),
        64
    )