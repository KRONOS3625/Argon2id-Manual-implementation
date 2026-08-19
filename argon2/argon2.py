from crypto_engine.blake2.blake2b_long import h_prime
from crypto_engine.argon2.parameters import Argon2Parameters


def le32(value: int) -> bytes:
    return value.to_bytes(4, byteorder="little")


def encode_bytes(data: bytes) -> bytes:
    return le32(len(data)) + data


def initial_hash(
    password: bytes,
    salt: bytes,
    params: Argon2Parameters
) -> bytes:

    params.validate()

    if not isinstance(password, bytes):
        raise TypeError("password must be bytes")

    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")

    input_data = bytearray()

    input_data += le32(params.parallelism)
    input_data += le32(params.tag_length)
    input_data += le32(params.memory_cost)
    input_data += le32(params.time_cost)
    input_data += le32(params.version)
    input_data += le32(params.variant)

    input_data += encode_bytes(password)
    input_data += encode_bytes(salt)

    # Empty secret
    input_data += le32(0)

    # Empty associated data
    input_data += le32(0)

    return h_prime(bytes(input_data), 64)