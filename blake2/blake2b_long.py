from crypto_engine.blake2.blake2b import blake2b


def h_prime(data: bytes, output_length: int) -> bytes:

    if output_length <= 0:
        raise ValueError(
            "output_length must be positive"
        )

    length_prefix = output_length.to_bytes(
        4,
        byteorder="little"
    )

    input_data = length_prefix + data

    # T <= 64
    if output_length <= 64:
        return blake2b(
            input_data,
            digest_size=output_length
        )

    # T > 64
    r = (output_length + 31) // 32 - 2

    previous = blake2b(
        input_data,
        digest_size=64
    )

    output = bytearray()

    for _ in range(r):

        output.extend(previous[:32])

        previous = blake2b(
            previous,
            digest_size=64
        )

    remaining_length = output_length - (32 * r)

    final_block = blake2b(
        previous,
        digest_size=remaining_length
    )

    output.extend(final_block)

    return bytes(output)