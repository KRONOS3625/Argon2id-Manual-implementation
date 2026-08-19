import hashlib
import os

from blake2b import blake2b


def test_case(data: bytes, digest_size: int = 64):
    ours = blake2b(data, digest_size)
    reference = hashlib.blake2b(
        data,
        digest_size=digest_size
    ).digest()

    assert ours == reference, (
        f"Mismatch for input length {len(data)}"
    )


def main():
    test_inputs = [
        b"",
        b"a",
        b"hello",
        b"password",
        b"The quick brown fox jumps over the lazy dog",
        bytes(range(128)),
        bytes(range(129)),
        bytes(range(255)),
        os.urandom(1024),
        os.urandom(4096),
    ]

    digest_sizes = [1, 16, 20, 32, 48, 64]

    total = 0

    for data in test_inputs:
        for digest_size in digest_sizes:
            test_case(data, digest_size)
            total += 1

    print(f"All {total} BLAKE2b tests passed.")


if __name__ == "__main__":
    main()