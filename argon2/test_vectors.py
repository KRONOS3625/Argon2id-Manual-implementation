from argon2.low_level import (
    hash_secret_raw,
    Type,
)

from crypto_engine.argon2.engine import argon2id


def main():

    password = b"password"
    salt = b"somesalt"

    # --------------------------------------------------
    # Reference implementation
    # --------------------------------------------------

    reference = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=1,
        memory_cost=32,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )

    print("Reference Argon2id:")
    print(reference.hex())

    # --------------------------------------------------
    # OUR implementation
    # --------------------------------------------------

        # --------------------------------------------------
    # OUR IMPLEMENTATION
    # --------------------------------------------------

    ours = argon2id(
        password=password,
        salt=salt,
        memory_kib=32,
        passes=1,
        lanes=1,
        output_length=32,
    )

    print()
    print("Our Argon2id:")
    print(ours.hex())

    print()
    print("Length:", len(ours))

    assert len(ours) == 32

    if ours == reference:

        print()
        print("FULL ARGON2ID TEST: PASS")

    else:

        print()
        print("FULL ARGON2ID TEST: FAIL")

        print()
        print("Expected:")
        print(reference.hex())

        print()
        print("Got:")
        print(ours.hex())

        raise AssertionError(
            "Our Argon2id implementation does not "
            "match the reference implementation."
        )

    print()
    print("Our Argon2id:")
    print(ours.hex())

    # --------------------------------------------------
    # Compare
    # --------------------------------------------------

    print()
    print("Length:", len(ours))

    assert len(ours) == 32

    if ours == reference:

        print()
        print("FULL ARGON2ID TEST: PASS")

    else:

        print()
        print("FULL ARGON2ID TEST: FAIL")
        print()
        print("Expected:")
        print(reference.hex())
        print()
        print("Got:")
        print(ours.hex())

        raise AssertionError(
            "Our Argon2id implementation does not "
            "match the reference implementation."
        )


if __name__ == "__main__":
    main()