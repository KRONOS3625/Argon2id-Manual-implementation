from crypto_engine.argon2.parameters import Argon2Parameters
from crypto_engine.argon2.initial_hash import initial_hash
from crypto_engine.argon2.memory import (
    generate_initial_block,
    block_to_words,
    words_to_block
)


def main():

    params = Argon2Parameters(
        parallelism=1,
        memory_cost=32,
        time_cost=1,
        tag_length=32
    )

    password = b"password"
    salt = b"somesalt"

    # --------------------------------------------------
    # Step 1: Generate H_0
    # --------------------------------------------------

    h0 = initial_hash(
        password,
        salt,
        params
    )

    print("Argon2 H_0:")
    print(h0.hex())
    print("Length:", len(h0))

    # --------------------------------------------------
    # Step 2: Generate B[0][0]
    # --------------------------------------------------

    b0 = generate_initial_block(
        h0,
        block_index=0,
        lane=0
    )

    print()
    print("B[0][0]")
    print("Length:", len(b0))
    print("First 32 bytes:")
    print(b0[:32].hex())

    # --------------------------------------------------
    # Step 3: Generate B[0][1]
    # --------------------------------------------------

    b1 = generate_initial_block(
        h0,
        block_index=1,
        lane=0
    )

    print()
    print("B[0][1]")
    print("Length:", len(b1))
    print("First 32 bytes:")
    print(b1[:32].hex())

    # --------------------------------------------------
    # Step 4: Convert B[0][0] to 64-bit words
    # --------------------------------------------------

    words = block_to_words(b0)

    print()
    print("B[0][0] word count:")
    print(len(words))

    print()
    print("First 4 words:")

    for i in range(4):
        print(
            f"word[{i}] = {words[i]:016x}"
        )

    # --------------------------------------------------
    # Step 5: Convert back to bytes
    # --------------------------------------------------

    reconstructed = words_to_block(words)

    print()
    print("Block reconstruction:", end=" ")

    if reconstructed == b0:
        print("PASS")
    else:
        print("FAIL")

    # --------------------------------------------------
    # Basic assertions
    # --------------------------------------------------

    assert len(h0) == 64
    assert len(b0) == 1024
    assert len(b1) == 1024
    assert len(words) == 128
    assert reconstructed == b0
    assert b0 != b1

    print()
    print("All initial-block tests passed.")


if __name__ == "__main__":
    main()