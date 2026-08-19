from crypto_engine.argon2.addressing import (
    build_address_input,
    build_address_block_input,
    bytes_to_words,
    words_to_bytes,
    generate_address_block,
)


def test_z():

    z = build_address_input(
        pass_number=0,
        lane=0,
        slice_number=0,
        memory_blocks=32,
        passes=1,
        argon2_type=2,
    )

    assert len(z) == 48

    assert z[0:8] == (0).to_bytes(8, "little")
    assert z[8:16] == (0).to_bytes(8, "little")
    assert z[16:24] == (0).to_bytes(8, "little")
    assert z[24:32] == (32).to_bytes(8, "little")
    assert z[32:40] == (1).to_bytes(8, "little")
    assert z[40:48] == (2).to_bytes(8, "little")

    print("Z construction: PASS")


def test_address_block_input():

    z = build_address_input(
        0,
        0,
        0,
        32,
        1,
        2,
    )

    block = build_address_block_input(
        z,
        counter=1,
    )

    assert len(block) == 1024
    assert block[:48] == z
    assert block[48:56] == (
        1
    ).to_bytes(8, "little")

    assert block[56:] == bytes(968)

    print("Address input block size: PASS")
    print("Counter placement: PASS")
    print("Zero padding: PASS")


def test_word_conversion():

    original = bytes(
        ((i * 37) + 11) & 0xFF
        for i in range(1024)
    )

    words = bytes_to_words(original)

    assert len(words) == 128

    recovered = words_to_bytes(words)

    assert recovered == original

    print("Word conversion: PASS")


def test_real_address_generation():

    address = generate_address_block(
        pass_number=0,
        lane=0,
        slice_number=0,
        memory_blocks=32,
        passes=1,
        argon2_type=2,
        counter=1,
    )

    assert len(address) == 1024

    words = bytes_to_words(address)

    assert len(words) == 128

    print()
    print("Real address block length:", len(address))
    print("First 8 address words:")

    for i in range(8):
        print(
            f"address[{i}] = "
            f"{words[i]:016x}"
        )

    print("Real compression address generation: PASS")


def main():

    test_z()
    test_address_block_input()
    test_word_conversion()
    test_real_address_generation()

    print()
    print("All address-generation tests passed.")


if __name__ == "__main__":
    main()