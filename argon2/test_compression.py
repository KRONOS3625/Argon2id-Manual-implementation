from crypto_engine.argon2.compression import (
    blamka,
    rotr64,
    g,
    p,
    compress_block
)


MASK_64 = 0xFFFFFFFFFFFFFFFF


def reference_blamka(x: int, y: int) -> int:
    low_x = x & 0xFFFFFFFF
    low_y = y & 0xFFFFFFFF

    return (
        x
        + y
        + 2 * low_x * low_y
    ) & MASK_64


def main():

    test_rotr64()

    test_cases = [
        (0, 0),
        (1, 1),
        (0xFFFFFFFF, 0xFFFFFFFF),
        (0xFFFFFFFFFFFFFFFF, 1),
        (0x123456789ABCDEF0, 0xFEDCBA9876543210),
    ]

    for x, y in test_cases:

        result = blamka(x, y)
        expected = reference_blamka(x, y)

        print(
            f"x={x:016x} "
            f"y={y:016x} "
            f"result={result:016x}"
        )

        assert result == expected

    print()
    print("All BlaMka tests passed.")
    test_g()
    test_p()
    test_compress_block()
    test_compression_avalanche()


def test_compress_block():

    # --------------------------------------------------
    # Create two deterministic 1024-byte blocks
    # --------------------------------------------------

    x = bytes(
        ((i * 37) + 11) & 0xFF
        for i in range(1024)
    )

    y = bytes(
        ((i * 91) + 73) & 0xFF
        for i in range(1024)
    )   

    result = compress_block(x, y)

    print()
    print("Compression output length:")
    print(len(result))

    print()
    print("First 32 bytes:")
    print(result[:32].hex())

    print()
    print("Last 32 bytes:")
    print(result[-32:].hex())

    assert len(result) == 1024
    assert result != x
    assert result != y
    assert result != bytes(1024)

    print()
    print("Block compression structural test passed.")

def test_compression_avalanche():

    x = bytes(
        ((i * 37) + 11) & 0xFF
        for i in range(1024)
    )

    y = bytes(
        ((i * 91) + 73) & 0xFF
        for i in range(1024)
    )

    original = compress_block(x, y)

    # Flip exactly one bit
    modified_x = bytearray(x)
    modified_x[0] ^= 0x01
    modified_x = bytes(modified_x)

    modified = compress_block(
        modified_x,
        y
    )

    different_bits = sum(
        bin(a ^ b).count("1")
        for a, b in zip(original, modified)
    )

    print()
    print("Compression avalanche test")
    print("Different bits:", different_bits)
    print("Total bits:", 1024 * 8)

    # We expect substantial diffusion.
    assert different_bits > 3000

    print("Avalanche test passed.")

def test_rotr64():

    assert rotr64(0x0000000000000001, 1) == \
        0x8000000000000000

    assert rotr64(0x8000000000000000, 1) == \
        0x4000000000000000

    assert rotr64(0xFFFFFFFFFFFFFFFF, 32) == \
        0xFFFFFFFFFFFFFFFF

    print("64-bit rotation tests passed.")

def test_g():

    a = 0x0123456789ABCDEF
    b = 0x1111111111111111
    c = 0x2222222222222222
    d = 0x3333333333333333

    result = g(a, b, c, d)

    assert len(result) == 4

    for value in result:
        assert 0 <= value <= MASK_64

    print()
    print("G output:")

    for i, value in enumerate(result):
        print(f"g[{i}] = {value:016x}")

    print("G structural test passed.") 

def test_p():

    input_words = [
        0x0000000000000000,
        0x1111111111111111,
        0x2222222222222222,
        0x3333333333333333,
        0x4444444444444444,
        0x5555555555555555,
        0x6666666666666666,
        0x7777777777777777,
        0x8888888888888888,
        0x9999999999999999,
        0xaaaaaaaaaaaaaaaa,
        0xbbbbbbbbbbbbbbbb,
        0xcccccccccccccccc,
        0xdddddddddddddddd,
        0xeeeeeeeeeeeeeeee,
        0xffffffffffffffff,
    ]

    result = p(input_words)

    assert len(result) == 16

    for value in result:
        assert 0 <= value <= MASK_64

    assert result != input_words

    print()
    print("P output:")

    for i, value in enumerate(result):
        print(f"p[{i}] = {value:016x}")

    print("P structural test passed.") 

if __name__ == "__main__":
    main()