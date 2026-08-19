MASK_64 = 0xFFFFFFFFFFFFFFFF
MASK_32 = 0xFFFFFFFF


def blamka(x: int, y: int) -> int:
    """
    Argon2 BlaMka addition.

    BlaMka(x, y) =
        x + y + 2 * (low32(x) * low32(y))

    All arithmetic is reduced modulo 2^64.
    """

    low_x = x & MASK_32
    low_y = y & MASK_32

    return (
        x
        + y
        + 2 * low_x * low_y
    ) & MASK_64

def rotr64(x: int, n: int) -> int:
    """
    Rotate a 64-bit integer right by n bits.
    """

    x &= MASK_64

    return (
        (x >> n)
        | (x << (64 - n))
    ) & MASK_64

def g(a: int, b: int, c: int, d: int):
    """
    Argon2's BlaMka-based G function.

    Returns the four mixed 64-bit words.
    """

    a = blamka(a, b)
    d = rotr64(d ^ a, 32)

    c = blamka(c, d)
    b = rotr64(b ^ c, 24)

    a = blamka(a, b)
    d = rotr64(d ^ a, 16)

    c = blamka(c, d)
    b = rotr64(b ^ c, 63)

    return a, b, c, d

def p(words: list[int]) -> list[int]:
    """
    Argon2's P transformation.

    Applies G to the columns of a 4x4 matrix,
    followed by G to its diagonals.
    """

    if len(words) != 16:
        raise ValueError(
            "P requires exactly 16 words"
        )

    v = words.copy()

    # --------------------------------------------------
    # Column rounds
    # --------------------------------------------------

    v[0], v[4], v[8], v[12] = g(
        v[0], v[4], v[8], v[12]
    )

    v[1], v[5], v[9], v[13] = g(
        v[1], v[5], v[9], v[13]
    )

    v[2], v[6], v[10], v[14] = g(
        v[2], v[6], v[10], v[14]
    )

    v[3], v[7], v[11], v[15] = g(
        v[3], v[7], v[11], v[15]
    )

    # --------------------------------------------------
    # Diagonal rounds
    # --------------------------------------------------

    v[0], v[5], v[10], v[15] = g(
        v[0], v[5], v[10], v[15]
    )

    v[1], v[6], v[11], v[12] = g(
        v[1], v[6], v[11], v[12]
    )

    v[2], v[7], v[8], v[13] = g(
        v[2], v[7], v[8], v[13]
    )

    v[3], v[4], v[9], v[14] = g(
        v[3], v[4], v[9], v[14]
    )

    return v

def compress_block(x: bytes, y: bytes) -> bytes:
    """
    Argon2 compression function G.

    X and Y are 1024-byte blocks.

    R = X XOR Y
    Q = P applied row-wise to R
    Z = P applied column-wise to Q
    Output = Z XOR R
    """

    if len(x) != 1024:
        raise ValueError("X must be exactly 1024 bytes")

    if len(y) != 1024:
        raise ValueError("Y must be exactly 1024 bytes")

    # --------------------------------------------------
    # Convert blocks to 128 little-endian 64-bit words
    # --------------------------------------------------

    x_words = [
        int.from_bytes(
            x[i:i + 8],
            byteorder="little"
        )
        for i in range(0, 1024, 8)
    ]

    y_words = [
        int.from_bytes(
            y[i:i + 8],
            byteorder="little"
        )
        for i in range(0, 1024, 8)
    ]

    # --------------------------------------------------
    # R = X XOR Y
    # --------------------------------------------------

    r = [
        x_words[i] ^ y_words[i]
        for i in range(128)
    ]

    # Q starts as a copy of R
    q = r.copy()

    # --------------------------------------------------
    # ROW PHASE
    #
    # Each row contains:
    #
    # 8 registers × 2 words = 16 words
    #
    # Therefore:
    #
    # row 0 = words 0..15
    # row 1 = words 16..31
    # ...
    # row 7 = words 112..127
    # --------------------------------------------------

    for row in range(8):

        start = row * 16

        row_words = q[start:start + 16]

        row_result = p(row_words)

        q[start:start + 16] = row_result

    # --------------------------------------------------
    # COLUMN PHASE
    #
    # Each column contains 8 registers.
    # Each register contains 2 words.
    #
    # Column 0:
    #
    # words:
    #   0,1
    #   16,17
    #   32,33
    #   ...
    #   112,113
    # --------------------------------------------------

    z = q.copy()

    for column in range(8):

        column_words = []

        for row in range(8):

            register_start = (
                row * 16
                + column * 2
            )

            column_words.extend(
                q[
                    register_start:
                    register_start + 2
                ]
            )

        column_result = p(column_words)

        index = 0

        for row in range(8):

            register_start = (
                row * 16
                + column * 2
            )

            z[
                register_start:
                register_start + 2
            ] = column_result[index:index + 2]

            index += 2

    # --------------------------------------------------
    # Final:
    #
    # output = Z XOR R
    # --------------------------------------------------

    output_words = [
        z[i] ^ r[i]
        for i in range(128)
    ]

    # --------------------------------------------------
    # Convert words back to 1024 bytes
    # --------------------------------------------------

    output = bytearray()

    for word in output_words:

        output.extend(
            word.to_bytes(
                8,
                byteorder="little"
            )
        )

    return bytes(output)