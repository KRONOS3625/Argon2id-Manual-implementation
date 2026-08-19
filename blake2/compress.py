def compress(
    h: list[int],
    block: list[int],
    counter: int,
    is_final: bool
) -> list[int]:
    """
    BLAKE2b compression function.

    h:
        Current 8-word hash state.

    block:
        16-word message block.

    counter:
        Number of bytes processed so far.

    is_final:
        True when this is the final message block.
    """

    if len(h) != 8:
        raise ValueError("Hash state must contain 8 words")

    if len(block) != 16:
        raise ValueError("Message block must contain 16 words")

    # --------------------------------------------------
    # Step 1: Initialize working vector
    # --------------------------------------------------

    v = h.copy() + IV.copy()

    # --------------------------------------------------
    # Step 2: XOR byte counter into v[12] and v[13]
    # --------------------------------------------------

    t0 = counter & MASK_64
    t1 = (counter >> 64) & MASK_64

    v[12] ^= t0
    v[13] ^= t1

    # --------------------------------------------------
    # Step 3: Mark final block
    # --------------------------------------------------

    if is_final:
        v[14] ^= MASK_64

    # --------------------------------------------------
    # Step 4: Perform 12 rounds
    # --------------------------------------------------

    for round_number in range(ROUNDS):

        s = SIGMA[round_number]

        # Column step

        G(v, 0, 4, 8, 12, block[s[0]], block[s[1]])
        G(v, 1, 5, 9, 13, block[s[2]], block[s[3]])
        G(v, 2, 6, 10, 14, block[s[4]], block[s[5]])
        G(v, 3, 7, 11, 15, block[s[6]], block[s[7]])

        # Diagonal step

        G(v, 0, 5, 10, 15, block[s[8]], block[s[9]])
        G(v, 1, 6, 11, 12, block[s[10]], block[s[11]])
        G(v, 2, 7, 8, 13, block[s[12]], block[s[13]])
        G(v, 3, 4, 9, 14, block[s[14]], block[s[15]])

    # --------------------------------------------------
    # Step 5: Final state transformation
    # --------------------------------------------------

    new_h = []

    for i in range(8):
        value = h[i] ^ v[i] ^ v[i + 8]
        new_h.append(value & MASK_64)

    return new_h