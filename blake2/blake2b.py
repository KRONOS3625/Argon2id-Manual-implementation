import hashlib

from crypto_engine.blake2.constants import (
    IV,
    MASK_64,
    SIGMA,
    ROUNDS
)

MASK_64 = 0xFFFFFFFFFFFFFFFF


def rotr64(x: int, n: int) -> int:
    """
    Rotate a 64-bit integer x to the right by n bits.
    """
    x &= MASK_64

    return (
        (x >> n) |
        (x << (64 - n))
    ) & MASK_64

MASK_64 = 0xFFFFFFFFFFFFFFFF


from crypto_engine.blake2.constants import (
    IV,
    MASK_64,
    SIGMA,
    ROUNDS
)


def initialize_state(digest_size: int = 64) -> list[int]:
    """
    Initialize the eight-word BLAKE2b state.

    digest_size:
        Desired digest size in bytes.
        Valid range: 1-64.
    """

    if not 1 <= digest_size <= 64:
        raise ValueError("digest_size must be between 1 and 64 bytes")

    # Copy the initialization vector.
    state = IV.copy()

    # BLAKE2b parameter block.
    key_length = 0

    parameter = (
        0x01010000
        ^ (key_length << 8)
        ^ digest_size
    )

    # XOR parameter block into first state word.
    state[0] ^= parameter

    state[0] &= MASK_64

    return state

def G(v: list[int], a: int, b: int, c: int, d: int,
      x: int, y: int) -> None:
    """
    BLAKE2b G mixing function.

    v:
        16-word working vector.

    a, b, c, d:
        Indices of the four working words.

    x, y:
        Two message words.
    """

    # First half
    v[a] = (v[a] + v[b] + x) & MASK_64
    v[d] = rotr64(v[d] ^ v[a], 32)

    v[c] = (v[c] + v[d]) & MASK_64
    v[b] = rotr64(v[b] ^ v[c], 24)

    # Second half
    v[a] = (v[a] + v[b] + y) & MASK_64
    v[d] = rotr64(v[d] ^ v[a], 16)

    v[c] = (v[c] + v[d]) & MASK_64
    v[b] = rotr64(v[b] ^ v[c], 63)

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

def bytes_to_words(block: bytes) -> list[int]:
    """
    Convert a 128-byte BLAKE2b block into
    sixteen little-endian 64-bit words.
    """

    if len(block) != 128:
        raise ValueError("BLAKE2b blocks must be exactly 128 bytes")

    words = []

    for i in range(16):
        start = i * 8
        word = int.from_bytes(
            block[start:start + 8],
            byteorder="little"
        )

        words.append(word)

    return words

def blake2b(data: bytes, digest_size: int = 64) -> bytes:
    """
    Compute BLAKE2b hash.

    data:
        Input message as bytes.

    digest_size:
        Desired digest length in bytes.
        Valid range: 1-64.
    """

    if not 1 <= digest_size <= 64:
        raise ValueError("digest_size must be between 1 and 64 bytes")

    h = initialize_state(digest_size)

    data_length = len(data)

    # --------------------------------------------------
    # Process all blocks except the final block
    # --------------------------------------------------

    offset = 0

    while data_length - offset > 128:

        block = data[offset:offset + 128]

        words = bytes_to_words(block)

        offset += 128

        h = compress(
            h=h,
            block=words,
            counter=offset,
            is_final=False
        )

    # --------------------------------------------------
    # Final block
    # --------------------------------------------------

    remaining = data[offset:]

    padded_block = remaining + bytes(128 - len(remaining))

    words = bytes_to_words(padded_block)

    h = compress(
        h=h,
        block=words,
        counter=data_length,
        is_final=True
    )

    # --------------------------------------------------
    # Serialize final state
    # --------------------------------------------------

    digest = b""

    for word in h:
        digest += word.to_bytes(
            8,
            byteorder="little"
        )

    return digest[:digest_size]

if __name__ == "__main__":

    test_message = b"hello"

    our_result = blake2b(test_message)

    reference_result = hashlib.blake2b(
        test_message
    ).digest()

    print("Our BLAKE2b:")
    print(our_result.hex())

    print("\nReference BLAKE2b:")
    print(reference_result.hex())

    print("\nMatch:")
    print(our_result == reference_result)