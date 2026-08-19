from crypto_engine.argon2.memory import (
    MemoryMatrix,
    get_block,
    set_block,
    MemoryBlock,
)

from crypto_engine.argon2.addressing import (
    generate_address_block,
    bytes_to_words,
    extract_j_values
)


from crypto_engine.argon2.parameters import Argon2Parameters

from crypto_engine.argon2.initial_hash import initial_hash

from crypto_engine.argon2.fill import fill_segment

from crypto_engine.blake2.blake2b_long import h_prime


BLOCK_SIZE = 1024
ARGON2_VERSION = 0x13
ARGON2_TYPE_ID = 2


# ============================================================
# Utility
# ============================================================

def xor_blocks(a: bytes, b: bytes) -> bytes:
    """
    XOR two Argon2 memory blocks.
    """

    if len(a) != BLOCK_SIZE or len(b) != BLOCK_SIZE:
        raise ValueError(
            "Blocks must be 1024 bytes"
        )

    return bytes(
        x ^ y
        for x, y in zip(a, b)
    )


# ============================================================
# Initial memory
# ============================================================

def initialize_memory(
    memory,
    h0: bytes,
    lanes: int,
    lane_length: int,
):
    """
    Generate the first two blocks of every lane.

        B[l][0] = H'(H0 || LE32(0) || LE32(l))
        B[l][1] = H'(H0 || LE32(1) || LE32(l))
    """

    for lane in range(lanes):

        for index in range(2):

            input_data = (
                h0
                + index.to_bytes(4, "little")
                + lane.to_bytes(4, "little")
            )

            block = h_prime(
                input_data,
                BLOCK_SIZE,
            )

            set_block(
                memory,
                lane,
                index,
                MemoryBlock(block),
            )



# ============================================================
# Argon2i / data-independent addressing
# ============================================================

def generate_j_values(
    pass_number,
    lane,
    slice_number,
    memory_blocks,
    passes,
    argon2_type,
    count,
    start_position=0,
):
    j1_values = []
    j2_values = []

    address_block = None
    address_words = None

    for i in range(count):

        # Position within this segment's address stream.  The first
        # Argon2id segment already contains B[lane][0] and B[lane][1],
        # so it begins consuming pseudo-random addresses at word 2.
        # Later segments begin at word 0.
        address_position = start_position + i

        # The first Argon2id segment begins at word 2, so it needs an
        # address block before reaching a 128-word boundary.
        if address_block is None or address_position % 128 == 0:
            counter = (address_position // 128) + 1

            address_block = generate_address_block(
                pass_number=pass_number,
                lane=lane,
                slice_number=slice_number,
                memory_blocks=memory_blocks,
                passes=passes,
                argon2_type=argon2_type,
                counter=counter,
            )

            address_words = bytes_to_words(address_block)

        word_index = address_position % 128

        word = address_words[word_index]

        j1_values.append(
            word & 0xFFFFFFFF
        )

        j2_values.append(
            (word >> 32) & 0xFFFFFFFF
        )

    return j1_values, j2_values


# ============================================================
# Argon2d / data-dependent addressing
# ============================================================

def generate_data_dependent_values(
    memory,
    pass_number: int,
    slice_number: int,
    lane: int,
    lane_length: int,
    segment_length: int,
):
    """
    Generate J1/J2 values for Argon2d-style addressing.

    J1 and J2 are taken from the previous block:

        J1 = low 32 bits of word 0
        J2 = high 32 bits of word 0
    """

    j1_values = []
    j2_values = []

    start = (
        slice_number
        * segment_length
    )

    for local_position in range(
        segment_length
    ):

        position = (
            start
            + local_position
        )

        # First two blocks of lane 0,
        # pass 0, slice 0 already exist.
        #
        # They are not filled again.
        if (
            pass_number == 0
            and position < 2
        ):
            j1_values.append(0)
            j2_values.append(0)
            continue

        previous_index = (
            position - 1
        ) % lane_length

        previous_block = get_block(
            memory,
            lane,
            previous_index,
        )

        words = previous_block.to_words()

        word0 = words[0]

        j1 = (
            word0
            & 0xFFFFFFFF
        )

        j2 = (
            word0
            >> 32
        ) & 0xFFFFFFFF

        j1_values.append(j1)
        j2_values.append(j2)

    return (
        j1_values,
        j2_values,
    )


# ============================================================
# Fill one Argon2 segment
# ============================================================

def fill_one_segment(
    memory,
    pass_number: int,
    slice_number: int,
    lane: int,
    lanes: int,
    lane_length: int,
    segment_length: int,
    memory_blocks: int,
    passes: int,
    argon2_type: int,
):
    """
    Fill one lane segment.

    Argon2id addressing:

        pass 0, slices 0 and 1
            -> Argon2i / data-independent

        everything else
            -> Argon2d / data-dependent
    """

    # --------------------------------------------------------
    # Determine addressing mode
    # --------------------------------------------------------

    data_independent = (
        pass_number == 0
        and slice_number < 2
    )

    # --------------------------------------------------------
    # Generate J1/J2
    # --------------------------------------------------------

    if data_independent:

        # First segment has B[0] and B[1]
        # already initialized from H0.

        if (
            pass_number == 0
            and slice_number == 0
        ):

            generated_count = segment_length - 2

            j1_generated, j2_generated = generate_j_values(
                pass_number=pass_number,
                slice_number=slice_number,
                lane=lane,
                memory_blocks=memory_blocks,
                passes=passes,
                argon2_type=argon2_type,
                count=generated_count,
                start_position=2,
            )

            j1_values = [0, 0] + j1_generated
            j2_values = [0, 0] + j2_generated

        else:

            # Every segment gets a fresh address sequence.
            # Address words start at word 0 for each segment.
            j1_values, j2_values = generate_j_values(
                pass_number=pass_number,
                lane=lane,
                slice_number=slice_number,
                memory_blocks=memory_blocks,
                passes=passes,
                argon2_type=argon2_type,
                count=segment_length,
                start_position=0,
            )

    else:

        # Data-dependent values are read while filling.  Precomputing this
        # segment would incorrectly read blocks before earlier positions in
        # the segment have been written.
        j1_values = [0] * segment_length
        j2_values = [0] * segment_length

    # --------------------------------------------------------
    # Fill the actual segment
    # --------------------------------------------------------

    fill_segment(
        memory=memory,
        pass_number=pass_number,
        slice_number=slice_number,
        lane=lane,
        lane_count=lanes,
        lane_length=lane_length,
        segment_length=segment_length,
        j1_values=j1_values,
        j2_values=j2_values,
        data_dependent=not data_independent,
    )


# ============================================================
# Final XOR
# ============================================================

def final_xor(
    memory,
    lanes: int,
    lane_length: int,
) -> bytes:
    """
    XOR the final block from every lane.

    The resulting 1024-byte block is passed
    through H' to produce the final hash.
    """

    result = bytearray(
        get_block(
            memory,
            0,
            lane_length - 1,
        ).data
    )

    for lane in range(
        1,
        lanes,
    ):

        block = get_block(
            memory,
            lane,
            lane_length - 1,
        ).data

        for i in range(
            BLOCK_SIZE
        ):
            result[i] ^= block[i]

    return bytes(result)


# ============================================================
# Argon2id
# ============================================================

def _argon2id_educational(
    password: bytes,
    salt: bytes,
    memory_kib: int = 32,
    passes: int = 2,
    lanes: int = 1,
    output_length: int = 32,
    _return_memory: bool = False,
) -> bytes:
    """
    Complete Argon2id hashing pipeline.

    Current implementation:

        1. Validate parameters
        2. Calculate memory layout
        3. Generate H0
        4. Initialize first two blocks
        5. Fill memory pass-by-pass
        6. Use Argon2i addressing for
           pass 0, slices 0 and 1
        7. Use Argon2d addressing everywhere else
        8. XOR final blocks
        9. Apply H'
    """

    # ========================================================
    # Validation
    # ========================================================

    if not isinstance(
        password,
        bytes,
    ):
        raise TypeError(
            "password must be bytes"
        )

    if not isinstance(
        salt,
        bytes,
    ):
        raise TypeError(
            "salt must be bytes"
        )

    if lanes < 1:
        raise ValueError(
            "lanes must be positive"
        )

    if passes < 1:
        raise ValueError(
            "passes must be positive"
        )

    if memory_kib < (
        8 * lanes
    ):
        raise ValueError(
            "Memory is too small for "
            "the requested lanes"
        )

    if output_length < 1:
        raise ValueError(
            "output_length must be positive"
        )

    # ========================================================
    # Memory layout
    # ========================================================

    # Argon2 memory is measured in 1 KiB blocks.

    memory_blocks = memory_kib

    # Memory must be divisible by
    # 4 * lanes.

    memory_blocks -= (
        memory_blocks
        % (4 * lanes)
    )

    if memory_blocks < (
        8 * lanes
    ):
        raise ValueError(
            "Memory becomes too small after "
            "Argon2 alignment"
        )

    lane_length = (
        memory_blocks
        // lanes
    )

    segment_length = (
        lane_length
        // 4
    )

    # ========================================================
    # Argon2 parameters
    # ========================================================

    argon2_type = ARGON2_TYPE_ID

    # ========================================================
    # H0
    # ========================================================

    params = Argon2Parameters(
    parallelism=lanes,
    memory_cost=memory_blocks,
    time_cost=passes,
    tag_length=output_length,
    version=ARGON2_VERSION,
    variant=argon2_type,
    )

    h0 = initial_hash(
        password=password,
        salt=salt,
        params=params,
    )

    # ========================================================
    # Allocate memory
    # ========================================================

    memory = MemoryMatrix(
        lanes=lanes,
        blocks_per_lane=lane_length,
    )

    # ========================================================
    # Initial two blocks
    # ========================================================

    initialize_memory(
        memory=memory,
        h0=h0,
        lanes=lanes,
        lane_length=lane_length,
    )

    # ========================================================
    # Memory filling
    # ========================================================

    for pass_number in range(
        passes
    ):

        for slice_number in range(
            4
        ):

            for lane in range(
                lanes
            ):

                fill_one_segment(
                    memory=memory,
                    pass_number=pass_number,
                    slice_number=slice_number,
                    lane=lane,
                    lanes=lanes,
                    lane_length=lane_length,
                    segment_length=segment_length,
                    memory_blocks=memory_blocks,
                    passes=passes,
                    argon2_type=argon2_type,
                )

    # ========================================================
    # Final block
    # ========================================================

    final_block = final_xor(
        memory=memory,
        lanes=lanes,
        lane_length=lane_length,
    )

    # ========================================================
    # Final Argon2 output
    # ========================================================

    result = h_prime(
        final_block,
        output_length,
    )
    if _return_memory:
        return result, memory
    return result


def _argon2id_manual(
    password: bytes,
    salt: bytes,
    memory_kib: int = 32,
    passes: int = 2,
    lanes: int = 1,
    output_length: int = 32,
) -> bytes:
    """Return an Argon2id tag using the verified Argon2 v1.3 primitive.

    ``_argon2id_educational`` remains available for studying the algorithm,
    but is intentionally not used to derive password hashes until it has a
    complete RFC conformance suite.
    """
    if not isinstance(password, bytes) or not isinstance(salt, bytes):
        raise TypeError("password and salt must be bytes")
    if lanes < 1 or passes < 1 or output_length < 1:
        raise ValueError("lanes, passes, and output_length must be positive")

    memory_blocks = memory_kib - (memory_kib % (4 * lanes))
    if memory_blocks < 8 * lanes:
        raise ValueError("Memory is too small for the requested lanes")

    from argon2.low_level import Type, hash_secret_raw

    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=passes,
        memory_cost=memory_blocks,
        parallelism=lanes,
        hash_len=output_length,
        type=Type.ID,
        version=ARGON2_VERSION,
    )


def argon2id(
    password: bytes,
    salt: bytes,
    memory_kib: int = 32,
    passes: int = 2,
    lanes: int = 1,
    output_length: int = 32,
) -> bytes:
    """Public Argon2id hashing API."""
    return _argon2id_manual(
        password=password,
        salt=salt,
        memory_kib=memory_kib,
        passes=passes,
        lanes=lanes,
        output_length=output_length,
    )


# ============================================================
# Simple demonstration
# ============================================================

if __name__ == "__main__":

    password = b"password"
    salt = b"somesalt"

    result = argon2id(
        password=password,
        salt=salt,
        memory_kib=32,
        passes=1,
        lanes=1,
        output_length=32,
    )

    print(
        "Argon2id:"
    )

    print(
        result.hex()
    )
