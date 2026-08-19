from crypto_engine.argon2.memory import (
    MemoryBlock,
    get_block,
    set_block,
)

from crypto_engine.argon2.compression import (
    compress_block,
)

from crypto_engine.argon2.addressing import (
    select_reference_block,
)


def fill_segment(
    memory,
    pass_number: int,
    slice_number: int,
    lane: int,
    lane_count: int,
    lane_length: int,
    segment_length: int,
    j1_values: list[int],
    j2_values: list[int],
    data_dependent: bool = False,
):
    """
    Fill one Argon2 memory segment.

    Implements RFC 9106 Section 3.2 and Section 3.4.

    For pass 0:
        B[i][j] = G(B[i][j-1], B[l][z])

    For passes > 0:
        B[i][j] =
            G(B[i][j-1], B[l][z]) XOR B[i][j]

    Positions 0 and 1 of slice 0, pass 0 are already
    initialized from H0 and must not be overwritten.
    """

    if len(j1_values) != segment_length:
        raise ValueError(
            "j1_values must contain segment_length values"
        )

    if len(j2_values) != segment_length:
        raise ValueError(
            "j2_values must contain segment_length values"
        )

    # Absolute beginning of this segment.
    segment_start = slice_number * segment_length

    for local_position in range(segment_length):

        position = segment_start + local_position

        # --------------------------------------------------
        # Skip the two blocks initialized from H0.
        # --------------------------------------------------

        if (
            pass_number == 0
            and slice_number == 0
            and local_position < 2
        ):
            continue

        # --------------------------------------------------
        # Previous block
        #
        # Normally position - 1.
        # For position 0 in later passes, the previous
        # block is the last block of this lane.
        # --------------------------------------------------

        previous_index = (
            position - 1
        ) % lane_length

        previous_block = get_block(
            memory,
            lane,
            previous_index,
        )

        # --------------------------------------------------
        # J1 / J2.  Data-dependent addressing must be read here rather
        # than precomputed for the whole segment: each newly written block
        # becomes the previous block for the next position.
        # --------------------------------------------------

        if data_dependent:
            previous_word = previous_block.to_words()[0]
            j1 = previous_word & 0xFFFFFFFF
            j2 = (previous_word >> 32) & 0xFFFFFFFF
        else:
            j1 = j1_values[local_position]
            j2 = j2_values[local_position]

        # --------------------------------------------------
        # Select reference block.
        # --------------------------------------------------

        reference_lane, reference_index = select_reference_block(
            j1=j1,
            j2=j2,
            pass_number=pass_number,
            slice_number=slice_number,
            position=position,
            current_lane=lane,
            lane_count=lane_count,
            lane_length=lane_length,
            segment_length=segment_length,
        )

        reference_block = get_block(
            memory,
            reference_lane,
            reference_index,
        )

        # --------------------------------------------------
        # Argon2 compression
        #
        # compress_block() ALREADY performs:
        #
        #     R = X XOR Y
        #     Z = P(P(R))
        #     G = Z XOR R
        #
        # Therefore:
        #
        #     G(previous, reference)
        #
        # is exactly:
        #
        #     compress_block(previous, reference)
        # --------------------------------------------------

        compressed = compress_block(
            previous_block.data,
            reference_block.data,
        )

        # --------------------------------------------------
        # Pass > 0:
        #
        # XOR the newly generated block with the old
        # contents of B[lane][position].
        #
        # RFC 9106:
        #
        # B[i][j] =
        #     G(B[i][j-1], B[l][z]) XOR B[i][j]
        # --------------------------------------------------

        if pass_number > 0:

            existing_block = get_block(
                memory,
                lane,
                position,
            )

            compressed = bytes(
                a ^ b
                for a, b in zip(
                    compressed,
                    existing_block.data,
                )
            )

        # --------------------------------------------------
        # Store the resulting block.
        # --------------------------------------------------

        set_block(
            memory,
            lane,
            position,
            MemoryBlock(compressed),
        )
