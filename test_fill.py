from crypto_engine.argon2.memory import (
    MemoryBlock,
    MemoryMatrix,
    get_block,
    set_block,
)

from crypto_engine.argon2.fill import (
    fill_segment,
)


def main():

    lanes = 1
    lane_length = 32
    segment_length = 8

    memory = MemoryMatrix(
        lanes=lanes,
        blocks_per_lane=lane_length,
    )

    # --------------------------------------------------
    # Create deterministic initial blocks.
    #
    # In the real Argon2 engine these will come from H_0.
    # For this structural test we deliberately use
    # recognizable values.
    # --------------------------------------------------

    block0 = MemoryBlock(
        bytes([0x11] * 1024)
    )

    block1 = MemoryBlock(
        bytes([0x22] * 1024)
    )

    set_block(
        memory,
        lane=0,
        index=0,
        block=block0,
    )

    set_block(
        memory,
        lane=0,
        index=1,
        block=block1,
    )

    # --------------------------------------------------
    # Deterministic J1/J2 values.
    #
    # One pair for every position in the segment.
    # --------------------------------------------------

    j1_values = [
        0x00000000
        for _ in range(segment_length)
    ]

    j2_values = [
        0x00000000
        for _ in range(segment_length)
    ]

    # --------------------------------------------------
    # Fill first segment.
    # --------------------------------------------------

    fill_segment(
        memory=memory,
        pass_number=0,
        slice_number=0,
        lane=0,
        lane_count=lanes,
        lane_length=lane_length,
        segment_length=segment_length,
        j1_values=j1_values,
        j2_values=j2_values,
    )

    # --------------------------------------------------
    # Verify first two blocks were untouched.
    # --------------------------------------------------

    assert (
        get_block(memory, 0, 0).data
        == bytes([0x11] * 1024)
    )

    assert (
        get_block(memory, 0, 1).data
        == bytes([0x22] * 1024)
    )

    print(
        "Initial blocks preserved: PASS"
    )

    # --------------------------------------------------
    # Verify positions 2..7 were generated.
    # --------------------------------------------------

    for index in range(2, 8):

        block = get_block(
            memory,
            0,
            index,
        )

        assert len(block.data) == 1024

        print(
            f"B[0][{index}] generated: PASS"
        )

    # --------------------------------------------------
    # Verify generated blocks aren't still zero.
    # --------------------------------------------------

    for index in range(2, 8):

        block = get_block(
            memory,
            0,
            index,
        )

        assert block.data != bytes(1024)

    print(
        "Generated blocks are non-zero: PASS"
    )

    print()
    print(
        "First segment fill test passed."
    )


if __name__ == "__main__":
    main()