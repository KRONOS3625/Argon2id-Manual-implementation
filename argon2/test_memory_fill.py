from crypto_engine.argon2.memory import (
    MemoryBlock,
    MemoryMatrix,
    get_block,
    set_block,
)


def main():

    lanes = 2
    blocks_per_lane = 32

    memory = MemoryMatrix(
        lanes=lanes,
        blocks_per_lane=blocks_per_lane,
    )

    # Create a deterministic test block.
    test_block = MemoryBlock(
        bytes([0xAA] * 1024)
    )

    set_block(
        memory,
        lane=0,
        index=5,
        block=test_block,
    )

    recovered = get_block(
        memory,
        lane=0,
        index=5,
    )

    assert recovered is test_block

    print(
        "Memory block write/read: PASS"
    )

    assert len(recovered.data) == 1024

    print(
        "Memory block size: PASS"
    )

    assert memory.total_blocks() == (
        lanes * blocks_per_lane
    )

    print(
        "Memory matrix size: PASS"
    )

    print()
    print(
        "Memory interface tests passed."
    )


if __name__ == "__main__":
    main()