from crypto_engine.argon2.memory import (
    MemoryBlock,
    MemoryMatrix,
    BLOCK_SIZE,
    WORDS_PER_BLOCK
)


def test_memory_block():

    block = MemoryBlock()

    assert len(block) == 1024
    assert len(block.to_words()) == 128

    print("MemoryBlock size: PASS")
    print("MemoryBlock word count: PASS")


def test_word_conversion():

    words = [
        i
        for i in range(WORDS_PER_BLOCK)
    ]

    block = MemoryBlock.from_words(words)

    recovered = block.to_words()

    assert recovered == words

    print("Word conversion: PASS")


def test_memory_matrix():

    matrix = MemoryMatrix(
        lanes=1,
        blocks_per_lane=32
    )

    assert matrix.lanes == 1
    assert matrix.blocks_per_lane == 32
    assert matrix.total_blocks() == 32

    for i in range(32):

        block = matrix.get(0, i)

        assert isinstance(
            block,
            MemoryBlock
        )

        assert len(block) == BLOCK_SIZE

    print("Memory matrix size: PASS")
    print("Total blocks:", matrix.total_blocks())


def main():

    test_memory_block()
    test_word_conversion()
    test_memory_matrix()

    print()
    print("All memory tests passed.")


if __name__ == "__main__":
    main()