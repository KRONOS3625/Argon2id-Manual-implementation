BLOCK_SIZE = 1024
WORD_SIZE = 8
WORDS_PER_BLOCK = 128


class MemoryBlock:
    """
    Represents one 1024-byte Argon2 memory block.
    """

    def __init__(self, data: bytes | None = None):

        if data is None:
            data = bytes(BLOCK_SIZE)

        if len(data) != BLOCK_SIZE:
            raise ValueError(
                "Argon2 memory block must be exactly 1024 bytes"
            )

        self.data = bytes(data)

    def to_words(self) -> list[int]:

        return [
            int.from_bytes(
                self.data[i:i + WORD_SIZE],
                byteorder="little"
            )
            for i in range(
                0,
                BLOCK_SIZE,
                WORD_SIZE
            )
        ]

    @classmethod
    def from_words(cls, words: list[int]):

        if len(words) != WORDS_PER_BLOCK:
            raise ValueError(
                "Argon2 block must contain exactly 128 words"
            )

        data = bytearray()

        for word in words:

            if not 0 <= word <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(
                    "Word is not a valid uint64"
                )

            data.extend(
                word.to_bytes(
                    WORD_SIZE,
                    byteorder="little"
                )
            )

        return cls(bytes(data))

    def __len__(self):
        return len(self.data)

    def __bytes__(self):
        return self.data


class MemoryMatrix:
    """
    Argon2 memory organized as lanes × blocks.
    """

    def __init__(
        self,
        lanes: int,
        blocks_per_lane: int
    ):

        if lanes < 1:
            raise ValueError(
                "There must be at least one lane"
            )

        if blocks_per_lane < 2:
            raise ValueError(
                "Each lane must contain at least two blocks"
            )

        self.lanes = lanes
        self.blocks_per_lane = blocks_per_lane

        self.blocks = [
            [
                MemoryBlock()
                for _ in range(blocks_per_lane)
            ]
            for _ in range(lanes)
        ]

    def get(
        self,
        lane: int,
        index: int
    ) -> MemoryBlock:

        return self.blocks[lane][index]

    def set(
        self,
        lane: int,
        index: int,
        block: MemoryBlock
    ):

        if not isinstance(block, MemoryBlock):
            raise TypeError(
                "block must be a MemoryBlock"
            )

        self.blocks[lane][index] = block

    def total_blocks(self) -> int:
        return (
            self.lanes
            * self.blocks_per_lane
        )

def get_block(
    memory,
    lane: int,
    index: int,
) -> MemoryBlock:
    """
    Retrieve a block from the Argon2 memory matrix.
    """

    if lane < 0 or lane >= memory.lanes:
        raise IndexError(
            "lane outside memory matrix"
        )

    if index < 0 or index >= memory.blocks_per_lane:
        raise IndexError(
            "index outside lane"
        )

    return memory.get(lane, index)


def set_block(
    memory,
    lane: int,
    index: int,
    block: MemoryBlock,
):
    """
    Store a MemoryBlock in the Argon2 memory matrix.
    """

    if not isinstance(block, MemoryBlock):
        raise TypeError(
            "block must be a MemoryBlock"
        )

    if lane < 0 or lane >= memory.lanes:
        raise IndexError(
            "lane outside memory matrix"
        )

    if index < 0 or index >= memory.blocks_per_lane:
        raise IndexError(
            "index outside lane"
        )

    memory.set(
        lane,
        index,
        block
    )