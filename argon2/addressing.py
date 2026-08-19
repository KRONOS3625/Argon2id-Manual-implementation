import struct

from crypto_engine.argon2.compression import compress_block

MASK_32 = 0xFFFFFFFF


def map_j1_to_index(
    j1: int,
    reference_area_size: int
) -> int:
    """
    Argon2 reference-position mapping.

    Implements the quadratic mapping from RFC 9106.

    J1 is treated as an unsigned 32-bit value.
    """

    if not 0 <= j1 <= MASK_32:
        raise ValueError(
            "J1 must be a 32-bit unsigned integer"
        )

    if reference_area_size <= 0:
        raise ValueError(
            "reference_area_size must be positive"
        )

    # J1^2
    x = j1 * j1

    # floor(J1^2 / 2^32)
    x = x >> 32

    # floor(reference_area_size * x / 2^32)
    relative_position = (
        reference_area_size * x
    ) >> 32

    # RFC mapping
    relative_position = (
        reference_area_size
        - 1
        - relative_position
    )

    return relative_position

def reference_area_size(
    pass_number: int,
    slice_number: int,
    local_position: int,
    segment_length: int,
    same_lane: bool,
) -> int:
    """
    Calculate Argon2 reference-area size.

    local_position is the block's position inside the
    current segment, NOT its global position in the lane.
    """

    if pass_number < 0:
        raise ValueError("pass_number must be >= 0")

    if not 0 <= slice_number < 4:
        raise ValueError(
            "slice_number must be between 0 and 3"
        )

    if not 0 <= local_position < segment_length:
        raise ValueError(
            "local_position outside segment"
        )

    if segment_length <= 0:
        raise ValueError(
            "segment_length must be positive"
        )

    # --------------------------------------------------
    # PASS 0
    # --------------------------------------------------

    if pass_number == 0:

        # First slice:
        #
        # Only previously generated blocks can be referenced.
        #
        # local_position = 2 -> area = 1
        # local_position = 3 -> area = 2
        #
        if slice_number == 0:
            return local_position - 1

        # Later slices
        #
        # Same lane:
        #   Previous completed slices +
        #   blocks already generated in this segment.
        #
        if same_lane:
            return (
                slice_number * segment_length
                + local_position
                - 1
            )

        # Different lane:
        #   Only completed previous slices.
        #
        # If this is the first block of the segment,
        # exclude the most recent block as required by
        # the Argon2 indexing rules.
        return (
            slice_number * segment_length
            - (1 if local_position == 0 else 0)
        )

    # --------------------------------------------------
    # PASS > 0
    # --------------------------------------------------

    # Same lane:
    #
    # Previous three completed segments +
    # blocks already computed in current segment.
    if same_lane:
        return (
            3 * segment_length
            + local_position
            - 1
        )

    # Different lane:
    #
    # Only the previous three completed segments.
    return (
        3 * segment_length
        - (1 if local_position == 0 else 0)
    )

import struct


BLOCK_WORDS = 128
BLOCK_SIZE = 1024
MASK_64 = 0xFFFFFFFFFFFFFFFF


def _le64(value: int) -> bytes:
    return struct.pack("<Q", value & MASK_64)


def _le32(value: int) -> bytes:
    return struct.pack("<I", value & MASK_32)


def build_address_input(
    pass_number: int,
    lane: int,
    slice_number: int,
    memory_blocks: int,
    passes: int,
    argon2_type: int,
) -> bytes:

    return b"".join([
        _le64(pass_number),
        _le64(lane),
        _le64(slice_number),
        _le64(memory_blocks),
        _le64(passes),
        _le64(argon2_type),
    ])


def build_address_block_input(
    z: bytes,
    counter: int,
) -> bytes:
    """
    Construct:

        Z || LE64(counter) || ZERO(968)

    Total size = 1024 bytes.
    """

    if len(z) != 48:
        raise ValueError(
            "Z must be exactly 48 bytes"
        )

    block = (
        z
        + _le64(counter)
        + bytes(968)
    )

    if len(block) != BLOCK_SIZE:
        raise AssertionError(
            "Address input block must be 1024 bytes"
        )

    return block

def bytes_to_words(block: bytes) -> list[int]:
    """
    Convert a 1024-byte block into
    128 little-endian uint64 words.
    """

    if len(block) != BLOCK_SIZE:
        raise ValueError(
            "Block must be exactly 1024 bytes"
        )

    return [
        int.from_bytes(
            block[i:i + 8],
            "little"
        )
        for i in range(
            0,
            BLOCK_SIZE,
            8
        )
    ]

def words_to_bytes(words: list[int]) -> bytes:
    """
    Convert 128 uint64 words into
    a 1024-byte block.
    """

    if len(words) != BLOCK_WORDS:
        raise ValueError(
            "Expected exactly 128 words"
        )

    return b"".join(
        word.to_bytes(
            8,
            "little"
        )
        for word in words
    )

def generate_address_block(
    pass_number: int,
    lane: int,
    slice_number: int,
    memory_blocks: int,
    passes: int,
    argon2_type: int,
    counter: int,
) -> bytes:
    """
    Generate one 1024-byte Argon2 address block.

    RFC 9106 construction:

        Z = LE64(r) || LE64(l) || LE64(sl) ||
            LE64(m') || LE64(t) || LE64(y)

        X = Z || LE64(counter) || ZERO(968)

        R = G(ZERO, X)

        ADDRESS = G(ZERO, R)
    """

    # --------------------------------------------------
    # Build the 48-byte parameter block Z
    # --------------------------------------------------

    z = build_address_input(
        pass_number=pass_number,
        lane=lane,
        slice_number=slice_number,
        memory_blocks=memory_blocks,
        passes=passes,
        argon2_type=argon2_type,
    )

    # --------------------------------------------------
    # Build the 1024-byte input block X
    # --------------------------------------------------

    x = build_address_block_input(
        z=z,
        counter=counter,
    )

    # --------------------------------------------------
    # First compression
    # --------------------------------------------------

    zero_block = bytes(1024)

    r = compress_block(
        zero_block,
        x,
    )

    # --------------------------------------------------
    # Second compression
    # --------------------------------------------------

    address = compress_block(
        zero_block,
        r,
    )

    return address

def extract_j_values(address_block: bytes) -> tuple[list[int], list[int]]:
    """
    Extract J1/J2 pairs from a 1024-byte Argon2
    address block.

    Each 64-bit word contains:

        low 32 bits  = J1
        high 32 bits = J2

    A 1024-byte block contains 128 uint64 words,
    therefore it contains 128 J1/J2 pairs.
    """

    if len(address_block) != 1024:
        raise ValueError(
            "Address block must be exactly 1024 bytes"
        )

    words = bytes_to_words(address_block)

    j1_values = []
    j2_values = []

    for word in words:

        j1 = word & 0xFFFFFFFF
        j2 = (word >> 32) & 0xFFFFFFFF

        j1_values.append(j1)
        j2_values.append(j2)

    return j1_values, j2_values   

def select_reference_lane(
    j2: int,
    current_lane: int,
    lane_count: int,
) -> int:
    """
    Select the reference lane using J2.

    For a single-lane configuration, the result
    is necessarily lane 0.
    """

    if lane_count <= 0:
        raise ValueError(
            "lane_count must be positive"
        )

    if not 0 <= current_lane < lane_count:
        raise ValueError(
            "current_lane outside lane range"
        )

    # RFC 9106:
    #
    # reference_lane = J2 mod lane_count
    #
    # During the first slice of the first pass,
    # the reference lane must be the current lane.
    #
    # That special-case is handled by the caller.
    return j2 % lane_count

def compute_reference_position(
    j1: int,
    reference_area_size_value: int,
) -> int:
    """
    Convert J1 into a relative reference position.

    RFC 9106:

        x = J1
        x = (x * x) >> 32
        y = reference_area_size * x
        y = y >> 32

    The result is then mapped relative to the
    reference-area start.
    """

    if reference_area_size_value <= 0:
        raise ValueError(
            "reference area must be positive"
        )

    x = j1 & 0xFFFFFFFF

    x = (
        x * x
    ) >> 32

    y = (
        reference_area_size_value * x
    ) >> 32

    return reference_area_size_value - 1 - y

def select_reference_block(
    j1: int,
    j2: int,
    pass_number: int,
    slice_number: int,
    position: int,
    current_lane: int,
    lane_count: int,
    lane_length: int,
    segment_length: int,
) -> tuple[int, int]:
    """
    Select the reference block according to RFC 9106
    Section 3.4.2.

    position is the GLOBAL position within the
    current lane.
    """

    if lane_count <= 0:
        raise ValueError(
            "lane_count must be positive"
        )

    if not 0 <= current_lane < lane_count:
        raise ValueError(
            "current_lane outside lane range"
        )

    if lane_length <= 0:
        raise ValueError(
            "lane_length must be positive"
        )

    if segment_length <= 0:
        raise ValueError(
            "segment_length must be positive"
        )

    # --------------------------------------------------
    # Local position inside the current segment
    # --------------------------------------------------

    local_position = position % segment_length

    # --------------------------------------------------
    # Select reference lane
    # --------------------------------------------------

    if (
        pass_number == 0
        and slice_number == 0
    ):
        # First slice of first pass can only reference
        # the current lane.
        reference_lane = current_lane

    else:
        reference_lane = (
            j2 % lane_count
        )

    same_lane = (
        reference_lane == current_lane
    )

    # --------------------------------------------------
    # Determine the reference set W.
    #
    # We represent W as a contiguous range:
    #
    #     start_position ... start_position + area_size - 1
    #
    # --------------------------------------------------

    if pass_number == 0:

        if slice_number == 0:

            # Only blocks before the current block.
            #
            # For B[2]:
            #     W = {B[0]}
            #
            # For B[3]:
            #     W = {B[0], B[1]}
            #
            area_size = local_position - 1
            start_position = 0

        elif same_lane:

            # Previous completed slices plus blocks
            # already computed in this segment,
            # excluding B[i][j-1].
            #
            # Example, slice 1:
            #
            # position 8:
            #     W = 0..6
            #
            # position 9:
            #     W = 0..7
            #
            area_size = (
                slice_number * segment_length
                + local_position
                - 1
            )

            start_position = 0

        else:

            # Different lane:
            #
            # Only completed previous slices.
            #
            # At the first position of a segment,
            # the last block of W is excluded.
            #
            area_size = (
                slice_number * segment_length
            )

            if local_position == 0:
                area_size -= 1

            start_position = 0

    else:

        if same_lane:

            # Previous three completed segments plus
            # already computed blocks in this segment,
            # excluding the previous block.
            area_size = (
                3 * segment_length
                + local_position
                - 1
            )

        else:

            # Other lane:
            # previous three completed segments.
            area_size = (
                3 * segment_length
            )

            # First block of the segment excludes the
            # last candidate from W.
            if local_position == 0:
                area_size -= 1

        # --------------------------------------------------
        # For passes > 0, W starts at the beginning of
        # the segment immediately after the current one,
        # except for slice 3 where it wraps to 0.
        # --------------------------------------------------

        if slice_number == 3:
            start_position = 0
        else:
            start_position = (
                (slice_number + 1)
                * segment_length
            )

    # --------------------------------------------------
    # Validate reference area
    # --------------------------------------------------

    if area_size <= 0:
        raise ValueError(
            f"Invalid reference area size: {area_size}"
        )

    # --------------------------------------------------
    # RFC 9106 quadratic mapping
    #
    # x = J1^2 / 2^32
    # y = W * x / 2^32
    # zz = W - 1 - y
    # --------------------------------------------------

    j1 &= 0xFFFFFFFF

    x = (
        j1 * j1
    ) >> 32

    y = (
        area_size * x
    ) >> 32

    relative_position = (
        area_size
        - 1
        - y
    )

    # --------------------------------------------------
    # Convert position inside W into actual lane index
    # --------------------------------------------------

    reference_index = (
        start_position
        + relative_position
    ) % lane_length

    return (
        reference_lane,
        reference_index,
    )