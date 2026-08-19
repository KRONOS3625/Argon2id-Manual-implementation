from blake2b_long import h_prime


def test_output_lengths():
    data = b"hello"

    expected_lengths = [
        1,
        16,
        32,
        64,
        65,
        96,
        128,
        256,
        1024,
    ]

    for length in expected_lengths:
        result = h_prime(data, length)

        assert len(result) == length, (
            f"Expected {length} bytes, got {len(result)}"
        )


def test_deterministic():
    data = b"hello"

    first = h_prime(data, 1024)
    second = h_prime(data, 1024)

    assert first == second


def test_different_inputs():
    first = h_prime(b"hello", 1024)
    second = h_prime(b"hello!", 1024)

    assert first != second


def main():
    test_output_lengths()
    test_deterministic()
    test_different_inputs()

    print("All H' structural tests passed.")


if __name__ == "__main__":
    main()