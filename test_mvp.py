from crypto_engine.argon2.engine import argon2id


def main():

    password = b"password"
    salt = b"somesalt"

    result = argon2id(
        password=password,
        salt=salt,
        memory_kib=32,
        passes=2,
        lanes=1,
        output_length=32,
    )

    print()
    print("Argon2id MVP")
    print("------------------------------")
    print("Password :", password)
    print("Salt     :", salt)
    print("Memory   : 32 KiB")
    print("Passes   : 2")
    print("Lanes    : 1")
    print()
    print("Hash:")
    print(result.hex())
    print()
    print("Length:", len(result))

    expected = (
        "31111cc053ba0a799c0884148fd7ec9d"
        "c3631f3e8cf476cca9521d4ccc5136e8"
    )

    if result.hex() == expected:
        print()
        print("================================")
        print("ARGON2ID MVP: PASS")
        print("================================")
    else:
        print()
        print("================================")
        print("ARGON2ID MVP: FAIL")
        print("================================")
        print()
        print("Expected:")
        print(expected)
        print()
        print("Got:")
        print(result.hex())


if __name__ == "__main__":
    main()
