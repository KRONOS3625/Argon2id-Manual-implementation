from dataclasses import dataclass


ARGON2_D = 0
ARGON2_I = 1
ARGON2_ID = 2

ARGON2_VERSION_13 = 0x13


@dataclass
class Argon2Parameters:
    """
    Parameters controlling an Argon2 computation.
    """

    parallelism: int
    memory_cost: int
    time_cost: int
    tag_length: int

    version: int = ARGON2_VERSION_13
    variant: int = ARGON2_ID

    def validate(self) -> None:
        """
        Validate Argon2 parameters.
        """

        if self.parallelism <= 0:
            raise ValueError(
                "parallelism must be greater than zero"
            )

        if self.memory_cost <= 0:
            raise ValueError(
                "memory_cost must be greater than zero"
            )

        if self.time_cost <= 0:
            raise ValueError(
                "time_cost must be greater than zero"
            )

        if self.tag_length <= 0:
            raise ValueError(
                "tag_length must be greater than zero"
            )

        if self.version != ARGON2_VERSION_13:
            raise ValueError(
                "Only Argon2 version 0x13 is currently supported"
            )

        if self.variant not in (
            ARGON2_D,
            ARGON2_I,
            ARGON2_ID
        ):
            raise ValueError(
                "Unsupported Argon2 variant"
            )