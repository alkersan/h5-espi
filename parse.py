import csv
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterator


class OpCode(IntEnum):
    PUT_VWIRE = 0x04
    GET_VWIRE = 0x05

    GET_CONFIGURATION = 0x21
    SET_CONFIGURATION = 0x22
    GET_STATUS = 0x25

    PUT_IORD_SHORT_1B = 0x40
    PUT_IOWR_SHORT_1B = 0x44
    PUT_IOWR_SHORT_2B = 0x45


@dataclass
class Frame:
    start_time: float
    io0: list[int]
    io1: list[int]


def crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xff if crc & 0x80 else crc << 1
    return crc


def bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("bit count is not byte-aligned")

    return bytes(
        sum(bit << (7 - i) for i, bit in enumerate(bits[pos:pos + 8]))
        for pos in range(0, len(bits), 8)
    )


def get_frames(path: str) -> Iterator[Frame]:
    with open(path, "r") as input_file:
        reader = csv.DictReader(input_file)
        previous = next(reader)
        frame = None
        for row in reader:
            cs_asserted = previous["CS"] == "1" and row["CS"] == "0"
            cs_deasserted = previous["CS"] == "0" and row["CS"] == "1"
            rising_clk = previous["CLK"] == "0" and row["CLK"] == "1"

            if cs_asserted:
                frame = Frame(start_time=float(row["Time"]), io0=[], io1=[])

            if row["CS"] == "0" and rising_clk and frame is not None:
                frame.io0.append(int(row["IO0"]))
                frame.io1.append(int(row["IO1"]))

            if cs_deasserted and frame is not None:
                if len(frame.io0) > 0:
                    yield frame
                frame = None

            previous = row


COMMAND_LENGTHS = {
    OpCode.GET_CONFIGURATION: 4,
    OpCode.SET_CONFIGURATION: 8,
    OpCode.GET_STATUS: 2,
    OpCode.PUT_IORD_SHORT_1B: 4,
    OpCode.PUT_IOWR_SHORT_1B: 5,
    OpCode.PUT_IOWR_SHORT_2B: 6,
    OpCode.GET_VWIRE: 2,
}


def main():
    stats = {}

    for frame in get_frames("captures/cold-boot-stock-1.02.csv"):
        op_code = OpCode(int("".join(map(str, frame.io0[:8])), 2))
        stats[op_code] = stats.get(op_code, 0) + 1

        match op_code:
            case OpCode.GET_CONFIGURATION | OpCode.SET_CONFIGURATION | OpCode.GET_STATUS \
                 | OpCode.PUT_IORD_SHORT_1B | OpCode.PUT_IOWR_SHORT_1B | OpCode.PUT_IOWR_SHORT_2B \
                 | OpCode.GET_VWIRE:
                cmd_end = COMMAND_LENGTHS[op_code] * 8
                cmd = bits_to_bytes(frame.io0[:cmd_end])
                if crc8(cmd) != 0:
                    raise ValueError(f"bad command CRC: {cmd.hex(' ')}")

                resp_start = cmd_end + 2
                resp = bits_to_bytes(frame.io1[resp_start:]).removeprefix(b"\x0f")
                if crc8(resp) != 0:
                    raise ValueError(f"bad response CRC: {resp.hex(' ')}")

                print(f"{frame.start_time:9.6f} {op_code.name}: [{cmd.hex(' ')}] <-> [{resp.hex(' ')}]")

            case OpCode.PUT_VWIRE:
                vw_count = int("".join(map(str, frame.io0[8:16])), 2) + 1
                cmd_end = (3 + 2 * vw_count) * 8
                cmd = bits_to_bytes(frame.io0[:cmd_end])
                if crc8(cmd) != 0:
                    raise ValueError(f"bad command CRC: {cmd.hex(' ')}")
                resp_start = cmd_end + 2
                resp = bits_to_bytes(frame.io1[resp_start:]).removeprefix(b"\x0f")
                if crc8(resp) != 0:
                    raise ValueError(f"bad response CRC: {resp.hex(' ')}")

                print(f"{frame.start_time:9.6f} {op_code.name}: [{cmd.hex(' ')}] <-> [{resp.hex(' ')}]")

            case _:
                print(f"{frame.start_time:9.6f} {op_code.name}")

    print("-----")
    for op_code, count in stats.items():
        print(f"{op_code.name} [{hex(op_code)}]: {count}")


if __name__ == '__main__':
    main()
