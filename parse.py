#!/usr/bin/env python3
import csv
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Iterator


class OpCode(IntEnum):
    PUT_VWIRE = 0x04
    GET_VWIRE = 0x05

    GET_CONFIG = 0x21
    SET_CONFIG = 0x22
    GET_STATUS = 0x25

    IO_READ_1B = 0x40
    IO_WRITE_1B = 0x44
    IO_WRITE_2B = 0x45


class RespCode(IntEnum):
    ACCEPT = 0x08
    DEFER = 0x01
    NON_FATAL_ERROR = 0x2
    FATAL_ERROR = 0x3
    NO_RESPONSE = 0xff



@dataclass
class Frame:
    start_time: float
    io0: list[int]
    io1: list[int]
    has_alert: bool = False


@dataclass
class Txn:
    start_time: float
    op_code: OpCode
    cmd: bytes
    rsp: bytes


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


def bits_to_byte(bits: list[int]) -> int:
    return bits_to_bytes(bits)[0]


def get_frames(path: str) -> Iterator[Frame]:
    with open(path, "r") as input_file:
        reader = csv.DictReader(input_file, fieldnames=["Time", "IO0", "IO1", "CS", "CLK"])
        previous = next(reader)
        frame = None
        for row in reader:
            cs_asserted = previous["CS"] == "1" and row["CS"] == "0"
            cs_deasserted = previous["CS"] == "0" and row["CS"] == "1"
            rising_clk = previous["CLK"] == "0" and row["CLK"] == "1"

            if cs_asserted:
                frame = Frame(start_time=float(row["Time"]), io0=[], io1=[])
                frame.has_alert = previous["IO1"] == "0"

            if row["CS"] == "0" and rising_clk and frame is not None:
                frame.io0.append(int(row["IO0"]))
                frame.io1.append(int(row["IO1"]))

            if cs_deasserted and frame is not None:
                if len(frame.io0) > 0:
                    yield frame
                frame = None

            previous = row


def command_len(op_code: OpCode, frame: Frame) -> int:
    if op_code == OpCode.PUT_VWIRE:
        # Virtual Wire count byte: bits 7:6 reserved, 5:0 zero-based count
        vw_count_byte = bits_to_byte(frame.io0[8:16])
        if vw_count_byte & 0xc0:
            raise ValueError(f"bad VW count reserved bits: {vw_count_byte:02x}")
        return 3 + 2 * ((vw_count_byte & 0x3f) + 1)

    fixed_len_cmd = {
        OpCode.GET_CONFIG: 4,
        OpCode.SET_CONFIG: 8,
        OpCode.GET_STATUS: 2,
        OpCode.IO_READ_1B: 4,
        OpCode.IO_WRITE_1B: 5,
        OpCode.IO_WRITE_2B: 6,
        OpCode.GET_VWIRE: 2,
    }
    return fixed_len_cmd[op_code]


def decode_frame(frame: Frame) -> Txn:
    op_code = OpCode(bits_to_byte(frame.io0[:8]))
    cmd_end = command_len(op_code, frame) * 8
    cmd = bits_to_bytes(frame.io0[:cmd_end])
    if crc8(cmd) != 0:
        raise ValueError(f"bad command CRC: {cmd.hex(' ')}")

    turnaround_bits = 2
    wait_state = b"\x0f"
    rsp = bits_to_bytes(frame.io1[cmd_end + turnaround_bits:])
    while rsp.startswith(wait_state):
        rsp = rsp[1:]
    if crc8(rsp) != 0:
        raise ValueError(f"bad response CRC: {rsp.hex(' ')}")
    return Txn(frame.start_time, op_code, cmd, rsp)


class EspiPcapWriter:
    LINKTYPE_USER0 = 147

    def __init__(self, filename):
        self.file = open(filename, "wb")
        self.file.write(struct.pack(
            "<IHHiIII",
            0xA1B2C3D4,  # Magic
            2, 4,  # PCAP version 2.4
            0,  # Reserved
            0,  # Reserved
            65535,  # Max captured packet size
            self.LINKTYPE_USER0
        ))

    def add_transaction(self, txn: Txn):
        header = struct.pack(">H", len(txn.cmd))
        data = header + txn.cmd + txn.rsp
        self.file.write(struct.pack(
            "<IIII",
            int(txn.start_time),
            datetime.fromtimestamp(txn.start_time).microsecond,
            len(data),
            len(data)
        ))
        self.file.write(data)

    def close(self):
        self.file.close()


def main():
    op_stats = defaultdict(int)
    io_addr_reads = defaultdict(int)
    io_addr_writes = defaultdict(int)
    get_stat_alerts = {True: 0, False: 0}
    # writer = EspiPcapWriter("espi.pcap")
    input_file = "captures/cold-boot-stock-1.02.csv"
    if len(sys.argv) > 1:
        input_file = sys.argv[1]

    for frame in get_frames(input_file):
        txn = decode_frame(frame)
        op_stats[txn.op_code] += 1

        cmd_data = txn.cmd[1:-1]
        rsp_data = txn.rsp[1:-3]
        rsp_status = txn.rsp[-3]
        tx_queues = [
            name
            for bit, name in enumerate(("pc", "np", "vw", "oob"), start=4)
            if rsp_status & (1 << bit)
        ]
        status_msg = ""
        if tx_queues:
            status_msg = f" [tx: {' '.join(tx_queues)}]"
        alert_msg = "   "
        if frame.has_alert:
            alert_msg = " A "

        match txn.op_code:
            case OpCode.IO_WRITE_1B | OpCode.IO_WRITE_2B:
                addr = int.from_bytes(cmd_data[:2])
                value = cmd_data[2:]
                io_addr_writes[addr] += 1
                print(f"{frame.start_time:9.6f}{alert_msg}{'IO_WRITE':<11}{addr:3x} -> {value.hex(' ')}{status_msg}")
            case OpCode.IO_READ_1B:
                addr = int.from_bytes(cmd_data[:2])
                io_addr_reads[addr] += 1
                print(f"{frame.start_time:9.6f}{alert_msg}{'IO_READ':<11}{addr:3x} <- {rsp_data.hex(' ')}{status_msg}")
            case OpCode.GET_CONFIG:
                addr = int.from_bytes(cmd_data[:2])
                print(f"{frame.start_time:9.6f}{alert_msg}{txn.op_code.name:<12}{addr:02x} <- {rsp_data.hex(' ')}{status_msg}")
            case OpCode.SET_CONFIG:
                addr = int.from_bytes(cmd_data[:2])
                print(f"{frame.start_time:9.6f}{alert_msg}{txn.op_code.name:<12}{addr:02x} -> {cmd_data[2:].hex(' ')}{status_msg}")
            case OpCode.GET_VWIRE:
                print(f"{frame.start_time:9.6f}{alert_msg}{txn.op_code.name:<12}   <- {rsp_data.hex(' ')}{status_msg}")
            case OpCode.PUT_VWIRE:
                print(f"{frame.start_time:9.6f}{alert_msg}{txn.op_code.name:<12}   -> {cmd_data.hex(' ')}{status_msg}")
            case OpCode.GET_STATUS:
                if tx_queues:
                    print(f"{frame.start_time:9.6f}{alert_msg}{txn.op_code.name}{status_msg}")
                else:
                    get_stat_alerts[frame.has_alert] += 1
            case _:
                print(
                    f"{frame.start_time:9.6f}{alert_msg}{txn.op_code.name:<20}" +
                    f"{cmd_data.hex(' '):<26} <=> " +
                    f"{rsp_data.hex(' '):<26}{status_msg}"
                )
        # writer.add_transaction(txn)
    # writer.close()

    print("\n=== OP Stats:")
    print(f"total: {sum(op_stats.values())}")
    for op_code, count in op_stats.items():
        print(f"{op_code.name} [{hex(op_code)}]: {count}")
    print("=== IO ADDR Writes:")
    for io_addr, count in io_addr_writes.items():
        print(f"{hex(io_addr)}: {count}")
    print("=== IO ADDR Reads:")
    for io_addr, count in io_addr_reads.items():
        print(f"{hex(io_addr)}: {count}")
    print("=== GET_STATUS had alert:")
    print(get_stat_alerts)

if __name__ == '__main__':
    main()
