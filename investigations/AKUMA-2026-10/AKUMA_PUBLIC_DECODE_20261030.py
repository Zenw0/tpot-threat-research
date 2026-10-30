#!/usr/bin/env python3
"""Verify the published Akuma/Polygon configuration evidence without network access.

This script uses the key disclosed by the report. It does NOT independently
recover that key from the malicious ELF or authenticate blockchain history.
For independent ELF-based key extraction, see the private forensic decoder.
No external Python packages are required; no malware is executed.
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import json
from pathlib import Path

KEY = bytes.fromhex("1a7e92513795dbd1ab8afdeea8a1d8b9dd56100601f7a1fc7b0021ea81a5d662")
CHECKIN_PREFIX = bytes.fromhex("00000001067838365f363409616b756d612e616462")


def decode_abi_string(hex_input: str) -> str:
    if not hex_input.startswith("0x9846adc5"):
        raise ValueError("Unexpected setter selector")
    raw = bytes.fromhex(hex_input[10:])
    if len(raw) < 64:
        raise ValueError("Truncated ABI string")
    offset = int.from_bytes(raw[:32], "big")
    if offset != 32 or offset + 32 > len(raw):
        raise ValueError("Invalid ABI offset")
    size = int.from_bytes(raw[offset:offset + 32], "big")
    if size > 128 or offset + 32 + size > len(raw):
        raise ValueError("Invalid ABI length")
    return raw[offset + 32:offset + 32 + size].decode("ascii")


def decode_configuration(ipv6: str) -> tuple[str, str, str]:
    packed = ipaddress.IPv6Address(ipv6).packed
    if packed[:4] != bytes.fromhex("20010db8"):
        raise ValueError("Unexpected documentary IPv6 prefix")
    ciphertext = packed[4:]
    plaintext = bytes(((((t << 5) | (t >> 3)) & 255) ^ KEY[(7 * i) % 32])
                      for i, b in enumerate(ciphertext)
                      for t in [(b - 13 * i) & 255])
    if plaintext != plaintext[:4] * 3:
        raise ValueError("Not a threefold IPv4 repetition")
    return ciphertext.hex(), plaintext.hex(), str(ipaddress.IPv4Address(plaintext[:4]))


def check(data: dict) -> None:
    adb = data["adbhoney"]
    events = adb["events"]
    if len(events) != adb["event_count"] or len(events) != 12:
        raise ValueError("Mismatch in published ADB event counts")
    counts = collections.Counter(e["src_ip"] for e in events)
    if counts != {"154.80.128.124": 8, "154.80.128.121": 4}:
        raise ValueError("Unexpected ADB event breakdown")
    if data["polygon"]["chain_id_hex"] != "0x89":
        raise ValueError("Unexpected chain identifier")
    for tx in data["polygon"]["setter_calls"]:
        ipv6 = decode_abi_string(tx["input"])
        if ipv6 != tx["stored_ipv6"]:
            raise ValueError("Calldata differs from curated IPv6")
        cipher, plain, destination = decode_configuration(ipv6)
        if destination != tx["decoded_ipv4"]:
            raise ValueError("Computed C2 differs from curated destination")
        print(f"Block {tx['block_number']} / tx {tx['transaction_hash'][:14]}...:")
        print(f"  stored IPv6 : {ipv6}")
        print(f"  encrypted   : {cipher}")
        print(f"  decoded 3x  : {plain}")
        print(f"  C2 config   : {destination}:25565 (reachability NOT tested)")

    observed = bytes.fromhex(data["isolated_lab_2026_10_29"]["c2_register_26_bytes_hex"])
    if len(observed) != 26 or not observed.startswith(CHECKIN_PREFIX):
        raise ValueError("C2 registration evidence does not match signature prefix")
    claimed = bytes.fromhex(data["isolated_lab_2026_10_29"]["candidate_network_signature"]["prefix_21_bytes_hex"])
    if claimed != CHECKIN_PREFIX:
        raise ValueError("Signature motif mismatch")
    print(f"C2 emulator registration: {len(observed)} bytes; 21-byte signature prefix verified")
    print("PASS: published records are internally consistent and decode offline.")
    print("LIMIT: the curated JSON and embedded key are secondary disclosures, not original raw evidence.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, help="AKUMA_PUBLIC_EVIDENCE_2026-10-28.json")
    args = parser.parse_args()
    check(json.loads(args.evidence.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
