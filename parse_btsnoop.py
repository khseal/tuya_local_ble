"""Parse Android btsnoop_hci.log: ATT writes and notifications (hex).

NOTE: Each HCI record may carry only one L2CAP fragment; long ATT values are
split across records. This script shows per-fragment payloads (~20 B). For full
reassembled ATT (needed to decrypt Tuya), use Wireshark/tshark or decrypt_from_tshark.py.
"""
from __future__ import annotations

import re
import struct
import sys


def main(path: str) -> None:
    with open(path, "rb") as f:
        hdr = f.read(16)
        if hdr[:8] != b"btsnoop\x00":
            print("Not a btsnoop file", hdr[:16])
            sys.exit(1)

    # Phone -> lock: on many Android captures flags are 0 or 2 (not 1/3)
    phone_to_lock: list[tuple[int, str]] = []
    lock_to_phone: list[tuple[int, str]] = []
    notifies: list[tuple[int, str]] = []

    with open(path, "rb") as f:
        f.seek(16)
        while True:
            rec = f.read(24)
            if len(rec) < 24:
                break
            _olen, ilen, flags, _drops, ts = struct.unpack(">IIIIQ", rec)
            data = f.read(ilen)
            if len(data) < ilen:
                break

            is_phone_to_lock = flags in (0, 2)

            if not data or data[0] != 0x02:
                continue
            if len(data) < 5:
                continue
            l2cap = data[5:]
            if len(l2cap) < 4:
                continue
            cid = struct.unpack_from("<H", l2cap, 2)[0]
            if cid != 0x0004:
                continue
            att = l2cap[4:]
            if len(att) < 3:
                continue
            opcode = att[0]
            if opcode == 0x1B:  # Handle Value Notification
                val = att[3:]
                notifies.append((ts, val.hex()))
                continue
            if opcode not in (0x12, 0x52):
                continue
            val = att[3:]
            h = val.hex()
            if is_phone_to_lock:
                phone_to_lock.append((ts, h))
            else:
                lock_to_phone.append((ts, h))

    print("=== Phone -> lock (ATT Write) ===")
    for i, (_ts, h) in enumerate(phone_to_lock):
        print(f"{i+1:3d}  len={len(h)//2}  {h}")

    print("\n=== Lock -> phone (ATT Write, rare) ===")
    for i, (_ts, h) in enumerate(lock_to_phone[:10]):
        print(f"{i+1:3d}  {h}")

    print("\n=== Notifications (lock -> phone) ===")
    for i, (_ts, h) in enumerate(notifies[:25]):
        print(f"{i+1:3d}  len={len(h)//2}  {h}")

    blob = open(path, "rb").read()
    ascii_nums = re.findall(rb"[0-9]{8}", blob)
    print("\n=== Raw file: 8-digit ASCII sequences ===")
    if not ascii_nums:
        print("(none — token is inside AES ciphertext, see decrypt script)")
    else:
        for u in sorted(set(ascii_nums))[:20]:
            print(u.decode("ascii"))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else r"c:\Users\khseal\Desktop\btsnoop_hci.log")
