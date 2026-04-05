"""
Try to find 8-digit unlock_token in btsnoop by decrypting Tuya BLE packets.

NOTE: Raw btsnoop parsing often sees only ~20 B per HCI fragment. Prefer
decrypt_from_tshark.py (tshark reassembles full ATT values).

Requires: pip install pycryptodome
Usage:
  py -3 extract_unlock_token_from_btsnoop.py btsnoop_hci.log "LOCAL_KEY_FIRST_6_CHARS_OR_FULL"
"""
from __future__ import annotations

import hashlib
import re
import struct
import sys

from Crypto.Cipher import AES


def parse_btsnoop_att(path: str) -> tuple[list[bytes], list[bytes]]:
    """Return (phone_writes, lock_notifies) as raw ATT values."""
    writes: list[bytes] = []
    notifies: list[bytes] = []
    with open(path, "rb") as f:
        f.seek(16)
        while True:
            rec = f.read(24)
            if len(rec) < 24:
                break
            _olen, ilen, flags, _drops, _ts = struct.unpack(">IIIIQ", rec)
            data = f.read(ilen)
            if len(data) < ilen:
                break
            is_phone = flags in (0, 2)
            if not data or data[0] != 0x02:
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
            op = att[0]
            if op == 0x1B:
                notifies.append(att[3:])
            elif op in (0x12, 0x52) and is_phone:
                writes.append(att[3:])
    return writes, notifies


def try_decrypt_blob(blob: bytes, key: bytes) -> bytes | None:
    if len(blob) < 18:
        return None
    flag = blob[0]
    if flag not in (4, 5):
        return None
    iv = blob[1:17]
    enc = blob[17:]
    if len(enc) < 16 or len(enc) % 16:
        return None
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        return cipher.decrypt(enc)
    except Exception:
        return None


def inner_plaintext(raw: bytes) -> bytes | None:
    if len(raw) < 12:
        return None
    _seq, _resp, _code, ln = struct.unpack(">IIHH", raw[:12])
    if 12 + ln > len(raw):
        return None
    return raw[12 : 12 + ln]


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else r"c:\Users\khseal\Desktop\btsnoop_hci.log"
    lk = sys.argv[2] if len(sys.argv) > 2 else ""
    if not lk:
        print("Usage: extract_unlock_token_from_btsnoop.py <btsnoop> <local_key>")
        sys.exit(1)

    key_bytes = lk[:6].encode()
    login_key = hashlib.md5(key_bytes).digest()
    session_key: bytes | None = None

    writes, notifies = parse_btsnoop_att(path)
    print(f"Phone writes: {len(writes)}, lock notifies: {len(notifies)}")

    all_blobs = writes + notifies
    for i, blob in enumerate(all_blobs):
        # Reassemble multi-chunk Tuya framing: skip — use full value as one chunk if small
        if len(blob) < 18:
            continue
        for key, label in ((login_key, "login"), (session_key, "session")):
            if key is None and label == "session":
                continue
            raw = try_decrypt_blob(blob, key)  # type: ignore[arg-type]
            if raw is None:
                continue
            inner = inner_plaintext(raw)
            if inner is None:
                continue
            # FUN_SENDER_DEVICE_INFO: get session
            if len(inner) >= 12 and label == "login":
                srand = inner[6:12]
                session_key = hashlib.md5(key_bytes + srand).digest()
            m = re.search(rb"[0-9]{8}", inner)
            if m:
                print(f"Candidate token in packet {i} ({label}): {m.group().decode()}")
            # hc7 payload often has ASCII digits after fixed header
            if b"31323334" in inner.hex().encode() or re.search(rb"[0-9]{8}", raw):
                print(f"packet {i} inner hex: {inner.hex()}")

    # Brute search decrypted notifies for 8 digits
    for i, blob in enumerate(notifies):
        for key in (login_key, session_key):
            if key is None:
                continue
            raw = try_decrypt_blob(blob, key)
            if not raw:
                continue
            m = re.search(rb"[0-9]{8}", raw)
            if m:
                print(f"Notify {i}: token? {m.group().decode()} (key={key is session_key})")


if __name__ == "__main__":
    main()
