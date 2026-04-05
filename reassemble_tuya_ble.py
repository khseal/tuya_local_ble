"""Reassemble Tuya BLE ATT values (20-byte MTU) and decrypt; find 8-digit token."""
from __future__ import annotations

import hashlib
import re
import struct
import sys

from Crypto.Cipher import AES


def unpack_int(data: bytes, start_pos: int) -> tuple[int, int]:
    result = 0
    offset = 0
    while offset < 5:
        pos = start_pos + offset
        if pos >= len(data):
            raise ValueError("eof")
        curr = data[pos]
        result |= (curr & 0x7F) << (offset * 7)
        offset += 1
        if (curr & 0x80) == 0:
            return result, start_pos + offset
    raise ValueError("varint")


def reassemble(values: list[bytes]) -> list[bytes]:
    """Match TuyaBLEDevice._notification_handler: concat fragments into full blobs."""
    out: list[bytes] = []
    buf: bytearray | None = None
    expected_len = 0
    expected_pkt = 0

    def clean() -> None:
        nonlocal buf, expected_len, expected_pkt
        buf = None
        expected_len = 0
        expected_pkt = 0

    for data in values:
        pos = 0
        pkt_num, pos = unpack_int(data, pos)
        if pkt_num < expected_pkt:
            clean()
        if pkt_num == expected_pkt:
            if pkt_num == 0:
                buf = bytearray()
                expected_len, pos = unpack_int(data, pos)
                pos += 1  # version byte
            assert buf is not None
            buf += data[pos:]
            expected_pkt += 1
            if len(buf) > expected_len:
                clean()
                continue
            if len(buf) == expected_len:
                out.append(bytes(buf))
                clean()
        else:
            clean()
            # same as handler: drop this notification
    return out


def decrypt_blob(blob: bytes, login_key: bytes, session_key: bytes | None) -> tuple[bytes, str] | None:
    if len(blob) < 18:
        return None
    flag = blob[0]
    if flag == 4:
        key = login_key
        label = "login"
    elif flag == 5:
        if session_key is None:
            return None
        key = session_key
        label = "session"
    elif flag == 1:
        return None  # auth_key unknown
    else:
        return None
    iv = blob[1:17]
    enc = blob[17:]
    if len(enc) < 16 or len(enc) % 16:
        return None
    raw = AES.new(key, AES.MODE_CBC, iv).decrypt(enc)
    return raw, label


def parse_inner(raw: bytes) -> tuple[int, int, int, bytes] | None:
    if len(raw) < 12:
        return None
    seq, rto, code, ln = struct.unpack(">IIHH", raw[:12])
    if 12 + ln > len(raw):
        return None
    return seq, rto, code, raw[12 : 12 + ln]


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else r"c:\Users\khseal\Desktop\btsnoop_hci.log"
    lk = sys.argv[2] if len(sys.argv) > 2 else "Phm+Ng"
    key_bytes = lk[:6].encode()
    login_key = hashlib.md5(key_bytes).digest()
    session_key: bytes | None = None

    from extract_unlock_token_from_btsnoop import parse_btsnoop_att

    writes, notifies = parse_btsnoop_att(path)
    print("login_key md5(first6):", login_key.hex())

    for name, vals in ("notify", notifies), ("write", writes):
        blobs = reassemble(vals)
        print(f"\n=== {name}: {len(vals)} ATT values -> {len(blobs)} complete blob(s) ===")
        for i, blob in enumerate(blobs):
            print(f"  blob {i+1}: len={len(blob)} hex={blob[:32].hex()}...")
        for i, blob in enumerate(blobs):
            # session_key only from lock DEVICE_INFO notify (>=46 B inner, srand at 6:12)
            if session_key is None and name == "notify":
                d = decrypt_blob(blob, login_key, None)
                if d and d[1] == "login":
                    raw, _ = d
                    inner = parse_inner(raw)
                    if inner:
                        _s, _r, code, data = inner
                        if code == 0 and len(data) >= 46:
                            srand = data[6:12]
                            session_key = hashlib.md5(key_bytes + srand).digest()
                            print(
                                f"  {name} blob {i+1}: DEVICE_INFO rsp, session_key={session_key.hex()}"
                            )
            d = decrypt_blob(blob, login_key, session_key)
            if not d:
                continue
            raw, label = d
            inner = parse_inner(raw)
            if inner:
                _s, _r, code, data = inner
                print(
                    f"  {name} blob {i+1} ({label}): code=0x{code:x} data_len={len(data)}"
                )
                for m in re.finditer(rb"[0-9]{8}", data):
                    print(
                        f"  *** 8-digit in {name} blob {i+1} ({label}) data: {m.group().decode()}"
                    )
                if b"12742760" in data or re.search(rb"1[0-9]{7}", data):
                    print(f"  {name} blob {i+1} inner ({label}): {data.hex()}")
            for m in re.finditer(rb"[0-9]{8}", raw):
                print(
                    f"  *** 8-digit in {name} blob {i+1} raw ({label}): {m.group().decode()}"
                )

    if session_key is None:
        print(
            "\nNo session_key from notify DEVICE_INFO (notify side incomplete in this capture)."
        )
        print(
            "Phone->lock writes may still decrypt with login_key only (flag 4) until session exists."
        )


if __name__ == "__main__":
    main()
