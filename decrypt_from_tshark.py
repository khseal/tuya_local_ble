"""Decrypt Tuya BLE using full ATT values from tshark (L2CAP reassembled)."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys

from Crypto.Cipher import AES


def _tshark_exe() -> str:
    w = shutil.which("tshark")
    if w:
        return w
    win = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.isfile(win):
        return win
    raise FileNotFoundError("tshark not found; install Wireshark or add tshark to PATH")


def tshark_notifies(btsnoop: str, handle: str = "0x0010") -> list[bytes]:
    exe = _tshark_exe()
    cmd = [
        exe,
        "-r",
        btsnoop,
        "-Y",
        f"btatt.opcode == 0x1b && btatt.handle == {handle}",
        "-T",
        "fields",
        "-e",
        "btatt.value",
    ]
    out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    rows = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return [bytes.fromhex(r) for r in rows]


def tshark_writes(btsnoop: str, handle: str = "0x000e") -> list[bytes]:
    exe = _tshark_exe()
    cmd = [
        exe,
        "-r",
        btsnoop,
        "-Y",
        f"btatt.opcode == 0x52 && btatt.handle == {handle}",
        "-T",
        "fields",
        "-e",
        "btatt.value",
    ]
    out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    rows = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return [bytes.fromhex(r) for r in rows]


def parse_tuya_outer(blob: bytes) -> tuple[int, bytes]:
    """After reassembly: leading varint pkt0, varint enc_len, version, then ciphertext."""
    pos = 0

    def uvi(b: bytes, p: int) -> tuple[int, int]:
        r, o = 0, 0
        while o < 5:
            if p + o >= len(b):
                raise ValueError("eof")
            c = b[p + o]
            r |= (c & 0x7F) << (o * 7)
            o += 1
            if (c & 0x80) == 0:
                return r, p + o
        raise ValueError("varint")

    _pn, pos = uvi(blob, pos)
    _elen, pos = uvi(blob, pos)
    pos += 1  # version
    enc = blob[pos:]
    return pos, enc


def decrypt_layer(enc: bytes, login_key: bytes, session_key: bytes | None) -> tuple[bytes, str] | None:
    if len(enc) < 18:
        return None
    flag = enc[0]
    if flag == 4:
        key, lab = login_key, "login"
    elif flag == 5:
        if session_key is None:
            return None
        key, lab = session_key, "session"
    else:
        return None
    iv, ct = enc[1:17], enc[17:]
    if len(ct) < 16 or len(ct) % 16:
        return None
    raw = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    return raw, lab


def inner_data(raw: bytes) -> tuple[int, int, int, bytes] | None:
    if len(raw) < 12:
        return None
    seq, rto, code, ln = struct.unpack(">IIHH", raw[:12])
    if 12 + ln > len(raw):
        return None
    return seq, rto, code, raw[12 : 12 + ln]


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else r"c:\Users\khseal\Desktop\btsnoop_hci.log"
    lk = sys.argv[2] if len(sys.argv) > 2 else "Phm+NgJ?r5K'o3;4"
    key6 = lk[:6].encode()
    login_key = hashlib.md5(key6).digest()
    session_key: bytes | None = None

    notifies = tshark_notifies(path)
    writes = tshark_writes(path)
    print("login_key:", login_key.hex())
    print("full ATT notifies:", len(notifies), "writes:", len(writes))

    for i, blob in enumerate(notifies):
        try:
            _hdr, enc = parse_tuya_outer(blob)
        except ValueError:
            print(f"notify {i+1}: bad outer ({len(blob)} B)")
            continue
        d = decrypt_layer(enc, login_key, session_key)
        if not d:
            print(f"notify {i+1}: skip flag={enc[0] if enc else -1} len={len(enc)}")
            continue
        raw, lab = d
        inn = inner_data(raw)
        if not inn:
            print(f"notify {i+1}: decrypt ok, bad inner")
            continue
        seq, rto, code, data = inn
        if code == 0 and len(data) >= 46 and session_key is None and lab == "login":
            srand = data[6:12]
            session_key = hashlib.md5(key6 + srand).digest()
            print(f"notify {i+1}: DEVICE_INFO -> session_key={session_key.hex()}")
        for m in re.finditer(rb"[0-9]{8}", data):
            print(f"notify {i+1}: *** 8-digit: {m.group().decode()} ***")
        if code == 0x27 or (code & 0xFFFF) == 0x27:
            print(f"notify {i+1}: code 0x27 data: {data.hex()}")

    if session_key:
        print("\n--- second pass with session_key ---")
        for i, blob in enumerate(notifies):
            try:
                _hdr, enc = parse_tuya_outer(blob)
            except ValueError:
                continue
            d = decrypt_layer(enc, login_key, session_key)
            if not d:
                continue
            raw, lab = d
            inn = inner_data(raw)
            if not inn:
                continue
            _seq, _rto, code, data = inn
            for m in re.finditer(rb"[0-9]{8}", data):
                print(f"notify {i+1}: *** 8-digit: {m.group().decode()} ***")
            if b"31323334" in data or re.search(rb"[0-9]{8}", raw):
                print(f"notify {i+1} raw tail: {raw[-48:].hex()} data: {data.hex()}")


if __name__ == "__main__":
    main()
