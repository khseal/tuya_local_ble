"""Decode phone->lock ATT writes from btsnoop: inner Tuya command codes and gaps."""
from __future__ import annotations

import hashlib
import struct
import subprocess
import sys

from Crypto.Cipher import AES

from decrypt_from_tshark import _tshark_exe, parse_tuya_outer, tshark_notifies


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte & 255
        for _ in range(8):
            tmp = crc & 1
            crc >>= 1
            if tmp != 0:
                crc ^= 0xA001
    return crc


def decrypt_inner(enc: bytes, login_key: bytes, session_key: bytes | None) -> bytes | None:
    if len(enc) < 18:
        return None
    flag = enc[0]
    if flag == 4:
        key = login_key
    elif flag == 5:
        if session_key is None:
            return None
        key = session_key
    else:
        return None
    iv, ct = enc[1:17], enc[17:]
    if len(ct) < 16 or len(ct) % 16:
        return None
    return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)


def trim_payload(raw: bytes) -> bytes:
    """Strip PKCS-ish padding and CRC after Tuya inner length."""
    if len(raw) < 12:
        return raw
    _seq, _rto, _code, ln = struct.unpack(">IIHH", raw[:12])
    end = 12 + ln
    if end > len(raw):
        return raw
    chunk = raw[:end]
    if len(raw) >= end + 2:
        (crc_rx,) = struct.unpack(">H", raw[end : end + 2])
        if crc16(chunk) == crc_rx:
            return chunk
    return chunk


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else r"c:\Users\khseal\Desktop\btsnoop_hci.log"
    lk = sys.argv[2] if len(sys.argv) > 2 else "Phm+NgJ?r5K'o3;4"
    key6 = lk[:6].encode()
    login_key = hashlib.md5(key6).digest()
    session_key: bytes | None = None

    for nb in tshark_notifies(path):
        try:
            _, enc = parse_tuya_outer(nb)
        except ValueError:
            continue
        raw = decrypt_inner(enc, login_key, None)
        if raw is None or len(raw) < 12:
            continue
        inner = trim_payload(raw) if len(raw) >= 12 else raw
        if len(inner) < 12:
            continue
        _seq, _rto, code, ln = struct.unpack(">IIHH", inner[:12])
        data = inner[12 : 12 + ln]
        if code == 0 and len(data) >= 46:
            session_key = hashlib.md5(key6 + data[6:12]).digest()
            break

    exe = _tshark_exe()
    cmd = [
        exe,
        "-r",
        path,
        "-Y",
        "btatt.opcode == 0x52 && btatt.handle == 0x000e",
        "-T",
        "fields",
        "-e",
        "frame.time_relative",
        "-e",
        "btatt.value",
    ]
    out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    rows = [ln.rstrip().split("\t", 1) for ln in out.splitlines() if ln.strip()]

    print(f"session_key: {session_key.hex() if session_key else 'None'}\n")
    print("time_s  delta_s  flag  inner_code  payload_hex (first 40)")
    prev_t = None
    for t_s, hx in rows:
        t = float(t_s)
        delta = "" if prev_t is None else f"{t - prev_t:.3f}"
        prev_t = t
        blob = bytes.fromhex(hx)
        try:
            _, enc = parse_tuya_outer(blob)
        except ValueError:
            print(f"{t:8.3f}  {delta:>7}  ?     parse_err")
            continue
        flag = enc[0] if enc else -1
        raw = decrypt_inner(enc, login_key, session_key)
        if raw is None:
            print(f"{t:8.3f}  {delta:>7}  {flag:<4} decrypt_skip (need session?)")
            continue
        inner = trim_payload(raw)
        if len(inner) >= 12:
            seq, rto, code, ln = struct.unpack(">IIHH", inner[:12])
            data = inner[12 : 12 + ln]
            print(
                f"{t:8.3f}  {delta:>7}  {flag:<4} 0x{code:04x}     {data[:24].hex()}"
            )
        else:
            print(f"{t:8.3f}  {delta:>7}  {flag:<4} short_inner {inner.hex()[:40]}")


if __name__ == "__main__":
    main()
