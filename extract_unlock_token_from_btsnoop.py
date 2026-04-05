#!/usr/bin/env python3
"""
Извлечение 8-значного unlock_token из Android btsnoop (HCI) для hc7n0urm.

Сырые HCI-фрагменты обрезают длинные ATT; скрипт использует tshark (Wireshark),
чтобы получить полные значения notify. Расшифровка: MD5(local_key[:6]) и session_key.

Требования: Python 3, pip install pycryptodome, Wireshark (tshark в PATH).

Пример:
  py -3 extract_unlock_token_from_btsnoop.py ./btsnoop_hci.log "ВАШ_LOCAL_KEY"
"""
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
    raise FileNotFoundError(
        "tshark не найден. Установите Wireshark или добавьте tshark в PATH."
    )


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


def parse_tuya_outer(blob: bytes) -> tuple[int, bytes]:
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
    pos += 1
    enc = blob[pos:]
    return pos, enc


def decrypt_layer(
    enc: bytes, login_key: bytes, session_key: bytes | None
) -> tuple[bytes, str] | None:
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
    if len(sys.argv) < 3:
        print(
            "Использование:\n"
            "  py -3 extract_unlock_token_from_btsnoop.py <btsnoop_hci.log> <local_key>\n",
            file=sys.stderr,
        )
        sys.exit(1)

    path = sys.argv[1]
    lk = sys.argv[2]
    key6 = lk[:6].encode()
    login_key = hashlib.md5(key6).digest()
    session_key: bytes | None = None
    tokens: list[str] = []

    if not os.path.isfile(path):
        print(f"Файл не найден: {path}", file=sys.stderr)
        sys.exit(1)

    notifies = tshark_notifies(path)

    for blob in notifies:
        try:
            _, enc = parse_tuya_outer(blob)
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
        if code == 0 and len(data) >= 46 and session_key is None and lab == "login":
            session_key = hashlib.md5(key6 + data[6:12]).digest()
        for m in re.finditer(rb"[0-9]{8}", data):
            tokens.append(m.group().decode())

    if session_key:
        for blob in notifies:
            try:
                _, enc = parse_tuya_outer(blob)
            except ValueError:
                continue
            d = decrypt_layer(enc, login_key, session_key)
            if not d:
                continue
            raw, _lab = d
            inn = inner_data(raw)
            if not inn:
                continue
            _seq, _rto, _code, data = inn
            for m in re.finditer(rb"[0-9]{8}", data):
                tokens.append(m.group().decode())

    print("login_key:", login_key.hex())
    if session_key:
        print("session_key:", session_key.hex())

    if tokens:
        # последний уникальный или первый — обычно один токен
        token = tokens[-1]
        print("\nunlock_token:", token)
    else:
        print(
            "\nТокен не найден. Проверьте local_key и что лог снят с этим ключом.",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
