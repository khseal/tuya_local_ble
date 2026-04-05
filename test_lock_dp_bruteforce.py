#!/usr/bin/env python3
"""
Перебор DP ID для поиска команды открытия Tuya BLE замка (протокол v4).

Подключается, отправляет Device Info + Pair, затем по очереди пробует
разные DP в форматах bool и raw. Между попытками — пауза.
Проверяй вручную, сработал ли замок.

Запуск:
  python test_lock_dp_bruteforce.py DC:23:51:E8:C5:91 --uuid ... --local-key "..." --device-id ...

Опции:
  --dp-range 1-80    Диапазон DP для перебора (default: 1-80)
  --delay 6          Пауза между попытками в секундах (default: 6)
  --formats bool_v45,raw_v45,bool,raw Какие форматы пробовать (default: bool_v45,raw_v45)
"""

from __future__ import annotations

import os
import sys

_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir in sys.path:
    sys.path.remove(_script_dir)

import argparse
import asyncio
import hashlib
import json
import logging
import secrets
import struct

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.device import BLEDevice
except ImportError:
    print("Установите: pip install bleak")
    sys.exit(1)

try:
    from Crypto.Cipher import AES
except ImportError:
    print("Установите: pip install pycryptodome")
    sys.exit(1)


TUYA_SERVICE_IDS = ("0000a201", "0000fd50", "07d0")
CHARACTERISTIC_NOTIFY_FALLBACK = "00000002-0000-1001-8001-00805f9b07d0"
CHARACTERISTIC_WRITE_FALLBACK = "00000001-0000-1001-8001-00805f9b07d0"
GATT_MTU = 20
RESPONSE_TIMEOUT = 30
FUN_SENDER_DEVICE_INFO = 0x0000
FUN_SENDER_PAIR = 0x0001
FUN_SENDER_DEVICE_STATUS = 0x0003
FUN_SENDER_DPS_V4 = 0x0027

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
LOG = logging.getLogger(__name__)


def pack_varint(value: int) -> bytearray:
    result = bytearray()
    while True:
        curr = value & 0x7F
        value >>= 7
        if value:
            curr |= 0x80
        result.append(curr)
        if not value:
            break
    return result


def unpack_varint(data: bytes, start: int) -> tuple[int, int]:
    result, pos = 0, start
    for offset in range(5):
        if pos >= len(data):
            raise ValueError("Varint overflow")
        curr = data[pos]
        result |= (curr & 0x7F) << (offset * 7)
        pos += 1
        if (curr & 0x80) == 0:
            return (result, pos)
    raise ValueError("Varint overflow")


def calc_crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte & 0xFF
        for _ in range(8):
            tmp = crc & 1
            crc >>= 1
            if tmp:
                crc ^= 0xA001
    return crc


def build_packet(
    seq_num: int,
    code: int,
    data: bytes,
    key: bytes,
    security_flag: int,
    protocol_version: int = 4,
    response_to: int = 0,
) -> list[bytes]:
    raw = bytearray()
    raw += struct.pack(">IIHH", seq_num, response_to, code, len(data))
    raw += data
    raw += struct.pack(">H", calc_crc16(raw))
    while len(raw) % 16:
        raw.append(0)
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = bytes([security_flag]) + iv + cipher.encrypt(raw)
    packets = []
    pos, packet_num = 0, 0
    length = len(encrypted)
    while pos < length:
        pkt = bytearray()
        pkt += pack_varint(packet_num)
        if packet_num == 0:
            pkt += pack_varint(length)
            pkt += struct.pack(">B", protocol_version << 4)
        chunk = encrypted[pos : pos + GATT_MTU - len(pkt)]
        pkt += chunk
        packets.append(bytes(pkt))
        pos += len(chunk)
        packet_num += 1
    return packets


def build_device_info(seq: int, login_key: bytes) -> list[bytes]:
    return build_packet(seq, FUN_SENDER_DEVICE_INFO, bytearray([0, 0xF3]), login_key, 4)


def build_pairing(
    seq: int, uuid: str, local_key: str, device_id: str, session_key: bytes
) -> list[bytes]:
    data = bytearray()
    data += uuid.encode()
    data += local_key[:6].encode()
    data += device_id.encode()
    data += b"\x00" * (44 - len(data))
    return build_packet(seq, FUN_SENDER_PAIR, bytes(data), session_key, 5)


def build_dp_bool_v4(seq: int, dp_id: int, value: bool, session_key: bytes) -> list[bytes]:
    data = bytearray()
    data += struct.pack(">BBH", dp_id, 1, 1)
    data += struct.pack(">B", 1 if value else 0)
    return build_packet(seq, FUN_SENDER_DPS_V4, bytes(data), session_key, 5)


def build_dp_raw_v4(seq: int, dp_id: int, payload: bytes, session_key: bytes) -> list[bytes]:
    data = bytearray()
    data += struct.pack(">BBH", dp_id, 0, len(payload))
    data += payload
    return build_packet(seq, FUN_SENDER_DPS_V4, bytes(data), session_key, 5)


# Протокол 4.5: extra header dp_sn(4), dp_s_type(1), dp_s_mode(1), dp_s_ack(1)
def _wrap_dp_v45(seq: int, dp_id: int, dp_type: int, payload: bytes) -> bytes:
    data = bytearray()
    data += struct.pack(">IBBB", seq & 0xFFFFFFFF, 0, 0, 0)
    data += struct.pack(">BBH", dp_id, dp_type, len(payload))
    data += payload
    return bytes(data)


def build_dp_bool_v45(seq: int, dp_id: int, value: bool, session_key: bytes) -> list[bytes]:
    payload = struct.pack(">B", 1 if value else 0)
    data = _wrap_dp_v45(seq, dp_id, 1, payload)
    return build_packet(seq, FUN_SENDER_DPS_V4, data, session_key, 5)


def build_dp_raw_v45(seq: int, dp_id: int, payload: bytes, session_key: bytes) -> list[bytes]:
    data = _wrap_dp_v45(seq, dp_id, 0, payload)
    return build_packet(seq, FUN_SENDER_DPS_V4, data, session_key, 5)


def find_notify_write(client: BleakClient) -> tuple[str, str]:
    notify_uuid = write_uuid = None
    for service in client.services:
        su = service.uuid.lower()
        if not any(tid in su for tid in TUYA_SERVICE_IDS):
            continue
        for char in service.characteristics:
            props = {p.lower() for p in char.properties}
            if not notify_uuid and {"notify", "indicate"} & props:
                notify_uuid = char.uuid
            if not write_uuid and {"write", "write-without-response"} & props:
                write_uuid = char.uuid
            if notify_uuid and write_uuid:
                return (notify_uuid, write_uuid)
    return (CHARACTERISTIC_NOTIFY_FALLBACK, CHARACTERISTIC_WRITE_FALLBACK)


def parse_response(
    buffer: bytearray,
    login_key: bytes,
    key_bytes: bytes,
    session_key: bytes | None = None,
) -> tuple[bytes | None, int]:
    if len(buffer) < 18:
        return (None, -1)
    security_flag = buffer[0]
    iv = buffer[1:17]
    encrypted = buffer[17:]
    key = (
        login_key
        if security_flag == 4
        else (session_key if security_flag == 5 and session_key else None)
    )
    if key is None:
        return (None, -1)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    raw = cipher.decrypt(encrypted)
    if len(raw) < 12:
        return (None, -1)
    _, _, code, length = struct.unpack(">IIHH", raw[:12])
    if code == FUN_SENDER_DEVICE_INFO and length >= 12:
        srand = raw[18:24]
        new_sk = hashlib.md5(key_bytes + srand).digest()
        return (new_sk, code)
    return (None, code)


async def scan(address: str) -> BLEDevice | None:
    LOG.info("Сканирование...")
    devices = await BleakScanner.discover(timeout=10.0)
    addr = address.upper().replace("-", ":")
    for d in devices:
        if d.address.upper().replace("-", ":") == addr:
            return d
    return None


async def try_unlock_dp(
    client: BleakClient,
    write_char: str,
    seq: int,
    dp_id: int,
    fmt: str,
    session_key: bytes,
) -> int:
    """Отправляет unlock для DP. Возвращает seq для следующей команды."""
    if fmt == "raw":
        pkts = build_dp_raw_v4(seq, dp_id, b"\x01\x01", session_key)
    elif fmt == "raw_v45":
        pkts = build_dp_raw_v45(seq, dp_id, b"\x01\x01", session_key)
    elif fmt == "bool_v45":
        pkts = build_dp_bool_v45(seq, dp_id, True, session_key)
    else:
        pkts = build_dp_bool_v4(seq, dp_id, True, session_key)
    for pkt in pkts:
        await client.write_gatt_char(write_char, pkt, response=False)
        await asyncio.sleep(0.2)
    return seq + 1


async def run_bruteforce(
    address: str,
    uuid: str,
    local_key: str,
    device_id: str,
    dp_start: int,
    dp_end: int,
    delay: float,
    formats: list[str],
) -> None:
    address = address.upper().replace("-", ":")
    key_bytes = local_key[:6].encode()
    login_key = hashlib.md5(key_bytes).digest()

    device = await scan(address)
    if not device:
        LOG.error("Устройство не найдено")
        return

    total = (dp_end - dp_start + 1) * len(formats)
    LOG.info("Перебор: DP %d-%d, форматы %s. Всего попыток: %d", dp_start, dp_end, formats, total)

    attempt = 0
    for dp_id in range(dp_start, dp_end + 1):
        for fmt in formats:
            attempt += 1
            LOG.info("[%d/%d] DP %d, формат %s", attempt, total, dp_id, fmt)

            # Пересканирование и пауза для восстановления замка
            await asyncio.sleep(delay)
            dev = await scan(address)
            if not dev:
                dev = device

            try:
                async with BleakClient(dev, timeout=20.0) as client:
                    if not client.is_connected:
                        LOG.warning("Не удалось подключиться, пропуск")
                        await asyncio.sleep(delay)
                        continue

                    notify_char, write_char = find_notify_write(client)

                    input_buffer = bytearray()
                    expected_len = 0
                    response_event = asyncio.Event()
                    session_key: bytes | None = None

                    def on_notify(_: int, data: bytearray):
                        nonlocal input_buffer, expected_len, session_key
                        data = bytes(data)
                        pos = 0
                        try:
                            pkt_num, pos = unpack_varint(data, pos)
                            if pkt_num == 0:
                                expected_len, pos = unpack_varint(data, pos)
                                pos += 1
                                input_buffer = bytearray()
                            input_buffer += data[pos:]
                            if len(input_buffer) >= expected_len:
                                sk, code = parse_response(
                                    input_buffer, login_key, key_bytes, session_key
                                )
                                if sk is not None:
                                    session_key = sk
                                if code in (FUN_SENDER_DEVICE_INFO, FUN_SENDER_PAIR):
                                    response_event.set()
                        except Exception:
                            pass

                    await client.start_notify(notify_char, on_notify)
                    await asyncio.sleep(1.0)

                    seq = 1

                    # Device Info
                    response_event.clear()
                    for pkt in build_device_info(seq, login_key):
                        await client.write_gatt_char(write_char, pkt, response=False)
                        await asyncio.sleep(0.2)
                    try:
                        await asyncio.wait_for(response_event.wait(), RESPONSE_TIMEOUT)
                    except asyncio.TimeoutError:
                        LOG.warning("Таймаут Device Info, пропуск DP %d %s", dp_id, fmt)
                        await asyncio.sleep(delay + 3)
                        continue

                    if session_key is None:
                        LOG.warning("Нет session_key, пропуск")
                        await asyncio.sleep(delay)
                        continue

                    seq += 1

                    # Pair
                    response_event.clear()
                    for pkt in build_pairing(seq, uuid, local_key, device_id, session_key):
                        await client.write_gatt_char(write_char, pkt, response=False)
                        await asyncio.sleep(0.2)
                    try:
                        await asyncio.wait_for(response_event.wait(), RESPONSE_TIMEOUT)
                    except asyncio.TimeoutError:
                        LOG.warning("Таймаут Pair, пропуск")
                        await asyncio.sleep(delay)
                        continue

                    seq += 1

                    # Unlock
                    seq = await try_unlock_dp(
                        client, write_char, seq, dp_id, fmt, session_key
                    )
                    await asyncio.sleep(delay)

            except Exception as e:
                LOG.warning("Ошибка DP %d %s: %s", dp_id, fmt, e)
                await asyncio.sleep(delay)

    LOG.info("Перебор завершён. Если замок открылся — запомни DP и формат.")


def load_creds(address: str, config_dir: str) -> dict | None:
    path = os.path.join(config_dir, "tuya_local_ble", "devices.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    addr = address.upper().replace("-", ":")
    for k, v in data.items():
        if k.upper().replace("-", ":") == addr:
            return v
    return None


def main():
    parser = argparse.ArgumentParser(description="Перебор DP для unlock Tuya BLE замка")
    parser.add_argument("address", help="BLE адрес")
    parser.add_argument("--uuid", help="UUID из облака")
    parser.add_argument("--local-key", help="Local Key из облака")
    parser.add_argument("--device-id", help="Device ID из облака")
    parser.add_argument("--config", default="/config", help="Путь к config HA")
    parser.add_argument(
        "--dp-range",
        default="1-80",
        help="Диапазон DP (например 1-80)",
    )
    parser.add_argument("--delay", type=float, default=6.0, help="Пауза между попытками (сек)")
    parser.add_argument(
        "--formats",
        default="bool_v45,raw_v45",
        help="Форматы через запятую: bool_v45,raw_v45,bool,raw",
    )
    args = parser.parse_args()

    try:
        a, b = args.dp_range.split("-")
        dp_start, dp_end = int(a.strip()), int(b.strip())
    except ValueError:
        print("--dp-range должен быть вида 1-80")
        sys.exit(1)

    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    if not formats:
        formats = ["bool_v45", "raw_v45"]

    creds = None
    if args.uuid and args.local_key and args.device_id:
        creds = {
            "uuid": args.uuid,
            "local_key": args.local_key,
            "device_id": args.device_id,
        }
    else:
        creds = load_creds(args.address, args.config)

    if not creds:
        print("Укажите --uuid, --local-key, --device-id или devices.json")
        sys.exit(1)

    asyncio.run(
        run_bruteforce(
            args.address,
            creds["uuid"],
            creds["local_key"],
            creds["device_id"],
            dp_start,
            dp_end,
            args.delay,
            formats,
        )
    )


if __name__ == "__main__":
    main()
