#!/usr/bin/env python3
"""
Тестовый скрипт открытия/закрытия Tuya BLE замка A1 Ultra-JM.

Позволяет проверить DP ID и отправить lock/unlock команды.

Запуск:
  python test_lock_control.py DC:23:51:E8:C5:91 --uuid ... --local-key "..." --device-id ...

Команды:
  --lock     Закрыть замок (dp_id_lock)
  --unlock   Открыть замок (dp_id_unlock)
  --state    Запросить статус (FUN_SENDER_DEVICE_STATUS)

Тестирование DP:
  --dp-lock 46   ID для команды закрытия (default: 46)
  --dp-unlock 6  ID для команды открытия (default: 6)
  --dp-state 47  ID для чтения состояния (default: 47)
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
FUN_SENDER_DPS = 0x0002
FUN_SENDER_DEVICE_STATUS = 0x0003
FUN_SENDER_DPS_V4 = 0x0027

logging.basicConfig(
    level=logging.DEBUG,
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
    data = bytearray([0, 0xF3])
    return build_packet(seq, FUN_SENDER_DEVICE_INFO, data, login_key, 4)


def build_pairing(seq: int, uuid: str, local_key: str, device_id: str, session_key: bytes) -> list[bytes]:
    data = bytearray()
    data += uuid.encode()
    data += local_key[:6].encode()
    data += device_id.encode()
    data += b"\x00" * (44 - len(data))
    return build_packet(seq, FUN_SENDER_PAIR, bytes(data), session_key, 5)


def build_dp_bool_v4(seq: int, dp_id: int, value: bool, session_key: bytes) -> list[bytes]:
    """Протокол 4: dp_id, type=1 (BOOL), len=2, value. Для DP 46 (manual lock)."""
    data = bytearray()
    data += struct.pack(">BBH", dp_id, 1, 1)  # type 1 = BOOL, len 1
    data += struct.pack(">B", 1 if value else 0)
    return build_packet(seq, FUN_SENDER_DPS_V4, bytes(data), session_key, 5)


def build_dp_raw_v4(seq: int, dp_id: int, payload: bytes, session_key: bytes) -> list[bytes]:
    """Протокол 4: dp_id, type=0 (RAW), len=2, payload. Для DP 6 (unlock: 0x01 0x01)."""
    data = bytearray()
    data += struct.pack(">BBH", dp_id, 0, len(payload))  # type 0 = RAW
    data += payload
    return build_packet(seq, FUN_SENDER_DPS_V4, bytes(data), session_key, 5)

def build_dp_value_v4(seq: int, dp_id: int, value: int, session_key: bytes) -> list[bytes]:
    """Протокол 4: dp_id, type=2 (VALUE), len=2, value(4 bytes)."""
    payload = struct.pack(">I", int(value) & 0xFFFFFFFF)
    data = bytearray()
    data += struct.pack(">BBH", dp_id, 2, len(payload))  # type 2 = VALUE
    data += payload
    return build_packet(seq, FUN_SENDER_DPS_V4, bytes(data), session_key, 5)


# Протокол 4.5: extra header dp_sn(4), dp_s_type(1), dp_s_mode(1), dp_s_ack(1)
DP_SEND_TYPE_ACTIVE = 0
DP_SEND_FOR_CLOUD_PANEL = 0
DP_SEND_WITH_RESPONSE = 0


def _wrap_dp_v45(seq: int, dp_id: int, dp_type: int, payload: bytes) -> bytes:
    """Обёртка 4.5: 7-byte header + dp_id, type, len(2), data."""
    data = bytearray()
    data += struct.pack(">IBBB", seq & 0xFFFFFFFF, DP_SEND_TYPE_ACTIVE, DP_SEND_FOR_CLOUD_PANEL, DP_SEND_WITH_RESPONSE)
    data += struct.pack(">BBH", dp_id, dp_type, len(payload))
    data += payload
    return bytes(data)


def build_dp_bool_v45(seq: int, dp_id: int, value: bool, session_key: bytes) -> list[bytes]:
    """Протокол 4.5: extra values + dp_id, type=BOOL, len=2, value."""
    payload = struct.pack(">B", 1 if value else 0)
    data = _wrap_dp_v45(seq, dp_id, 1, payload)
    return build_packet(seq, FUN_SENDER_DPS_V4, data, session_key, 5)


def build_dp_raw_v45(seq: int, dp_id: int, payload: bytes, session_key: bytes) -> list[bytes]:
    """Протокол 4.5: extra values + dp_id, type=RAW, len=2, payload."""
    data = _wrap_dp_v45(seq, dp_id, 0, payload)
    return build_packet(seq, FUN_SENDER_DPS_V4, data, session_key, 5)

def build_dp_value_v45(seq: int, dp_id: int, value: int, session_key: bytes) -> list[bytes]:
    """Протокол 4.5: extra values + dp_id, type=VALUE, len=2, value(4 bytes)."""
    payload = struct.pack(">I", int(value) & 0xFFFFFFFF)
    data = _wrap_dp_v45(seq, dp_id, 2, payload)
    return build_packet(seq, FUN_SENDER_DPS_V4, data, session_key, 5)



def build_device_status(seq: int, session_key: bytes) -> list[bytes]:
    return build_packet(seq, FUN_SENDER_DEVICE_STATUS, bytes(0), session_key, 5)


def find_notify_write(client: BleakClient) -> tuple[str | None, str | None]:
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
    return (notify_uuid or CHARACTERISTIC_NOTIFY_FALLBACK, write_uuid or CHARACTERISTIC_WRITE_FALLBACK)


def parse_response(
    buffer: bytearray,
    login_key: bytes,
    key_bytes: bytes,
    session_key: bytes | None = None,
) -> tuple[bytes | None, bytes | None, int, bytes]:
    """Разбирает ответ: (new_session_key, data, code, raw). session_key для flag 5."""
    if len(buffer) < 18:
        return (None, None, -1, buffer)

    security_flag = buffer[0]
    iv = buffer[1:17]
    encrypted = buffer[17:]

    key = (
        login_key
        if security_flag == 4
        else (session_key if security_flag == 5 and session_key else None)
    )
    if key is None:
        return (None, None, -1, buffer)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    raw = cipher.decrypt(encrypted)

    if len(raw) < 12:
        return (None, None, -1, buffer)

    seq_num, response_to, code, length = struct.unpack(">IIHH", raw[:12])
    data_end = 12 + length
    if len(raw) < data_end:
        return (None, None, -1, buffer)

    data = raw[12:data_end]

    if code == FUN_SENDER_DEVICE_INFO and len(data) >= 12:
        srand = data[6:12]
        session_key = hashlib.md5(key_bytes + srand).digest()
        return (session_key, data, code, raw)

    return (None, data, code, raw)


async def scan(address: str) -> BLEDevice | None:
    LOG.info("Сканирование...")
    devices = await BleakScanner.discover(timeout=10.0)
    addr = address.upper().replace("-", ":")
    for d in devices:
        if d.address.upper().replace("-", ":") == addr:
            return d
    return None


async def run(
    address: str,
    uuid: str,
    local_key: str,
    device_id: str,
    do_lock: bool,
    do_unlock: bool,
    do_state: bool,
    dp_lock: int,
    dp_unlock: int,
    unlock_format: str = "bool",
    unlock_value: int = 1,
) -> bool:
    address = address.upper().replace("-", ":")
    key_bytes = local_key[:6].encode()
    login_key = hashlib.md5(key_bytes).digest()

    device = await scan(address)
    if not device:
        LOG.error("Устройство не найдено")
        return False

    input_buffer = bytearray()
    expected_len = 0
    expected_packet = 0
    response_event = asyncio.Event()
    response_data: list[bytes] = []
    session_key: bytes | None = None

    def on_notify(_: int, data: bytearray):
        nonlocal input_buffer, expected_len, expected_packet, session_key
        data = bytes(data)
        response_data.append(data)
        pos = 0
        try:
            pkt_num, pos = unpack_varint(data, pos)
            if pkt_num == 0:
                expected_len, pos = unpack_varint(data, pos)
                pos += 1  # version byte
                input_buffer = bytearray()
            input_buffer += data[pos:]
            expected_packet = pkt_num + 1

            if len(input_buffer) >= expected_len:
                sk, d, code, _ = parse_response(
            input_buffer, login_key, key_bytes, session_key
        )
                if sk is not None:
                    session_key = sk
                    LOG.info("Device Info: session_key получен")
                if code == FUN_SENDER_PAIR and d and len(d) >= 1:
                    LOG.info("Pair: результат=%s", d[0])
                if code == FUN_SENDER_DEVICE_STATUS and d:
                    LOG.info("Device Status: %s", d.hex())
                response_event.set()
        except Exception as e:
            LOG.debug("Parse: %s", e)

    LOG.info("Подключение...")
    try:
        async with BleakClient(device, timeout=20.0) as client:
            if not client.is_connected:
                return False

            notify_char, write_char = find_notify_write(client)
            await client.start_notify(notify_char, on_notify)
            await asyncio.sleep(1.0)

            def send_packets(packets: list[bytes]):
                for p in packets:
                    asyncio.create_task(client.write_gatt_char(write_char, p, response=False))

            seq = 1

            # 1. Device Info
            LOG.info("Device Info...")
            response_event.clear()
            for pkt in build_device_info(seq, login_key):
                await client.write_gatt_char(write_char, pkt, response=False)
                await asyncio.sleep(0.2)
            try:
                await asyncio.wait_for(response_event.wait(), RESPONSE_TIMEOUT)
            except asyncio.TimeoutError:
                LOG.error("Таймаут Device Info")
                return False

            if session_key is None:
                LOG.error("Не удалось получить session_key")
                return False

            seq += 1

            # 2. Pair
            LOG.info("Pair...")
            response_event.clear()
            for pkt in build_pairing(seq, uuid, local_key, device_id, session_key):
                await client.write_gatt_char(write_char, pkt, response=False)
                await asyncio.sleep(0.2)
            try:
                await asyncio.wait_for(response_event.wait(), RESPONSE_TIMEOUT)
            except asyncio.TimeoutError:
                LOG.error("Таймаут Pair")
                return False

            seq += 1

            # 3. Lock / Unlock / State
            if do_state:
                LOG.info("Запрос статуса...")
                response_event.clear()
                for pkt in build_device_status(seq, session_key):
                    await client.write_gatt_char(write_char, pkt, response=False)
                    await asyncio.sleep(0.2)
                try:
                    await asyncio.wait_for(response_event.wait(), RESPONSE_TIMEOUT)
                except asyncio.TimeoutError:
                    LOG.warning("Таймаут Device Status")

            if do_lock:
                LOG.info("Закрытие замка (DP %d, bool)...", dp_lock)
                for pkt in build_dp_bool_v4(seq, dp_lock, True, session_key):
                    await client.write_gatt_char(write_char, pkt, response=False)
                    await asyncio.sleep(0.2)
                seq += 1
                await asyncio.sleep(2.0)

            if do_unlock:
                # Протокол v4 / v4.5
                unlock_fmt = unlock_format
                if unlock_fmt == "raw":
                    LOG.info("Открытие (DP %d, v4 raw 0x01 0x01)...", dp_unlock)
                    pkts = build_dp_raw_v4(seq, dp_unlock, b"\x01\x01", session_key)
                elif unlock_fmt == "value":
                    LOG.info("Открытие (DP %d, v4 value=%d)...", dp_unlock, unlock_value)
                    pkts = build_dp_value_v4(seq, dp_unlock, unlock_value, session_key)
                elif unlock_fmt == "raw_v45":
                    LOG.info("Открытие (DP %d, v4.5 raw 0x01 0x01)...", dp_unlock)
                    pkts = build_dp_raw_v45(seq, dp_unlock, b"\x01\x01", session_key)
                elif unlock_fmt == "value_v45":
                    LOG.info("Открытие (DP %d, v4.5 value=%d)...", dp_unlock, unlock_value)
                    pkts = build_dp_value_v45(seq, dp_unlock, unlock_value, session_key)
                elif unlock_fmt == "bool_v45":
                    LOG.info("Открытие (DP %d, v4.5 bool)...", dp_unlock)
                    pkts = build_dp_bool_v45(seq, dp_unlock, True, session_key)
                else:
                    LOG.info("Открытие (DP %d, v4 bool)...", dp_unlock)
                    pkts = build_dp_bool_v4(seq, dp_unlock, True, session_key)
                for pkt in pkts:
                    await client.write_gatt_char(write_char, pkt, response=False)
                    await asyncio.sleep(0.2)
                seq += 1
                await asyncio.sleep(2.0)

            LOG.info("Готово.")
            return True

    except Exception as e:
        LOG.exception("Ошибка: %s", e)
        return False


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
    parser = argparse.ArgumentParser(description="Тест lock/unlock Tuya BLE замка")
    parser.add_argument("address", help="BLE адрес")
    parser.add_argument("--uuid", help="UUID из облака")
    parser.add_argument("--local-key", help="Local Key из облака")
    parser.add_argument("--device-id", help="Device ID из облака")
    parser.add_argument("--config", default="/config", help="Путь к config HA")
    parser.add_argument("--lock", action="store_true", help="Закрыть замок")
    parser.add_argument("--unlock", action="store_true", help="Открыть замок")
    parser.add_argument("--state", action="store_true", help="Запросить статус")
    parser.add_argument(
        "--dp-lock", type=int, default=46, help="DP ID закрытия (default: 46)"
    )
    parser.add_argument(
        "--dp-unlock", type=int, default=6, help="DP ID открытия (default: 6)"
    )
    parser.add_argument(
        "--unlock-format",
        choices=["raw", "bool", "value", "raw_v45", "bool_v45", "value_v45"],
        default="bool_v45",
        help="Формат unlock: bool_v45 (default), value_v45, raw_v45, bool, value, raw",
    )
    parser.add_argument(
        "--unlock-value",
        type=int,
        default=1,
        help="Значение для unlock-format value/value_v45 (default: 1)",
    )
    args = parser.parse_args()

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
        print("Укажите --uuid, --local-key, --device-id или создайте devices.json")
        sys.exit(1)

    if not args.lock and not args.unlock and not args.state:
        args.state = True
        print("Не указана команда, выполняю --state")

    ok = asyncio.run(
        run(
            args.address,
            creds["uuid"],
            creds["local_key"],
            creds["device_id"],
            args.lock,
            args.unlock,
            args.state,
            args.dp_lock,
            args.dp_unlock,
            args.unlock_format,
            args.unlock_value,
        )
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
