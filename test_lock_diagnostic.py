#!/usr/bin/env python3
"""
Диагностический скрипт для Tuya BLE замка A1 Ultra-JM.

Поддерживает сервис 0000FD50 и характеристики 00000001/00000002.

Запуск (нужен BLE-адаптер на том же компьютере):

  1. Установка зависимостей:
     pip install bleak pycryptodome

  2. Запуск с учётными данными из облака:
     python test_lock_diagnostic.py DC:23:51:E8:C5:91 --uuid f3b492ca7766b861 --local-key "06p.X3iM]/TG^&y_" --device-id bfdb9fbvasxgu8xf

  3. Или из devices.json (укажите путь к config HA):
     python test_lock_diagnostic.py DC:23:51:E8:C5:91 --config D:\\path\\to\\config

  HA в Docker: скопируйте скрипт в custom_components, установите bleak/pycryptodome
  в контейнере и запустите внутри контейнера.
"""

from __future__ import annotations

import os
import sys

# Не даём папке скрипта подменять stdlib (select.py в tuya_local_ble)
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
import sys

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


# Fallback для A1 Ultra-JM (сервис 0000FD50, характеристики 00000001/00000002)
CHARACTERISTIC_NOTIFY_FALLBACK = "00000002-0000-1001-8001-00805f9b07d0"
CHARACTERISTIC_WRITE_FALLBACK = "00000001-0000-1001-8001-00805f9b07d0"
GATT_MTU = 20
RESPONSE_TIMEOUT = 30

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


def build_device_info_packet(
    seq_num: int,
    local_key: bytes,
    protocol_version: int = 4,
) -> list[bytes]:
    """Собирает пакет FUN_SENDER_DEVICE_INFO (код 0x0000). A1 Ultra-JM: proto 4, data [0,0xF3]."""
    login_key = hashlib.md5(local_key).digest()
    code = 0x0000
    data = bytearray([0, 0xF3]) if protocol_version >= 4 else bytes(0)
    response_to = 0

    raw = bytearray()
    raw += struct.pack(">IIHH", seq_num, response_to, code, len(data))
    raw += data
    raw += struct.pack(">H", calc_crc16(raw))
    while len(raw) % 16:
        raw.append(0)

    iv = secrets.token_bytes(16)
    cipher = AES.new(login_key, AES.MODE_CBC, iv)
    encrypted = bytes([4]) + iv + cipher.encrypt(raw)

    packets = []
    pos = 0
    packet_num = 0
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


TUYA_SERVICE_IDS = ("0000a201", "0000fd50", "07d0")  # A1 Ultra-JM использует 0000FD50


def find_notify_write_characteristics(client: BleakClient) -> tuple[str | None, str | None]:
    """Ищет Notify и Write только в сервисе Tuya (FD50/A201), не в стандартном GATT."""
    notify_uuid = None
    write_uuid = None
    for service in client.services:
        su = service.uuid.lower()
        if not any(tid in su for tid in TUYA_SERVICE_IDS):
            continue  # Пропуск не-Tuya сервисов (иначе возьмёт 00002a05 и т.п.)
        for char in service.characteristics:
            props = {p.lower() for p in char.properties}
            if not notify_uuid and {"notify", "indicate"} & props:
                notify_uuid = char.uuid
            if not write_uuid and {"write", "write-without-response"} & props:
                write_uuid = char.uuid
            if notify_uuid and write_uuid:
                return (notify_uuid, write_uuid)
    return (notify_uuid, write_uuid)


async def scan_for_device(address: str) -> BLEDevice | None:
    """Сканирует и возвращает устройство по адресу."""
    LOG.info("Сканирование BLE...")
    devices = await BleakScanner.discover(timeout=10.0)
    addr_upper = address.upper().replace("-", ":")
    for d in devices:
        if d.address.upper().replace("-", ":") == addr_upper:
            LOG.info("Найдено: %s RSSI=%s", d.address, getattr(d, "rssi", "?"))
            return d
    LOG.warning("Устройство %s не найдено", address)
    return None


async def run_diagnostic(
    address: str,
    uuid: str,
    local_key: str,
    device_id: str,
    category: str,
    product_id: str,
    protocol_version: int = 2,
) -> bool:
    address = address.upper().replace("-", ":")
    key_bytes = local_key[:6].encode()

    device = await scan_for_device(address)
    if not device:
        return False

    response_received = asyncio.Event()
    received_data: list[bytes] = []

    def notification_handler(handle: int, data: bytearray):
        LOG.info("Получены данные: %s (%d байт)", data.hex(), len(data))
        received_data.append(bytes(data))
        response_received.set()

    LOG.info("Подключение к %s...", address)
    try:
        async with BleakClient(device, timeout=20.0) as client:
            if not client.is_connected:
                LOG.error("Не удалось подключиться")
                return False

            notify_char, write_char = find_notify_write_characteristics(client)
            if not notify_char or not write_char:
                notify_char = notify_char or CHARACTERISTIC_NOTIFY_FALLBACK
                write_char = write_char or CHARACTERISTIC_WRITE_FALLBACK
            LOG.info("Notify=%s Write=%s", notify_char, write_char)
            LOG.info("Протокол версия %d", protocol_version)

            LOG.info("Подписка на уведомления...")
            await client.start_notify(notify_char, notification_handler)
            await asyncio.sleep(1.0)  # Пауза после подписки, замок должен успеть инициализироваться

            seq_num = 1
            packets = build_device_info_packet(seq_num, key_bytes, protocol_version)
            LOG.info("Отправка Device Info (%d пакетов)...", len(packets))

            for i, pkt in enumerate(packets):
                await client.write_gatt_char(write_char, pkt, response=False)
                LOG.debug("Пакет %d отправлен: %s", i + 1, pkt.hex())
                await asyncio.sleep(0.2)  # Больше пауза между пакетами для медленного замка

            LOG.info("Ожидание ответа (до %d сек)...", RESPONSE_TIMEOUT)
            try:
                await asyncio.wait_for(response_received.wait(), RESPONSE_TIMEOUT)
                LOG.info("Ответ получен! Связь работает.")
                return True
            except asyncio.TimeoutError:
                LOG.error("Таймаут: замок не ответил за %d сек.", RESPONSE_TIMEOUT)
                return False

    except Exception as e:
        LOG.exception("Ошибка: %s", e)
        return False


def load_credentials_from_file(address: str, config_dir: str) -> dict | None:
    path = os.path.join(config_dir, "tuya_local_ble", "devices.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    addr_norm = address.upper().replace("-", ":")
    for k, v in data.items():
        if k.upper().replace("-", ":") == addr_norm:
            return v
    return None


def main():
    parser = argparse.ArgumentParser(description="Диагностика Tuya BLE замка")
    parser.add_argument("address", help="BLE адрес замка (например DC:23:51:E8:C5:91)")
    parser.add_argument("--uuid", help="UUID из облака Tuya")
    parser.add_argument("--local-key", help="Local Key из облака Tuya")
    parser.add_argument("--device-id", help="Device ID из облака Tuya")
    parser.add_argument("--category", default="jtmspro", help="Категория (default: jtmspro)")
    parser.add_argument("--product-id", default="hc7n0urm", help="Product ID (default: hc7n0urm)")
    parser.add_argument(
        "--config",
        default=os.environ.get("HOMEASSISTANT_CONFIG_PATH", "/config"),
        help="Путь к config Home Assistant",
    )
    parser.add_argument(
        "--protocol",
        type=int,
        default=4,
        choices=[2, 3, 4],
        help="Версия протокола Tuya BLE (A1 Ultra-JM: 4, default: 4)",
    )
    args = parser.parse_args()

    creds = None
    if args.uuid and args.local_key and args.device_id:
        creds = {
            "uuid": args.uuid,
            "local_key": args.local_key,
            "device_id": args.device_id,
            "category": args.category or "jtmspro",
            "product_id": args.product_id or "hc7n0urm",
        }
    else:
        creds = load_credentials_from_file(args.address, args.config)
        if not creds:
            print("Учётные данные не найдены.")
            print("Укажите --uuid, --local-key, --device-id или создайте config/tuya_local_ble/devices.json")
            sys.exit(1)

    success = asyncio.run(
        run_diagnostic(
            args.address,
            creds["uuid"],
            creds["local_key"],
            creds["device_id"],
            creds.get("category", "jtmspro"),
            creds.get("product_id", "hc7n0urm"),
            args.protocol,
        )
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
