from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
from collections.abc import Callable
from struct import pack, unpack

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakDBusError
from bleak_retry_connector import BLEAK_BACKOFF_TIME
from bleak_retry_connector import BLEAK_RETRY_EXCEPTIONS
from bleak_retry_connector import (
    BleakClientWithServiceCache,
    BleakError,
    BleakNotFoundError,
    establish_connection,
)
from Crypto.Cipher import AES

from .const import (
    CHARACTERISTIC_NOTIFY,
    CHARACTERISTIC_WRITE,
    GATT_MTU,
    HANDSHAKE_RESPONSE_TIMEOUT,
    MANUFACTURER_DATA_ID,
    RESPONSE_WAIT_TIMEOUT,
    SERVICE_UUID,
    TuyaBLECode,
    TuyaBLEDataPointType,
)
from .exceptions import (
    TuyaBLECommandError,
    TuyaBLEDataCRCError,
    TuyaBLEDataFormatError,
    TuyaBLEDataLengthError,
    TuyaBLEDeviceError,
    TuyaBLEEnumValueError,
)
from .manager import AbstaractTuyaBLEDeviceManager, TuyaBLEDeviceCredentials

_LOGGER = logging.getLogger(__name__)


BLEAK_EXCEPTIONS = (*BLEAK_RETRY_EXCEPTIONS, OSError)

HC7_PRODUCT_ID = "hc7n0urm"
HC7_CONNECT_ATTEMPTS = 8
HC7_NOTIFY_SETTLE_DELAY = 0.35
HC7_NOTIFY_RETRY_DELAY = 0.8
# ESP32 Bluetooth proxies add notify latency; allow a longer handshake window.
HC7_HANDSHAKE_RESPONSE_TIMEOUT = 45
# Pause after device-info before pair so session_key is stable through the proxy.
HC7_HANDSHAKE_PAIR_DELAY = 0.75
HC7_PAIR_ATTEMPTS = 3
HC7_PAIR_RETRY_DELAY = 0.6
# hc7n0urm can take 20+ s to ack V4 lock/unlock on a loaded BLE link.
HC7_COMMAND_RESPONSE_TIMEOUT = 25
HC7_PREPARE_SETTLE_DELAY = 0.3
HC7_NOTIFY_DEDUPE_TTL = 60.0


class TuyaBLEDataPoint:
    def __init__(
        self,
        owner: TuyaBLEDataPoints,
        id: int,
        timestamp: float,
        flags: int,
        type: TuyaBLEDataPointType,
        value: bytes | bool | int | str,
    ) -> None:
        self._owner = owner
        self._id = id
        self._value = value
        self._changed_by_device = False
        self._update_from_device(timestamp, flags, type, value)

    def _update_from_device(
        self,
        timestamp: float,
        flags: int,
        type: TuyaBLEDataPointType,
        value: bytes | bool | int | str,
    ) -> None:
        self._timestamp = timestamp
        self._flags = flags
        self._type = type
        self._changed_by_device = self._value != value
        self._value = value

    def _get_value(self) -> bytes:
        match self._type:
            case TuyaBLEDataPointType.DT_RAW | TuyaBLEDataPointType.DT_BITMAP:
                return self._value
            case TuyaBLEDataPointType.DT_BOOL:
                return pack(">B", 1 if self._value else 0)
            case TuyaBLEDataPointType.DT_VALUE:
                return pack(">i", self._value)
            case TuyaBLEDataPointType.DT_ENUM:
                if self._value > 0xFFFF:
                    return pack(">I", self._value)
                elif self._value > 0xFF:
                    return pack(">H", self._value)
                else:
                    return pack(">B", self._value)
            case TuyaBLEDataPointType.DT_STRING:
                return self._value.encode()

    @property
    def id(self) -> int:
        return self._id

    @property
    def timestamp(self) -> float:
        return self._timestamp

    @property
    def flags(self) -> int:
        return self._flags

    @property
    def type(self) -> TuyaBLEDataPointType:
        return self._type

    @property
    def value(self) -> bytes | bool | int | str:
        return self._value

    @property
    def changed_by_device(self) -> bool:
        return self._changed_by_device

    async def set_value(self, value: bytes | bool | int | str) -> None:
        match self._type:
            case TuyaBLEDataPointType.DT_RAW | TuyaBLEDataPointType.DT_BITMAP:
                self._value = bytes(value)
            case TuyaBLEDataPointType.DT_BOOL:
                self._value = bool(value)
            case TuyaBLEDataPointType.DT_VALUE:
                self._value = int(value)
            case TuyaBLEDataPointType.DT_ENUM:
                value = int(value)
                if value >= 0:
                    self._value = value
                else:
                    raise TuyaBLEEnumValueError()

            case TuyaBLEDataPointType.DT_STRING:
                self._value = str(value)

        self._changed_by_device = False
        await self._owner._update_from_user(self._id)


class TuyaBLEDataPoints:
    def __init__(self, owner: TuyaBLEDevice) -> None:
        self._owner = owner
        self._datapoints: dict[int, TuyaBLEDataPoint] = {}
        self._update_started: int = 0
        self._updated_datapoints: list[int] = []

    def __len__(self) -> int:
        return len(self._datapoints)

    def __getitem__(self, key: int) -> TuyaBLEDataPoint | None:
        return self._datapoints.get(key)

    def has_id(self, id: int, type: TuyaBLEDataPointType | None = None) -> bool:
        return (id in self._datapoints) and (
            (type is None) or (self._datapoints[id].type == type)
        )

    def get_or_create(
        self,
        id: int,
        type: TuyaBLEDataPointType,
        value: bytes | bool | int | str | None = None,
    ) -> TuyaBLEDataPoint:
        datapoint = self._datapoints.get(id)
        if datapoint:
            return datapoint
        datapoint = TuyaBLEDataPoint(self, id, time.time(), 0, type, value)
        self._datapoints[id] = datapoint
        return datapoint

    def begin_update(self) -> None:
        self._update_started += 1

    async def end_update(self) -> None:
        if self._update_started > 0:
            self._update_started -= 1
            if self._update_started == 0 and len(self._updated_datapoints) > 0:
                await self._owner._send_datapoints(self._updated_datapoints)
                self._updated_datapoints = []

    def _update_from_device(
        self,
        dp_id: int,
        timestamp: float,
        flags: int,
        type: TuyaBLEDataPointType,
        value: bytes | bool | int | str,
    ) -> None:
        dp = self._datapoints.get(dp_id)
        if dp:
            dp._update_from_device(timestamp, flags, type, value)
        else:
            self._datapoints[dp_id] = TuyaBLEDataPoint(
                self, dp_id, timestamp, flags, type, value
            )

    async def _update_from_user(self, dp_id: int) -> None:
        if self._update_started > 0:
            if dp_id in self._updated_datapoints:
                self._updated_datapoints.remove(dp_id)
            self._updated_datapoints.append(dp_id)
        else:
            await self._owner._send_datapoints([dp_id])


global_connect_lock = asyncio.Lock()


class TuyaBLEDevice:
    def __init__(
        self,
        device_manager: AbstaractTuyaBLEDeviceManager,
        ble_device: BLEDevice,
        advertisement_data: AdvertisementData | None = None,
    ) -> None:
        """Init the TuyaBLE."""
        self._device_manager = device_manager
        self._device_info: TuyaBLEDeviceCredentials | None = None
        self._ble_device = ble_device
        self._advertisement_data = advertisement_data
        self._operation_lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._client: BleakClientWithServiceCache | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._expected_disconnect = False
        self._connected_callbacks: list[Callable[[], None]] = []
        self._callbacks: list[Callable[[list[TuyaBLEDataPoint]], None]] = []
        self._disconnected_callbacks: list[Callable[[], None]] = []
        self._current_seq_num = 1
        self._seq_num_lock = asyncio.Lock()

        self._is_bound = False
        self._flags = 0
        self._protocol_version = 2

        self._device_version: str = ""
        self._protocol_version_str: str = ""
        self._hardware_version: str = ""

        self._auth_key: bytes | None = None
        self._local_key: bytes | None = None
        self._login_key: bytes | None = None
        self._session_key: bytes | None = None
        self._unlock_token: str = ""
        self._hc7_unlock_prepared = False
        # Deduplicate fully decoded device requests by sequence number. Raw GATT
        # fragments must never be dropped: every replay still needs an ACK.
        self._hc7_received_requests: dict[tuple[int, int], float] = {}
        # One best-effort ACK task per device request. A notification replay
        # burst must not create an unbounded number of failing GATT writes.
        self._pending_responses: set[tuple[int, int]] = set()

        self._is_paired = False

        self._input_buffer: bytearray | None = None
        self._input_expected_packet_num = 0
        self._input_expected_length = 0
        self._input_expected_responses: dict[int,
                                             asyncio.Future[int] | None] = {}
        # self._input_future: asyncio.Future[int] | None = None

        self._datapoints = TuyaBLEDataPoints(self)

    def set_ble_device_and_advertisement_data(
        self, ble_device: BLEDevice, advertisement_data: AdvertisementData
    ) -> None:
        """Set the ble device."""
        self._ble_device = ble_device
        self._advertisement_data = advertisement_data

    async def initialize(self) -> None:
        _LOGGER.debug("%s: Initializing", self.address)
        if await self._update_device_info():
            self._decode_advertisement_data()
            
    def _build_pairing_request(self) -> bytes:
        result = bytearray()

        result += self._device_info.uuid.encode()
        result += self._local_key
        result += self._device_info.device_id.encode()
        for _ in range(44 - len(result)):
            result += b"\x00"

        return result

    async def pair(self) -> None:
        """
        _LOGGER.debug("%s: Sending pairing request: %s",
            self.address, data.hex()
        )
        """
        await self._send_packet(
            TuyaBLECode.FUN_SENDER_PAIR, self._build_pairing_request()
        )

    async def update(self) -> bool:
        _LOGGER.debug("%s: Updating", self.address)
        timeout = (
            HC7_COMMAND_RESPONSE_TIMEOUT
            if self.product_id == HC7_PRODUCT_ID
            else RESPONSE_WAIT_TIMEOUT
        )
        return await self._send_packet(
            TuyaBLECode.FUN_SENDER_DEVICE_STATUS, bytes(), True, timeout
        )

    async def _update_device_info(self) -> bool:
        if self._device_info is None:
            if self._device_manager:
                self._device_info = await self._device_manager.get_device_credentials(
                    self._ble_device.address, False
                )
            if self._device_info:
                self._local_key = self._device_info.local_key[:6].encode()
                self._login_key = hashlib.md5(self._local_key).digest()
                self._unlock_token = getattr(self._device_info, "unlock_token", "") or ""

        return self._device_info is not None

    def _decode_advertisement_data(self) -> None:
        raw_product_id: bytes | None = None
        # raw_product_key: bytes | None = None
        raw_uuid: bytes | None = None
        if self._advertisement_data:
            if self._advertisement_data.service_data:
                service_data = self._advertisement_data.service_data.get(
                    SERVICE_UUID)
                if service_data and len(service_data) > 1:
                    match service_data[0]:
                        case 0:
                            raw_product_id = service_data[1:]
                        # case 1:
                        #    raw_product_key = service_data[1:]

            if self._advertisement_data.manufacturer_data:
                manufacturer_data = self._advertisement_data.manufacturer_data.get(
                    MANUFACTURER_DATA_ID
                )
                if manufacturer_data and len(manufacturer_data) > 6:
                    self._is_bound = (manufacturer_data[0] & 0x80) != 0
                    self._protocol_version = manufacturer_data[1]
                    raw_uuid = manufacturer_data[6:]
                    if raw_product_id:
                        key = hashlib.md5(raw_product_id).digest()
                        cipher = AES.new(key, AES.MODE_CBC, key)
                        raw_uuid = cipher.decrypt(raw_uuid)
                        self._uuid = raw_uuid.decode("utf-8")

    @property
    def address(self) -> str:
        """Return the address."""
        return self._ble_device.address

    @property
    def name(self) -> str:
        """Get the name of the device."""
        if self._device_info:
            return self._device_info.device_name
        else:
            return self._ble_device.name or self._ble_device.address

    @property
    def rssi(self) -> int | None:
        """Get the rssi of the device."""
        if self._advertisement_data:
            return self._advertisement_data.rssi
        return None

    @property
    def uuid(self) -> str:
        if self._device_info is not None:
            return self._device_info.uuid
        else:
            return ""

    @property
    def local_key(self) -> str:
        if self._device_info is not None:
            return self._device_info.local_key
        else:
            return ""

    @property
    def category(self) -> str:
        if self._device_info is not None:
            return self._device_info.category
        else:
            return ""

    @property
    def device_id(self) -> str:
        if self._device_info is not None:
            return self._device_info.device_id
        else:
            return ""

    @property
    def product_id(self) -> str:
        if self._device_info is not None:
            return self._device_info.product_id
        else:
            return ""

    @property
    def product_model(self) -> str:
        if self._device_info is not None:
            return self._device_info.product_model
        else:
            return ""

    @property
    def product_name(self) -> str:
        if self._device_info is not None:
            return self._device_info.product_name
        else:
            return ""

    @property
    def device_version(self) -> str:
        return self._device_version

    @property
    def hardware_version(self) -> str:
        return self._hardware_version

    @property
    def protocol_version(self) -> str:
        return self._protocol_version_str

    @property
    def firmware_version(self) -> str | None:
        """Return a displayable version only after DEVICE_INFO arrives."""
        if self._device_version and self._protocol_version_str:
            return f"{self._device_version} (protocol {self._protocol_version_str})"
        if self._device_version:
            return self._device_version
        if self._protocol_version_str:
            return f"protocol {self._protocol_version_str}"
        return None

    @property
    def datapoints(self) -> TuyaBLEDataPoints:
        """Get datapoints exposed by device."""
        return self._datapoints

    def get_or_create_datapoint(
        self,
        id: int,
        type: TuyaBLEDataPointType,
        value: bytes | bool | int | str | None = None,
    ) -> TuyaBLEDataPoint:
        """Get datapoints exposed by device."""

    def _fire_connected_callbacks(self) -> None:
        """Fire the callbacks."""
        for callback in self._connected_callbacks:
            callback()

    def register_connected_callback(
        self, callback: Callable[[], None]
    ) -> Callable[[], None]:
        """Register a callback to be called when device disconnected."""

        def unregister_callback() -> None:
            self._connected_callbacks.remove(callback)

        self._connected_callbacks.append(callback)
        return unregister_callback

    def _fire_callbacks(self, datapoints: list[TuyaBLEDataPoint]) -> None:
        """Fire the callbacks."""
        for callback in self._callbacks:
            callback(datapoints)

    def register_callback(
        self,
        callback: Callable[[list[TuyaBLEDataPoint]], None],
    ) -> Callable[[], None]:
        """Register a callback to be called when the state changes."""

        def unregister_callback() -> None:
            self._callbacks.remove(callback)

        self._callbacks.append(callback)
        return unregister_callback

    def _fire_disconnected_callbacks(self) -> None:
        """Fire the callbacks."""
        for callback in self._disconnected_callbacks:
            callback()

    def register_disconnected_callback(
        self, callback: Callable[[], None]
    ) -> Callable[[], None]:
        """Register a callback to be called when device disconnected."""

        def unregister_callback() -> None:
            self._disconnected_callbacks.remove(callback)

        self._disconnected_callbacks.append(callback)
        return unregister_callback

    async def start(self):
        """Start the TuyaBLE."""
        _LOGGER.debug("%s: Starting...", self.address)
        # await self._send_packet()

    async def stop(self) -> None:
        """Stop the TuyaBLE."""
        _LOGGER.debug("%s: Stop", self.address)
        await self._execute_disconnect()

    def _fail_pending_responses(self, reason: str) -> None:
        """Fail requests belonging to a closed BLE session."""
        for seq_num, future in list(self._input_expected_responses.items()):
            self._input_expected_responses.pop(seq_num, None)
            if future is not None and not future.done():
                future.set_exception(BleakError(reason))

    def _disconnected(self, client: BleakClientWithServiceCache) -> None:
        """Disconnected callback."""
        # A delayed callback from an older client must not tear down a newly
        # established session.
        if self._client is not None and client is not self._client:
            _LOGGER.debug("%s: Ignoring stale disconnect callback", self.address)
            return
        was_paired = self._is_paired
        self._is_paired = False
        self._hc7_unlock_prepared = False
        self._hc7_received_requests.clear()
        self._clean_input()
        self._fail_pending_responses("BLE device disconnected")
        self._fire_disconnected_callbacks()
        if self._expected_disconnect:
            _LOGGER.debug(
                "%s: Disconnected from device; RSSI: %s",
                self.address,
                self.rssi,
            )
            return
        self._client = None
        _LOGGER.debug(
            "%s: Device unexpectedly disconnected; RSSI: %s",
            self.address,
            self.rssi,
        )
        if was_paired:
            _LOGGER.debug(
                "%s: Scheduling reconnect; RSSI: %s",
                self.address,
                self.rssi,
            )
            self._schedule_reconnect()

    def _disconnect(self) -> None:
        """Disconnect from device."""
        asyncio.create_task(self._execute_timed_disconnect())

    async def _execute_timed_disconnect(self) -> None:
        """Execute timed disconnection."""
        _LOGGER.debug("%s: Disconnecting", self.address)
        await self._execute_disconnect()

    async def _execute_disconnect(self) -> None:
        """Execute disconnection."""
        async with self._connect_lock:
            self._expected_disconnect = True
            await self._cleanup_failed_connection(self._client)
        self._is_paired = False
        self._hc7_unlock_prepared = False
        self._hc7_received_requests.clear()
        self._clean_input()
        self._fail_pending_responses("BLE integration stopped")
        async with self._seq_num_lock:
            self._current_seq_num = 1

    async def _cleanup_failed_connection(
        self, client: BleakClientWithServiceCache | None
    ) -> None:
        """Close a failed BLE session without scheduling a reconnect task."""
        if self._client is client:
            self._client = None
        self._is_paired = False
        self._hc7_unlock_prepared = False
        self._clean_input()
        if client is None:
            return
        expected_disconnect = self._expected_disconnect
        self._expected_disconnect = True
        try:
            if client.is_connected:
                await client.disconnect()
        except BLEAK_EXCEPTIONS:
            _LOGGER.debug("%s: cleanup disconnect failed", self.address, exc_info=True)
        except Exception:
            _LOGGER.debug("%s: cleanup disconnect failed", self.address, exc_info=True)
        finally:
            self._expected_disconnect = expected_disconnect

    async def _start_notify_with_retry(
        self, client: BleakClientWithServiceCache
    ) -> bool:
        """Start notifications, giving slow battery locks a settle delay."""
        if self.product_id == HC7_PRODUCT_ID:
            await asyncio.sleep(HC7_NOTIFY_SETTLE_DELAY)
        try:
            await client.start_notify(
                CHARACTERISTIC_NOTIFY,
                lambda sender, data: self._notification_handler(sender, data, client),
            )
            return True
        except BleakDBusError as err:
            # BlueZ: notify already enabled (race). Old callback may be stale:
            # stop and subscribe again so notifications reach this handler.
            err_s = str(err).lower()
            if (
                ("notpermitted" in err_s and "acquired" in err_s)
                or "notify acquired" in err_s
            ):
                _LOGGER.debug(
                    "%s: notify busy; re-subscribing RSSI: %s",
                    self.address,
                    self.rssi,
                )
                try:
                    await client.stop_notify(CHARACTERISTIC_NOTIFY)
                    await asyncio.sleep(0.2)
                except (BleakDBusError, BleakError, OSError):
                    pass
                try:
                    await client.start_notify(
                        CHARACTERISTIC_NOTIFY,
                        lambda sender, data: self._notification_handler(
                            sender, data, client
                        ),
                    )
                    return True
                except BleakDBusError as err_re:
                    err_re_s = str(err_re).lower()
                    if (
                        ("notpermitted" in err_re_s and "acquired" in err_re_s)
                        or "notify acquired" in err_re_s
                    ):
                        _LOGGER.warning(
                            "%s: notify still acquired after stop; rebuilding BLE session; RSSI: %s",
                            self.address,
                            self.rssi,
                        )
                    else:
                        _LOGGER.debug(
                            "%s: notify re-subscribe failed",
                            self.address,
                            exc_info=True,
                        )
                except Exception:
                    _LOGGER.debug(
                        "%s: notify re-subscribe failed",
                        self.address,
                        exc_info=True,
                    )
            else:
                _LOGGER.debug(
                    "%s: start_notify failed",
                    self.address,
                    exc_info=True,
                )
        except BLEAK_EXCEPTIONS:
            _LOGGER.debug(
                "%s: start_notify failed",
                self.address,
                exc_info=True,
            )
        except Exception:
            _LOGGER.debug(
                "%s: start_notify failed",
                self.address,
                exc_info=True,
            )
        return False

    async def _ensure_connected(self) -> None:
        """Ensure connection to device is established."""
        global global_connect_lock
        if self._expected_disconnect:
            return
        if self._connect_lock.locked():
            _LOGGER.debug(
                "%s: Connection already in progress,"
                " waiting for it to complete; RSSI: %s",
                self.address,
                self.rssi,
            )
        if self._client and self._client.is_connected and self._is_paired:
            return
        async with self._connect_lock:
            # Check again while holding the lock
            await asyncio.sleep(0.01)
            if self._client and self._client.is_connected and self._is_paired:
                return
            attempts_count = (
                HC7_CONNECT_ATTEMPTS if self.product_id == HC7_PRODUCT_ID else 100
            )
            while attempts_count > 0:
                attempts_count -= 1
                async with self._seq_num_lock:
                    self._current_seq_num = 1
                if attempts_count == 0:
                    _LOGGER.error(
                        "%s: Connecting, all attempts failed; RSSI: %s",
                        self.address,
                        self.rssi,
                    )
                    raise BleakNotFoundError()
                try:
                    async with global_connect_lock:
                        _LOGGER.debug(
                            "%s: Connecting; RSSI: %s", self.address, self.rssi
                        )
                        client = await establish_connection(
                            BleakClientWithServiceCache,
                            self._ble_device,
                            self.address,
                            self._disconnected,
                            use_services_cache=True,
                            ble_device_callback=lambda: self._ble_device,
                        )
                except BleakNotFoundError:
                    _LOGGER.error(
                        "%s: device not found, not in range, or poor RSSI: %s",
                        self.address,
                        self.rssi,
                        exc_info=True,
                    )
                    continue
                except BLEAK_EXCEPTIONS:
                    _LOGGER.debug(
                        "%s: communication failed", self.address, exc_info=True
                    )
                    continue
                except:
                    _LOGGER.debug("%s: unexpected error",
                                  self.address, exc_info=True)
                    continue

                if client and client.is_connected:
                    _LOGGER.debug("%s: Connected; RSSI: %s",
                                  self.address, self.rssi)
                    self._client = client
                    # New BLE session: must start at seq 1 and clear GATT reassembly,
                    # or the lock may ignore the first command after a failed attempt.
                    async with self._seq_num_lock:
                        self._current_seq_num = 1
                    self._clean_input()
                    if not await self._start_notify_with_retry(client):
                        _LOGGER.error(
                            "%s: starting notifications failed", self.address
                        )
                        await self._cleanup_failed_connection(client)
                        if self.product_id == HC7_PRODUCT_ID:
                            await asyncio.sleep(HC7_NOTIFY_RETRY_DELAY)
                        continue
                else:
                    continue

                if self._advertisement_data:
                    self._decode_advertisement_data()

                # Raykube A1 Ultra (hc7) uses protocol v4 on FD50 BLE; advertise it in the
                # first GATT fragments. Without this, firmware may ignore device info / reply.
                if self.product_id == HC7_PRODUCT_ID:
                    self._protocol_version = max(self._protocol_version, 4)
                    await asyncio.sleep(0.35)

                handshake_timeout = (
                    HC7_HANDSHAKE_RESPONSE_TIMEOUT
                    if self.product_id == HC7_PRODUCT_ID
                    else HANDSHAKE_RESPONSE_TIMEOUT
                )

                if self._client and self._client.is_connected:
                    _LOGGER.debug(
                        "%s: Sending device info request", self.address)
                    try:
                        if not await self._send_packet_while_connected(
                            TuyaBLECode.FUN_SENDER_DEVICE_INFO,
                            b"\x00\xf3",
                            0,
                            True,
                            handshake_timeout,
                        ):
                            _LOGGER.error(
                                "%s: Sending device info request failed (timeout after %ss)",
                                self.address,
                                handshake_timeout,
                            )
                            await self._cleanup_failed_connection(client)
                            continue
                    except:  # [BLEAK_EXCEPTIONS, BleakNotFoundError]:
                        _LOGGER.error("%s: Sending device info request failed",
                                      self.address, exc_info=True)
                        await self._cleanup_failed_connection(client)
                        continue
                else:
                    await self._cleanup_failed_connection(client)
                    continue

                if self._client and self._client.is_connected:
                    pair_attempts = (
                        HC7_PAIR_ATTEMPTS
                        if self.product_id == HC7_PRODUCT_ID
                        else 1
                    )
                    paired = False
                    for pair_try in range(pair_attempts):
                        if pair_try > 0:
                            self._clean_input()
                            await asyncio.sleep(HC7_PAIR_RETRY_DELAY)
                        elif self.product_id == HC7_PRODUCT_ID:
                            await asyncio.sleep(HC7_HANDSHAKE_PAIR_DELAY)
                        _LOGGER.debug(
                            "%s: Sending pairing request (attempt %s/%s)",
                            self.address,
                            pair_try + 1,
                            pair_attempts,
                        )
                        try:
                            if await self._send_packet_while_connected(
                                TuyaBLECode.FUN_SENDER_PAIR,
                                self._build_pairing_request(),
                                0,
                                True,
                                handshake_timeout,
                            ):
                                paired = True
                                break
                            _LOGGER.warning(
                                "%s: Pairing attempt %s/%s timed out (no notify response)",
                                self.address,
                                pair_try + 1,
                                pair_attempts,
                            )
                        except TuyaBLEDeviceError as err:
                            _LOGGER.error(
                                "%s: Pairing rejected by device (code %s)",
                                self.address,
                                err,
                            )
                            break
                        except:  # [BLEAK_EXCEPTIONS, BleakNotFoundError]:
                            _LOGGER.error(
                                "%s: Sending pairing request failed",
                                self.address,
                                exc_info=True,
                            )
                            break
                    if not paired:
                        _LOGGER.error(
                            "%s: Sending pairing request failed after %s attempt(s)",
                            self.address,
                            pair_attempts,
                        )
                        await self._cleanup_failed_connection(client)
                        continue
                else:
                    await self._cleanup_failed_connection(client)
                    continue

                break

        if self._client:
            if self._client.is_connected:
                if self._is_paired:
                    _LOGGER.debug("%s: Successfully connected", self.address)
                    self._fire_connected_callbacks()
                else:
                    _LOGGER.error("%s: Connected but not paired", self.address)
            else:
                _LOGGER.error("%s: Not connected", self.address)
        else:
            _LOGGER.error("%s: No client device", self.address)

    def _schedule_reconnect(self) -> None:
        """Run at most one reconnect loop at a time."""
        if self._expected_disconnect:
            return
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return
        self._reconnect_task = asyncio.create_task(self._reconnect())

    async def _reconnect(self) -> None:
        """Reconnect and restore state after an unexpected disconnect."""
        while not self._expected_disconnect:
            _LOGGER.debug("%s: Reconnect, ensuring connection", self.address)
            try:
                await self._ensure_connected()
                if self._expected_disconnect:
                    return
                if not (
                    self._client
                    and self._client.is_connected
                    and self._is_paired
                ):
                    raise BleakError("BLE reconnect finished without a paired session")
                # Notifications emitted while disconnected are lost. A status
                # request is therefore mandatory after every reconnect.
                if not await self.update():
                    raise BleakError("Status refresh after reconnect timed out")
                _LOGGER.debug("%s: Reconnect and status refresh completed", self.address)
                return
            except BLEAK_EXCEPTIONS:
                _LOGGER.debug(
                    "%s: Reconnect failed; backing off",
                    self.address,
                    exc_info=True,
                )
                await asyncio.sleep(BLEAK_BACKOFF_TIME)

    def _next_hc7_op_id(self) -> int:
        """Operation id used in vendor-specific 0x0027 payloads."""
        return self._current_seq_num & 0xFF

    async def _hc7_prepare_unlock(self) -> None:
        """Send unlock prepare frame for hc7n0urm."""
        if self._hc7_unlock_prepared:
            return
        if not self._unlock_token:
            raise TuyaBLECommandError("Missing unlock_token for hc7n0urm")

        token = self._unlock_token.encode("ascii")
        op_id = self._next_hc7_op_id()

        # HCI-confirmed:
        # 00000000014500000dffff0001313237343237363000
        payload = bytearray(b"\x00\x00\x00\x00")
        payload += pack(">B", op_id)
        payload += bytes.fromhex("45 00 00 0d ff ff 00 01")
        payload += token
        payload += b"\x00"

        # Do not log payload.hex(): it contains the unlock token.
        _LOGGER.debug("%s: Sending hc7 unlock prepare, op_id=%s", self.address, op_id)
        # Prepare ack is optional for unlock; do not block 10–25 s on it.
        if not await self._send_packet(
            TuyaBLECode.FUN_SENDER_DPS_V4,
            bytes(payload),
            False,
        ):
            raise TuyaBLECommandError("Could not send hc7 unlock prepare")
        self._hc7_unlock_prepared = True

    async def _hc7_reset_after_command_timeout(self) -> None:
        """Close a timed-out session so late responses cannot collide."""
        if not self._is_paired:
            # Pair retries still belong to the same handshake session.
            self._clean_input()
            return
        _LOGGER.debug("%s: Rebuilding BLE session after command timeout", self.address)
        await self._cleanup_failed_connection(self._client)
        self._fail_pending_responses("BLE command timed out")
        self._hc7_received_requests.clear()
        async with self._seq_num_lock:
            self._current_seq_num = 1
        self._schedule_reconnect()

    def _hc7_is_duplicate_request(self, seq_num: int, code: TuyaBLECode) -> bool:
        """Deduplicate decoded requests, never their transport fragments."""
        key = (seq_num, code.value)
        now = time.monotonic()
        seen_at = self._hc7_received_requests.get(key)
        if seen_at is not None and now - seen_at < HC7_NOTIFY_DEDUPE_TTL:
            return True
        self._hc7_received_requests[key] = now
        if len(self._hc7_received_requests) > 200:
            cutoff = now - HC7_NOTIFY_DEDUPE_TTL
            self._hc7_received_requests = {
                k: v for k, v in self._hc7_received_requests.items() if v >= cutoff
            }
        return False

    async def _hc7_unlock(self) -> None:
        """Send unlock command for hc7n0urm."""
        if not self._unlock_token:
            raise TuyaBLECommandError("Missing unlock_token for hc7n0urm")

        await self._ensure_connected()
        await self._hc7_prepare_unlock()
        await asyncio.sleep(HC7_PREPARE_SETTLE_DELAY)

        token = self._unlock_token.encode("ascii")
        op_id = self._next_hc7_op_id()
        ts = int(time.time())

        # HCI-confirmed shape:
        # 000000000247000013ffff000131323734323736300169b6ba1f0001
        payload = bytearray(b"\x00\x00\x00\x00")
        payload += pack(">B", op_id)
        payload += bytes.fromhex("47 00 00 13 ff ff 00 01")
        payload += token
        payload += b"\x01"
        payload += pack(">I", ts)
        payload += b"\x00\x01"

        # Do not log payload.hex(): it contains the unlock token.
        _LOGGER.debug("%s: Sending hc7 unlock command, op_id=%s", self.address, op_id)
        if not await self._send_packet(
            TuyaBLECode.FUN_SENDER_DPS_V4,
            bytes(payload),
            True,
            HC7_COMMAND_RESPONSE_TIMEOUT,
        ):
            raise TuyaBLECommandError("hc7 unlock was not acknowledged")

    @staticmethod
    def _calc_crc16(data: bytes) -> int:
        crc = 0xFFFF
        for byte in data:
            crc ^= byte & 255
            for _ in range(8):
                tmp = crc & 1
                crc >>= 1
                if tmp != 0:
                    crc ^= 0xA001
        return crc

    @staticmethod
    def _pack_int(value: int) -> bytearray:
        curr_byte: int
        result = bytearray()
        while True:
            curr_byte = value & 0x7F
            value >>= 7
            if value != 0:
                curr_byte |= 0x80
            result += pack(">B", curr_byte)
            if value == 0:
                break
        return result

    @staticmethod
    def _unpack_int(data: bytes, start_pos: int) -> tuple(int, int):
        result: int = 0
        offset: int = 0
        while offset < 5:
            pos: int = start_pos + offset
            if pos >= len(data):
                raise TuyaBLEDataFormatError()
            curr_byte: int = data[pos]
            result |= (curr_byte & 0x7F) << (offset * 7)
            offset += 1
            if (curr_byte & 0x80) == 0:
                break
        if offset > 4:
            raise TuyaBLEDataFormatError()
        else:
            return (result, start_pos + offset)

    def _build_packets(
        self,
        seq_num: int,
        code: TuyaBLECode,
        data: bytes,
        response_to: int = 0,
    ) -> list[bytes]:
        key: bytes
        iv = secrets.token_bytes(16)
        security_flag: bytes
        if code == TuyaBLECode.FUN_SENDER_DEVICE_INFO:
            key = self._login_key
            security_flag = b"\x04"
        else:
            key = self._session_key
            security_flag = b"\x05"

        raw = bytearray()
        raw += pack(">IIHH", seq_num, response_to, code.value, len(data))
        raw += data
        crc = self._calc_crc16(raw)
        raw += pack(">H", crc)
        while len(raw) % 16 != 0:
            raw += b"\x00"

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = security_flag + iv + cipher.encrypt(raw)

        command = []
        packet_num = 0
        pos = 0
        length = len(encrypted)
        while pos < length:
            packet = bytearray()
            packet += self._pack_int(packet_num)

            if packet_num == 0:
                packet += self._pack_int(length)
                packet += pack(">B", self._protocol_version << 4)

            data_part = encrypted[
                pos:pos + GATT_MTU - len(packet)  # fmt: skip
            ]
            packet += data_part
            command.append(packet)

            pos += len(data_part)
            packet_num += 1

        return command

    async def _get_seq_num(self) -> int:
        async with self._seq_num_lock:
            result = self._current_seq_num
            self._current_seq_num += 1
        return result

    async def _send_packet(
        self,
        code: TuyaBLECode,
        data: bytes,
        wait_for_response: bool = True,
        response_timeout: float | None = None,
        # retry: int | None = None,
    ) -> bool:
        """Send a packet and report whether the operation was confirmed."""
        if self._expected_disconnect:
            return False
        await self._ensure_connected()
        if (
            self._expected_disconnect
            or not self._client
            or not self._client.is_connected
            or not self._is_paired
        ):
            return False
        return await self._send_packet_while_connected(
            code, data, 0, wait_for_response, response_timeout
        )

    def _schedule_response(
        self,
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
    ) -> None:
        """Coalesce duplicate ACKs for a request already being answered."""
        key = (response_to, code.value)
        if key in self._pending_responses:
            return
        self._pending_responses.add(key)
        asyncio.create_task(self._send_response_and_clear(key, code, data, response_to))

    async def _send_response_and_clear(
        self,
        key: tuple[int, int],
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
    ) -> None:
        try:
            await self._send_response(code, data, response_to)
        finally:
            self._pending_responses.discard(key)

    async def _send_response(
        self,
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
    ) -> None:
        """Send a best-effort ACK without leaking background task errors."""
        client = self._client
        if (
            self._expected_disconnect
            or client is None
            or not client.is_connected
            or self._client is not client
        ):
            return
        try:
            await self._send_packet_while_connected(code, data, response_to, False)
        except Exception:
            # ACKs run in background tasks. A lost BLE session is recovered by
            # the reconnect path; the device can replay its request afterwards.
            _LOGGER.debug(
                "%s: Could not acknowledge request #%s; BLE session unavailable",
                self.address,
                response_to,
                exc_info=True,
            )

    async def _send_packet_while_connected(
        self,
        code: TuyaBLECode,
        data: bytes,
        response_to: int,
        wait_for_response: bool,
        response_timeout: float | None = None,
        # retry: int | None = None
    ) -> bool:
        """Send packet to device and optional read response."""
        result = True
        future: asyncio.Future | None = None
        seq_num = await self._get_seq_num()
        if wait_for_response:
            future = asyncio.Future()
            self._input_expected_responses[seq_num] = future

        if response_to > 0:
            _LOGGER.debug(
                "%s: Sending packet: #%s %s in response to #%s",
                self.address,
                seq_num,
                code.name,
                response_to,
            )
        else:
            _LOGGER.debug(
                "%s: Sending packet: #%s %s",
                self.address,
                seq_num,
                code.name,
            )
        try:
            packets: list[bytes] = self._build_packets(
                seq_num, code, data, response_to
            )
            await self._int_send_packet_while_connected(packets)
        except Exception:
            self._input_expected_responses.pop(seq_num, None)
            raise
        timeout_sec = (
            RESPONSE_WAIT_TIMEOUT if response_timeout is None else response_timeout
        )
        if future:
            try:
                await asyncio.wait_for(future, timeout_sec)
            except asyncio.CancelledError:
                self._input_expected_responses.pop(seq_num, None)
                raise
            except asyncio.TimeoutError:
                _LOGGER.error(
                    "%s: timeout receiving response, RSSI: %s",
                    self.address,
                    self.rssi,
                )
                result = False
                if self.product_id == HC7_PRODUCT_ID:
                    await self._hc7_reset_after_command_timeout()
            self._input_expected_responses.pop(seq_num, None)

        return result

    async def _int_send_packet_while_connected(
        self,
        packets: list[bytes],
    ) -> None:
        if self._operation_lock.locked():
            _LOGGER.debug(
                "%s: Operation already in progress, "
                "waiting for it to complete; RSSI: %s",
                self.address,
                self.rssi,
            )
        async with self._operation_lock:
            try:
                await self._send_packets_locked(packets)
            except BleakNotFoundError:
                _LOGGER.error(
                    "%s: device not found, no longer in range, or poor RSSI: %s",
                    self.address,
                    self.rssi,
                    exc_info=True,
                )
                raise
            except BLEAK_EXCEPTIONS:
                _LOGGER.debug(
                    "%s: communication failed",
                    self.address,
                    exc_info=True,
                )
                raise

    async def _resend_packets(self, packets: list[bytes]) -> None:
        if self._expected_disconnect:
            return
        await self._ensure_connected()
        if self._expected_disconnect:
            return
        await self._int_send_packet_while_connected(packets)

    async def _send_packets_locked(self, packets: list[bytes]) -> None:
        """Send command to device and read response."""
        try:
            await self._int_send_packets_locked(packets)
        except BleakDBusError as ex:
            # Disconnect so we can reset state and try again
            await asyncio.sleep(BLEAK_BACKOFF_TIME)
            _LOGGER.debug(
                "%s: RSSI: %s; Backing off %ss; Disconnecting due to error: %s",
                self.address,
                self.rssi,
                BLEAK_BACKOFF_TIME,
                ex,
            )
            # hc7n0urm V4 commands carry a UNIX timestamp / op_id; resending the
            # exact same payload after a transport error can replay a stale
            # command and trigger an audible ack on the lock without performing
            # the operation. Surface the error and let HA retry instead.
            if self.product_id == HC7_PRODUCT_ID:
                self._schedule_reconnect()
            elif self._is_paired:
                asyncio.create_task(self._resend_packets(packets))
            else:
                self._schedule_reconnect()
            raise BleakError from ex
        except BleakError as ex:
            # Disconnect so we can reset state and try again
            _LOGGER.debug(
                "%s: RSSI: %s; Disconnecting due to error: %s",
                self.address,
                self.rssi,
                ex,
            )
            if self.product_id == HC7_PRODUCT_ID:
                self._schedule_reconnect()
            elif self._is_paired:
                asyncio.create_task(self._resend_packets(packets))
            else:
                self._schedule_reconnect()
            raise

    async def _int_send_packets_locked(self, packets: list[bytes]) -> None:
        """Execute command and read response."""
        for packet in packets:
            if self._client:
                try:
                    # _LOGGER.debug("%s: Sending packet: %s", self.address, packet.hex())
                    await self._client.write_gatt_char(
                        CHARACTERISTIC_WRITE,
                        packet,
                        False,
                    )
                except Exception as err:
                    _LOGGER.debug(
                        "%s: Error during sending packet",
                        self.address,
                        exc_info=True,
                    )
                    if self._client and self._client.is_connected:
                        self._disconnected(self._client)
                    raise BleakError("GATT write failed") from err
            else:
                _LOGGER.debug("%s: Client disconnected during sending packet", self.address)
                raise BleakError("Client disconnected during sending packet")

    def _get_key(self, security_flag: int) -> bytes:
        if security_flag == 1:
            return self._auth_key
        if security_flag == 4:
            return self._login_key
        elif security_flag == 5:
            return self._session_key
        else:
            pass

    def _parse_timestamp(self, data: bytes, start_pos: int) -> tuple(float, int):
        timestamp: float
        pos = start_pos
        if pos >= len(data):
            raise TuyaBLEDataLengthError()
        time_type = data[pos]
        pos += 1
        end_pos = pos
        match time_type:
            case 0:
                end_pos += 13
                if end_pos > len(data):
                    raise TuyaBLEDataLengthError()
                timestamp = int(data[pos:end_pos].decode()) / 1000
                pass
            case 1:
                end_pos += 4
                if end_pos > len(data):
                    raise TuyaBLEDataLengthError()
                timestamp = int.from_bytes(data[pos:end_pos], "big") * 1.0
                pass
            case _:
                raise TuyaBLEDataFormatError()

        _LOGGER.debug(
            "%s: Received timestamp: %s",
            self.address,
            time.ctime(timestamp),
        )
        return (timestamp, end_pos)

    def _parse_datapoints_v3(
        self, timestamp: float, flags: int, data: bytes, start_pos: int
    ) -> int:
        datapoints: list[TuyaBLEDataPoint] = []

        pos = start_pos
        while len(data) - pos >= 4:
            id: int = data[pos]
            pos += 1
            _type: int = data[pos]
            if _type > TuyaBLEDataPointType.DT_BITMAP.value:
                raise TuyaBLEDataFormatError()
            type: TuyaBLEDataPointType = TuyaBLEDataPointType(_type)
            pos += 1
            data_len: int = data[pos]
            pos += 1
            next_pos = pos + data_len
            if next_pos > len(data):
                raise TuyaBLEDataLengthError()
            raw_value = data[pos:next_pos]
            match type:
                case (TuyaBLEDataPointType.DT_RAW | TuyaBLEDataPointType.DT_BITMAP):
                    value = raw_value
                case TuyaBLEDataPointType.DT_BOOL:
                    value = int.from_bytes(raw_value, "big") != 0
                case (TuyaBLEDataPointType.DT_VALUE | TuyaBLEDataPointType.DT_ENUM):
                    value = int.from_bytes(raw_value, "big", signed=True)
                case TuyaBLEDataPointType.DT_STRING:
                    value = raw_value.decode()

            _LOGGER.debug(
                "%s: Received datapoint update, id: %s, type: %s: value: %s",
                self.address,
                id,
                type.name,
                value,
            )
            self._datapoints._update_from_device(
                id, timestamp, flags, type, value)
            datapoints.append(self._datapoints[id])
            pos = next_pos

        self._fire_callbacks(datapoints)
        return pos

    def _parse_datapoints_v4(
        self, timestamp: float, flags: int, data: bytes, start_pos: int
    ) -> int:
        datapoints: list[TuyaBLEDataPoint] = []
        pos = start_pos

        while len(data) - pos >= 4:
            dp_id = data[pos]
            pos += 1

            _type = data[pos]
            if _type > TuyaBLEDataPointType.DT_BITMAP.value:
                break
            type = TuyaBLEDataPointType(_type)
            pos += 1

            dp_flags = data[pos]
            pos += 1

            data_len = data[pos]
            pos += 1

            next_pos = pos + data_len
            if next_pos > len(data):
                raise TuyaBLEDataLengthError()

            raw_value = data[pos:next_pos]

            match type:
                case TuyaBLEDataPointType.DT_RAW | TuyaBLEDataPointType.DT_BITMAP:
                    value = raw_value
                case TuyaBLEDataPointType.DT_BOOL:
                    value = int.from_bytes(raw_value, "big") != 0
                case TuyaBLEDataPointType.DT_VALUE | TuyaBLEDataPointType.DT_ENUM:
                    value = int.from_bytes(raw_value, "big", signed=True)
                case TuyaBLEDataPointType.DT_STRING:
                    value = raw_value.decode()

            _LOGGER.debug(
                "%s: Received datapoint update, id: %s, type: %s, flags: %s, value: %s",
                self.address,
                dp_id,
                type.name,
                dp_flags,
                value,
            )

            self._datapoints._update_from_device(dp_id, timestamp, dp_flags, type, value)
            datapoints.append(self._datapoints[dp_id])
            pos = next_pos

        self._fire_callbacks(datapoints)
        return pos

    def _handle_command_or_response(
        self, seq_num: int, response_to: int, code: TuyaBLECode, data: bytes
    ) -> None:
        result: int = 0

        match code:
            case TuyaBLECode.FUN_SENDER_DEVICE_INFO:
                if len(data) < 46:
                    raise TuyaBLEDataLengthError()

                self._device_version = ("%s.%s") % (data[0], data[1])
                self._protocol_version_str = ("%s.%s") % (data[2], data[3])
                self._hardware_version = ("%s.%s") % (data[12], data[13])

                self._protocol_version = data[2]
                self._flags = data[4]
                self._is_bound = data[5] != 0

                srand = data[6:12]
                self._session_key = hashlib.md5(
                    self._local_key + srand).digest()
                self._auth_key = data[14:46]

            case TuyaBLECode.FUN_SENDER_PAIR:
                if len(data) != 1:
                    raise TuyaBLEDataLengthError()
                result = data[0]
                if result == 2:
                    _LOGGER.debug(
                        "%s: Device is already paired",
                        self.address,
                    )
                    result = 0
                self._is_paired = result == 0

            case TuyaBLECode.FUN_SENDER_DEVICE_STATUS:
                if len(data) != 1:
                    raise TuyaBLEDataLengthError()
                result = data[0]

            case TuyaBLECode.FUN_SENDER_DPS_V4:
                _LOGGER.debug(
                    "%s: DPS_V4 response raw: %s",
                    self.address,
                    data.hex(),
                )

                pos = 0
                cmd_status = 0

                while len(data) - pos >= 5:
                    dp_id = data[pos]
                    pos += 1

                    _type = data[pos]
                    pos += 1

                    value_len = int.from_bytes(data[pos:pos + 2], "big")
                    pos += 2

                    next_pos = pos + value_len
                    if next_pos + 1 > len(data):
                        raise TuyaBLEDataLengthError()

                    raw_value = data[pos:next_pos]
                    pos = next_pos

                    cmd_status = data[pos]
                    pos += 1

                    _LOGGER.debug(
                        "%s: DPS_V4 response dp_id=%s type=%s value=%s status=%s",
                        self.address,
                        dp_id,
                        _type,
                        raw_value.hex(),
                        cmd_status,
                    )

                # For hc7n0urm, 0x0027 responses are vendor-specific ack frames.
                # Do not treat cmd_status as generic Tuya error code.
                result = 0 if self.product_id == "hc7n0urm" else cmd_status

            case TuyaBLECode.FUN_RECEIVE_TIME1_REQ:
                if len(data) != 0:
                    raise TuyaBLEDataLengthError()

                timestamp = int(time.time_ns() / 1000000)
                timezone = -int(time.timezone / 36)
                data = str(timestamp).encode() + pack(">h", timezone)
                self._schedule_response(code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_TIME2_REQ:
                if len(data) != 0:
                    raise TuyaBLEDataLengthError()

                time_str: time.struct_time = time.localtime()
                timezone = -int(time.timezone / 36)
                data = pack(
                    ">BBBBBBBh",
                    time_str.tm_year % 100,
                    time_str.tm_mon,
                    time_str.tm_mday,
                    time_str.tm_hour,
                    time_str.tm_min,
                    time_str.tm_sec,
                    time_str.tm_wday,
                    timezone,
                )
                self._schedule_response(code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_DP:
                self._parse_datapoints_v3(time.time(), 0, data, 0)
                self._schedule_response(code, bytes(0), seq_num)

            case TuyaBLECode.FUN_RECEIVE_SIGN_DP:
                dp_seq_num = int.from_bytes(data[:2], "big")
                flags = data[2]
                self._parse_datapoints_v3(time.time(), flags, data, 2)
                data = pack(">HBB", dp_seq_num, flags, 0)
                self._schedule_response(code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_TIME_DP:
                timestamp: float
                pos: int
                timestamp, pos = self._parse_timestamp(data, 0)
                self._parse_datapoints_v3(timestamp, 0, data, pos)
                self._schedule_response(code, bytes(0), seq_num)

            case TuyaBLECode.FUN_RECEIVE_SIGN_TIME_DP:
                timestamp: float
                pos: int
                dp_seq_num = int.from_bytes(data[:2], "big")
                flags = data[2]
                timestamp, pos = self._parse_timestamp(data, 3)
                self._parse_datapoints_v3(time.time(), flags, data, pos)
                data = pack(">HBB", dp_seq_num, flags, 0)
                self._schedule_response(code, data, seq_num)

            case TuyaBLECode.FUN_RECEIVE_DP_V4:
                _LOGGER.debug(
                    "%s: Received DP_V4 raw: %s",
                    self.address,
                    data.hex(),
                )
                if (
                    response_to == 0
                    and self.product_id == HC7_PRODUCT_ID
                    and self._hc7_is_duplicate_request(seq_num, code)
                ):
                    # A replay may mean that our previous ACK was lost. ACK it
                    # again, but do not apply the same datapoint update twice.
                    _LOGGER.debug("%s: Re-acking duplicate DP_V4 #%s", self.address, seq_num)
                    self._schedule_response(code, bytes(0), seq_num)
                    return

                try:
                    if self.product_id == "hc7n0urm":
                        # hc7n0urm layout (btsnoop):
                        #   bytes 0..3 padding
                        #   byte 4    seq/op
                        #   byte 5    often 0x00 even for real DP pushes (manual
                        #             lock/unlock notifications use 12-byte frames
                        #             with [5]==0x00 — must not treat as "echo").
                        #   byte 6    reserved (0x00)
                        #   byte 7..  V4 DP triplets for multi-DP reports ([5]==0x01)
                        #
                        # Long frames with [5]==0x00 are vendor command echoes
                        # (unlock blob etc.) — no bolt DP there.
                        if len(data) == 12:
                            # Single DP: tail = id(1) type(1) len(2) value(len)
                            # e.g. manual state 000000004600002f01000101 -> dp 47 bool 1
                            tail = data[-5:]
                            dp_id = tail[0]
                            _type = tail[1]
                            value_len = int.from_bytes(tail[2:4], "big")
                            raw_value = tail[4:4 + value_len]

                            if _type <= TuyaBLEDataPointType.DT_BITMAP.value and value_len == len(raw_value):
                                dp_type = TuyaBLEDataPointType(_type)

                                match dp_type:
                                    case TuyaBLEDataPointType.DT_RAW | TuyaBLEDataPointType.DT_BITMAP:
                                        value = raw_value
                                    case TuyaBLEDataPointType.DT_BOOL:
                                        value = int.from_bytes(raw_value, "big") != 0
                                    case TuyaBLEDataPointType.DT_VALUE | TuyaBLEDataPointType.DT_ENUM:
                                        value = int.from_bytes(raw_value, "big", signed=True)
                                    case TuyaBLEDataPointType.DT_STRING:
                                        value = raw_value.decode()

                                _LOGGER.debug(
                                    "%s: Received short DP_V4 update, id: %s, type: %s, value: %s",
                                    self.address,
                                    dp_id,
                                    dp_type.name,
                                    value,
                                )

                                self._datapoints._update_from_device(
                                    dp_id, time.time(), 0, dp_type, value
                                )
                                self._fire_callbacks([self._datapoints[dp_id]])
                            else:
                                self._parse_datapoints_v4(time.time(), 0, data, 7)
                        elif len(data) >= 6 and data[5] == 0x00:
                            _LOGGER.debug(
                                "%s: Ignoring DP_V4 vendor echo (%s B): %s",
                                self.address,
                                len(data),
                                data.hex(),
                            )
                        else:
                            self._parse_datapoints_v4(time.time(), 0, data, 7)
                    else:
                        self._parse_datapoints_v4(time.time(), 0, data, 8)
                except Exception:
                    _LOGGER.exception("%s: DP_V4 parse failed", self.address)

                self._schedule_response(code, bytes(0), seq_num)


        if response_to != 0:
            future = self._input_expected_responses.pop(response_to, None)
            if future is None and self.product_id == HC7_PRODUCT_ID:
                _LOGGER.debug(
                    "%s: ignoring late response to #%s (no waiter)",
                    self.address,
                    response_to,
                )
            if future:
                _LOGGER.debug(
                    "%s: Received expected response to #%s, result: %s",
                    self.address,
                    response_to,
                    result,
                )
                if result == 0:
                    future.set_result(result)
                else:
                    future.set_exception(TuyaBLEDeviceError(result))

    def _clean_input(self) -> None:
        self._input_buffer = None
        self._input_expected_packet_num = 0
        self._input_expected_length = 0

    def _parse_input(self) -> None:
        security_flag = self._input_buffer[0]
        key = self._get_key(security_flag)
        iv = self._input_buffer[1:17]
        encrypted = self._input_buffer[17:]

        self._clean_input()

        if key is None:
            _LOGGER.error(
                "%s: Unknown security flag %s in notify payload; cannot decrypt",
                self.address,
                security_flag,
            )
            return

        cipher = AES.new(key, AES.MODE_CBC, iv)
        raw = cipher.decrypt(encrypted)

        seq_num: int
        response_to: int
        _code: int
        length: int
        seq_num, response_to, _code, length = unpack(">IIHH", raw[:12])

        data_end_pos = length + 12
        raw_length = len(raw)
        if raw_length < data_end_pos:
            raise TuyaBLEDataLengthError()
        if raw_length > data_end_pos:
            calc_crc = self._calc_crc16(raw[:data_end_pos])
            (data_crc,) = unpack(
                ">H",
                raw[data_end_pos:data_end_pos + 2]  # fmt: skip
            )
            if calc_crc != data_crc:
                raise TuyaBLEDataCRCError()
        data = raw[12:data_end_pos]

        code: TuyaBLECode
        try:
            code = TuyaBLECode(_code)
        except ValueError:
            _LOGGER.debug(
                "%s: Received unknown message: #%s %x, response to #%s, data %s",
                self.address,
                seq_num,
                _code,
                response_to,
                data.hex(),
            )
            return

        if response_to != 0:
            _LOGGER.debug(
                "%s: Received: #%s %s, response to #%s",
                self.address,
                seq_num,
                code.name,
                response_to,
            )
        else:
            _LOGGER.debug(
                "%s: Received: #%s %s",
                self.address,
                seq_num,
                code.name,
            )

        self._handle_command_or_response(seq_num, response_to, code, data)

    def _notification_handler(
        self,
        _sender: int,
        data: bytearray,
        client: BleakClientWithServiceCache | None = None,
    ) -> None:
        """Handle notification responses from the current BLE session only."""
        if client is not None and self._client is not client:
            _LOGGER.debug("%s: Ignoring notify from a stale BLE session", self.address)
            return
        _LOGGER.debug("%s: Packet received: %s", self.address, data.hex())

        pos: int = 0
        packet_num: int

        packet_num, pos = self._unpack_int(data, pos)

        if packet_num < self._input_expected_packet_num:
            _LOGGER.error(
                "%s: Unexpcted packet (number %s) in notifications, " "expected %s",
                self.address,
                packet_num,
                self._input_expected_packet_num,
            )
            self._clean_input()

        if packet_num == self._input_expected_packet_num:
            if packet_num == 0:
                self._input_buffer = bytearray()
                self._input_expected_length, pos = self._unpack_int(data, pos)
                pos += 1
            self._input_buffer += data[pos:]
            self._input_expected_packet_num += 1
        else:
            _LOGGER.error(
                "%s: Missing packet (number %s) in notifications, received %s",
                self.address,
                self._input_expected_packet_num,
                packet_num,
            )
            self._clean_input()
            return

        if len(self._input_buffer) > self._input_expected_length:
            _LOGGER.error(
                "%s: Unexpcted length of data in notifications, "
                "received %s expected %s",
                self.address,
                len(self._input_buffer),
                self._input_expected_length,
            )
            self._clean_input()
            return
        elif len(self._input_buffer) == self._input_expected_length:
            try:
                self._parse_input()
            except (
                TuyaBLEDataLengthError,
                TuyaBLEDataCRCError,
                TuyaBLEDataFormatError,
            ):
                _LOGGER.warning(
                    "%s: Dropping corrupt notify frame (reassembled %s B); "
                    "often caused by BLE proxy fragmentation or a stale session",
                    self.address,
                    self._input_expected_length,
                    exc_info=True,
                )

    async def _send_datapoints_v4(self, datapoint_ids: list[int]) -> None:
        """Send new values of datapoints to the device using V4 command 0x0027."""

        if len(datapoint_ids) != 1:
            _LOGGER.error("%s: hc7n0urm expects single-DP V4 command", self.address)
            return

        dp_id = datapoint_ids[0]
        dp = self._datapoints[dp_id]
        value = dp._get_value()

        _LOGGER.debug(
            "%s: Sending V4 datapoint update, id: %s, type: %s: value: %s",
            self.address,
            dp.id,
            dp.type.name,
            dp.value,
        )

        # HCI-confirmed lock command:
        # 00000000032e01000101
        if dp.id == 46 and dp.type == TuyaBLEDataPointType.DT_BOOL and value == b"\x01":
            data = bytearray(b"\x00\x00\x00\x00\x03")
            data += pack(">BBH", dp.id, int(dp.type.value), len(value))
            data += value
        else:
            _LOGGER.error(
                "%s: Unsupported hc7n0urm V4 command dp_id=%s type=%s value=%s",
                self.address,
                dp.id,
                dp.type.name,
                value.hex(),
            )
            return

        if not await self._send_packet(
            TuyaBLECode.FUN_SENDER_DPS_V4,
            data,
            True,
            HC7_COMMAND_RESPONSE_TIMEOUT,
        ):
            raise TuyaBLECommandError("hc7 lock was not acknowledged")

    async def _send_datapoints(self, datapoint_ids: list[int]) -> None:
        """Send new values of datapoints to the device."""
        if self.product_id == "hc7n0urm":
            if len(datapoint_ids) != 1:
                raise TuyaBLECommandError("hc7n0urm expects a single datapoint command")

            dp_id = datapoint_ids[0]
            dp = self._datapoints[dp_id]

            # State is changed only by a genuine DP 47 notification. An ACK or
            # a timeout must never synthesise the physical bolt position.
            if dp_id == 46 and dp.type == TuyaBLEDataPointType.DT_BOOL and dp.value is True:
                await self._send_datapoints_v4(datapoint_ids)
                return

            if dp_id == 6 and dp.type == TuyaBLEDataPointType.DT_BOOL and dp.value is True:
                await self._hc7_unlock()
                return

            _LOGGER.error(
                "%s: Unsupported hc7n0urm V4 command dp_id=%s type=%s value=%s",
                self.address,
                dp_id,
                dp.type.name,
                dp._get_value().hex(),
            )
            return

        _LOGGER.error(
            "%s: Cannot send datapoints, unsupported protocol_version=%s",
            self.address,
            self._protocol_version,
        )
        return

