"""The Tuya BLE integration."""
from __future__ import annotations

import asyncio
import logging

from bleak_retry_connector import BLEAK_RETRY_EXCEPTIONS as BLEAK_EXCEPTIONS, get_device

from homeassistant.components import bluetooth
from homeassistant.components.lock import DOMAIN as LOCK_DOMAIN
from homeassistant.components.bluetooth.match import ADDRESS, BluetoothCallbackMatcher
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant, ServiceCall, callback, split_entity_id
from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.target import (
    TargetSelection,
    async_extract_referenced_entity_ids,
)

from .tuya_ble import TuyaBLEDevice

from .keyman import HASSTuyaBLEDeviceManager
from .const import DOMAIN, SERVICE_FORCE_LOCK, SERVICE_FORCE_UNLOCK
from .devices import TuyaBLECoordinator, TuyaBLEData, get_device_product_info

PLATFORMS: list[Platform] = [
    Platform.LOCK,
    Platform.BUTTON,
    Platform.CLIMATE,
    Platform.NUMBER,
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.SELECT,
    Platform.SWITCH,
    Platform.TEXT,
]

_LOGGER = logging.getLogger(__name__)

_FORCE_SERVICES_SCHEMA = cv.make_entity_service_schema({})


async def _async_service_force_lock(hass: HomeAssistant, call: ServiceCall) -> None:
    """tuya_local_ble.force_lock — same as lock.force_lock, with target support."""
    selection = TargetSelection(call.data)
    if not selection.has_any_target:
        raise HomeAssistantError(
            "Укажите цель действия: entity_id замка (или устройство/зона)."
        )
    referenced = async_extract_referenced_entity_ids(hass, selection, True)
    entity_ids = referenced.referenced | referenced.indirectly_referenced
    lock_comp = hass.data.get(LOCK_DOMAIN)
    if lock_comp is None:
        raise HomeAssistantError("Компонент lock не загружен.")
    found = False
    for eid in entity_ids:
        if split_entity_id(eid)[0] != "lock":
            continue
        entity = lock_comp.get_entity(eid)
        if entity is None or not hasattr(entity, "async_force_lock"):
            continue
        await entity.async_force_lock()
        found = True
    if not found:
        raise HomeAssistantError(
            "В цели нет замка Tuya Local BLE с поддержкой force_lock."
        )


async def _async_service_force_unlock(hass: HomeAssistant, call: ServiceCall) -> None:
    """tuya_local_ble.force_unlock — same as lock.force_unlock, with target support."""
    selection = TargetSelection(call.data)
    if not selection.has_any_target:
        raise HomeAssistantError(
            "Укажите цель действия: entity_id замка (или устройство/зона)."
        )
    referenced = async_extract_referenced_entity_ids(hass, selection, True)
    entity_ids = referenced.referenced | referenced.indirectly_referenced
    lock_comp = hass.data.get(LOCK_DOMAIN)
    if lock_comp is None:
        raise HomeAssistantError("Компонент lock не загружен.")
    found = False
    for eid in entity_ids:
        if split_entity_id(eid)[0] != "lock":
            continue
        entity = lock_comp.get_entity(eid)
        if entity is None or not hasattr(entity, "async_force_unlock"):
            continue
        await entity.async_force_unlock()
        found = True
    if not found:
        raise HomeAssistantError(
            "В цели нет замка Tuya Local BLE с поддержкой force_unlock."
        )


def _ensure_domain_force_services(hass: HomeAssistant) -> None:
    """Register tuya_local_ble.force_* once (parallel to lock.force_* entity services)."""
    root = hass.data.setdefault(DOMAIN, {})
    if root.get("_tuya_ble_force_services"):
        return
    root["_tuya_ble_force_services"] = True

    async def _force_lock(call: ServiceCall) -> None:
        await _async_service_force_lock(hass, call)

    async def _force_unlock(call: ServiceCall) -> None:
        await _async_service_force_unlock(hass, call)

    hass.services.async_register(
        DOMAIN,
        SERVICE_FORCE_LOCK,
        _force_lock,
        schema=_FORCE_SERVICES_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_FORCE_UNLOCK,
        _force_unlock,
        schema=_FORCE_SERVICES_SCHEMA,
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Tuya BLE from a config entry."""
    address: str = entry.data[CONF_ADDRESS]
    ble_device = bluetooth.async_ble_device_from_address(
        hass, address.upper(), True
    ) or await get_device(address)
    if not ble_device:
        raise ConfigEntryNotReady(
            f"Could not find Tuya BLE device with address {address}"
        )
    manager = HASSTuyaBLEDeviceManager(hass, entry.options.copy())
    await manager.async_load_devices_file()
    if manager.load_error == "invalid_json":
        raise ConfigEntryNotReady(
            "Invalid JSON in tuya_local_ble/devices.json — check the file for a "
            "syntax error (line/column is logged)."
        )
    device = TuyaBLEDevice(manager, ble_device)

    @callback
    def _async_update_ble(
        service_info: bluetooth.BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        """Keep BLEDevice and advertisement in sync (protocol version, RSSI)."""
        device.set_ble_device_and_advertisement_data(
            service_info.device, service_info.advertisement
        )

    entry.async_on_unload(
        bluetooth.async_register_callback(
            hass,
            _async_update_ble,
            BluetoothCallbackMatcher({ADDRESS: address}),
            bluetooth.BluetoothScanningMode.ACTIVE,
        )
    )

    await device.initialize()
    product_info = get_device_product_info(device)

    coordinator = TuyaBLECoordinator(hass, device)

    '''
    try:
        await device.update()
    except BLEAK_EXCEPTIONS as ex:
        raise ConfigEntryNotReady(
            f"Could not communicate with Tuya BLE device with address {address}"
        ) from ex
    '''

    def _log_update_err(task: asyncio.Task) -> None:
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as ex:
            _LOGGER.warning(
                "%s: initial device.update() failed: %s",
                address,
                ex,
                exc_info=True,
            )

    # Background connect + DEVICE_STATUS poll. Coordinator.connected stays False
    # until this runs; skipping it left hc7 entities unavailable with no logs
    # after "Initializing".
    t = hass.async_create_task(device.update())
    t.add_done_callback(_log_update_err)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = TuyaBLEData(
        entry.title,
        device,
        product_info,
        manager,
        coordinator,
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _ensure_domain_force_services(hass)
    #entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    async def _async_stop(event: Event) -> None:
        """Close the connection."""
        await device.stop()

    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _async_stop)
    )
    return True


#async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
#    """Handle options update."""
#    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
#    if entry.title != data.title:
#        await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data: TuyaBLEData = hass.data[DOMAIN].pop(entry.entry_id)
        await data.device.stop()

    return unload_ok
