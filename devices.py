"""Home Assistant entities for Raykube A1 Ultra."""
from __future__ import annotations

from dataclasses import dataclass
import logging

from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity import DeviceInfo, EntityDescription
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.update_coordinator import CoordinatorEntity, DataUpdateCoordinator
from home_assistant_bluetooth import BluetoothServiceInfoBleak

from .const import (
    DEVICE_DEF_MANUFACTURER,
    DOMAIN,
    SET_DISCONNECTED_DELAY,
    SUPPORTED_CATEGORY,
    SUPPORTED_PRODUCT_ID,
)
from .keyman import HASSTuyaBLEDeviceManager
from .tuya_ble import (
    AbstaractTuyaBLEDeviceManager,
    TuyaBLEDataPoint,
    TuyaBLEDevice,
    TuyaBLEDeviceCredentials,
)

_LOGGER = logging.getLogger(__name__)


@dataclass
class TuyaBLEProductInfo:
    name: str
    manufacturer: str = DEVICE_DEF_MANUFACTURER


RAYKUBE_A1_ULTRA = TuyaBLEProductInfo(name="A1 Ultra-JM")


class TuyaBLEEntity(CoordinatorEntity):
    """Base entity for the Raykube lock."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLECoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        description: EntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self._hass = hass
        self._coordinator = coordinator
        self._device = device
        self._product = product
        if description.translation_key is None:
            self._attr_translation_key = description.key
        self.entity_description = description
        self._attr_has_entity_name = True
        self._attr_device_info = get_device_info(self._device)
        self._attr_unique_id = f"{self._device.device_id}-{description.key}"

    @property
    def available(self) -> bool:
        return self._coordinator.connected

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._migrate_legacy_entity_id()

    @callback
    def _migrate_legacy_entity_id(self) -> None:
        """Move legacy sensor.* entity IDs onto their actual platform."""
        if self.platform is None or self.entity_id is None:
            return
        target_domain = self.platform.domain
        current_domain, _, object_id = self.entity_id.partition(".")
        if not object_id or current_domain == target_domain or current_domain != "sensor":
            return
        ent_reg = er.async_get(self.hass)
        new_entity_id = f"{target_domain}.{object_id}"
        if ent_reg.async_get(new_entity_id) is not None:
            _LOGGER.debug(
                "Skip entity_id migration %s -> %s (target already exists)",
                self.entity_id,
                new_entity_id,
            )
            return
        try:
            ent_reg.async_update_entity(self.entity_id, new_entity_id=new_entity_id)
        except (ValueError, KeyError) as err:
            _LOGGER.warning(
                "Could not migrate entity_id %s -> %s: %s",
                self.entity_id,
                new_entity_id,
                err,
            )
            return
        _LOGGER.info("Migrated legacy entity_id %s -> %s", self.entity_id, new_entity_id)

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()


class TuyaBLECoordinator(DataUpdateCoordinator[None]):
    """Coordinator receiving Raykube BLE updates."""

    def __init__(self, hass: HomeAssistant, device: TuyaBLEDevice) -> None:
        super().__init__(hass, _LOGGER, name=DOMAIN)
        self._device = device
        self._disconnected = True
        self._unsub_disconnect: CALLBACK_TYPE | None = None
        self._registered_versions: tuple[str | None, str | None] | None = None
        device.register_connected_callback(self._async_handle_connect)
        device.register_callback(self._async_handle_update)
        device.register_disconnected_callback(self._async_handle_disconnect)

    @property
    def connected(self) -> bool:
        return not self._disconnected

    @callback
    def _async_update_device_registry(self) -> None:
        """Persist version fields received during the BLE handshake."""
        versions = (self._device.firmware_version, self._device.hardware_version or None)
        if versions == self._registered_versions or not any(versions):
            return
        registry = dr.async_get(self.hass)
        device_entry = registry.async_get_device_by_identifier(
            (DOMAIN, self._device.address)
        )
        if device_entry is None:
            return
        registry.async_update_device(
            device_entry.id,
            sw_version=versions[0],
            hw_version=versions[1],
        )
        self._registered_versions = versions

    @callback
    def _async_handle_connect(self) -> None:
        self._async_update_device_registry()
        if self._unsub_disconnect is not None:
            self._unsub_disconnect()
            self._unsub_disconnect = None
        if self._disconnected:
            self._disconnected = False
            self.async_update_listeners()

    @callback
    def _async_handle_update(self, updates: list[TuyaBLEDataPoint]) -> None:
        self._async_handle_connect()
        self.async_set_updated_data(None)

    @callback
    def _set_disconnected(self, _: None) -> None:
        self._disconnected = True
        self._unsub_disconnect = None
        self.async_update_listeners()

    @callback
    def _async_handle_disconnect(self) -> None:
        if self._unsub_disconnect is None:
            self._unsub_disconnect = async_call_later(
                self.hass, SET_DISCONNECTED_DELAY, self._set_disconnected
            )

    async def _async_update_data(self) -> None:
        """The device pushes updates; there is no coordinator polling."""


@dataclass
class TuyaBLEData:
    title: str
    device: TuyaBLEDevice
    product: TuyaBLEProductInfo
    manager: HASSTuyaBLEDeviceManager
    coordinator: TuyaBLECoordinator


def get_product_info_by_ids(
    category: str, product_id: str
) -> TuyaBLEProductInfo | None:
    if category == SUPPORTED_CATEGORY and product_id == SUPPORTED_PRODUCT_ID:
        return RAYKUBE_A1_ULTRA
    return None


def get_device_product_info(device: TuyaBLEDevice) -> TuyaBLEProductInfo | None:
    return get_product_info_by_ids(device.category, device.product_id)


def get_short_address(address: str) -> str:
    results = address.replace("-", ":").upper().split(":")
    return f"{results[-3]}{results[-2]}{results[-1]}"[-6:]


async def get_device_readable_name(
    discovery_info: BluetoothServiceInfoBleak,
    manager: AbstaractTuyaBLEDeviceManager | None,
) -> str:
    credentials: TuyaBLEDeviceCredentials | None = None
    product_info: TuyaBLEProductInfo | None = None
    if manager:
        credentials = await manager.get_device_credentials(discovery_info.address)
        if credentials:
            product_info = get_product_info_by_ids(
                credentials.category, credentials.product_id
            )
    short_address = get_short_address(discovery_info.address)
    if product_info:
        return f"{product_info.name} {short_address}"
    if credentials:
        return f"{credentials.device_name} {short_address}"
    return f"{discovery_info.device.name} {short_address}"


def get_device_info(device: TuyaBLEDevice) -> DeviceInfo:
    product_info = get_device_product_info(device)
    product_name = product_info.name if product_info else device.name
    return DeviceInfo(
        connections={(dr.CONNECTION_BLUETOOTH, device.address)},
        hw_version=device.hardware_version or None,
        identifiers={(DOMAIN, device.address)},
        manufacturer=product_info.manufacturer if product_info else DEVICE_DEF_MANUFACTURER,
        model=f"{device.product_model or product_name} ({device.product_id})",
        name=f"{product_name} {get_short_address(device.address)}",
        sw_version=device.firmware_version,
    )
