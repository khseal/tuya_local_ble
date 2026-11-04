"""Diagnostic sensors for Raykube A1 Ultra."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import SIGNAL_STRENGTH_DECIBELS_MILLIWATT
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    BATTERY_STATE_HIGH,
    BATTERY_STATE_LOW,
    BATTERY_STATE_NORMAL,
    DOMAIN,
    SUPPORTED_CATEGORY,
    SUPPORTED_PRODUCT_ID,
)
from .devices import TuyaBLEData, TuyaBLEEntity, TuyaBLEProductInfo
from .tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice

SIGNAL_STRENGTH_DP_ID = -1


@dataclass
class TuyaBLESensorMapping:
    dp_id: int
    description: SensorEntityDescription
    force_add: bool = True
    dp_type: TuyaBLEDataPointType | None = None
    getter: Callable[[TuyaBLESensor], None] | None = None
    icons: list[str] | None = None


RAYKUBE_SENSORS = [
    TuyaBLESensorMapping(
        dp_id=9,
        description=SensorEntityDescription(
            key="battery_state",
            icon="mdi:battery",
            device_class=SensorDeviceClass.ENUM,
            options=[
                BATTERY_STATE_HIGH,
                BATTERY_STATE_NORMAL,
                BATTERY_STATE_LOW,
                BATTERY_STATE_LOW,
            ],
        ),
        icons=[
            "mdi:battery-check",
            "mdi:battery-50",
            "mdi:battery-alert",
            "mdi:battery-alert",
        ],
    )
]


def rssi_getter(sensor: TuyaBLESensor) -> None:
    sensor._attr_native_value = sensor._device.rssi


rssi_mapping = TuyaBLESensorMapping(
    dp_id=SIGNAL_STRENGTH_DP_ID,
    description=SensorEntityDescription(
        key="signal_strength",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    getter=rssi_getter,
)


def get_mapping_by_device(device: TuyaBLEDevice) -> list[TuyaBLESensorMapping]:
    if device.category == SUPPORTED_CATEGORY and device.product_id == SUPPORTED_PRODUCT_ID:
        return RAYKUBE_SENSORS
    return []


class TuyaBLESensor(TuyaBLEEntity, SensorEntity):
    """Representation of a Raykube diagnostic sensor."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: DataUpdateCoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLESensorMapping,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._mapping = mapping

    @callback
    def _handle_coordinator_update(self) -> None:
        if self._mapping.getter is not None:
            self._mapping.getter(self)
        else:
            datapoint = self._device.datapoints[self._mapping.dp_id]
            if datapoint:
                if datapoint.type == TuyaBLEDataPointType.DT_ENUM:
                    options = self.entity_description.options
                    if options is not None and 0 <= datapoint.value < len(options):
                        self._attr_native_value = options[datapoint.value]
                    else:
                        self._attr_native_value = datapoint.value
                    if self._mapping.icons is not None and 0 <= datapoint.value < len(
                        self._mapping.icons
                    ):
                        self._attr_icon = self._mapping.icons[datapoint.value]
                else:
                    self._attr_native_value = datapoint.value
        self.async_write_ha_state()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    entities = [
        TuyaBLESensor(
            hass, data.coordinator, data.device, data.product, rssi_mapping
        )
    ]
    for mapping in get_mapping_by_device(data.device):
        if mapping.force_add or data.device.datapoints.has_id(
            mapping.dp_id, mapping.dp_type
        ):
            entities.append(
                TuyaBLESensor(
                    hass, data.coordinator, data.device, data.product, mapping
                )
            )
    async_add_entities(entities)
