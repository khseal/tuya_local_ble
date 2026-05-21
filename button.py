"""The Tuya BLE integration."""
from __future__ import annotations

from dataclasses import dataclass, field

import logging
from typing import Callable

from homeassistant.components.button import (
    ButtonEntityDescription,
    ButtonEntity,
)
from homeassistant.components.lock import DOMAIN as LOCK_ENTITY_DOMAIN
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN, SERVICE_FORCE_LOCK, SERVICE_FORCE_UNLOCK
from .devices import TuyaBLEData, TuyaBLEEntity, TuyaBLEProductInfo
from .tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice

_LOGGER = logging.getLogger(__name__)


TuyaBLEButtonIsAvailable = Callable[["TuyaBLEButton", TuyaBLEProductInfo], bool] | None


@dataclass
class TuyaBLEButtonMapping:
    dp_id: int
    description: ButtonEntityDescription
    force_add: bool = True
    dp_type: TuyaBLEDataPointType | None = None
    is_available: TuyaBLEButtonIsAvailable = None
    #: When set, calls lock.force_lock / lock.force_unlock instead of a DP.
    service_force: str | None = None


def is_fingerbot_in_push_mode(self: TuyaBLEButton, product: TuyaBLEProductInfo) -> bool:
    result: bool = True
    if product.fingerbot:
        datapoint = self._device.datapoints[product.fingerbot.mode]
        if datapoint:
            result = datapoint.value == 0
    return result

@dataclass
class TuyaBLEFingerbotModeMapping(TuyaBLEButtonMapping):
    description: ButtonEntityDescription = field(
        default_factory=lambda: ButtonEntityDescription(
            key="push",
            translation_key="push",
        )
    )
    is_available: TuyaBLEButtonIsAvailable = is_fingerbot_in_push_mode

@dataclass
class TuyaBLEButtonMapping(TuyaBLEButtonMapping):
    description: ButtonEntityDescription = field(
        default_factory=lambda: ButtonEntityDescription(
            key="push",
            translation_key="push",
        )
    )
    is_available: TuyaBLEButtonIsAvailable = 0

@dataclass
class TuyaBLECategoryButtonMapping:
    products: dict[str, list[TuyaBLEButtonMapping]] | None = None
    mapping: list[TuyaBLEButtonMapping] | None = None


mapping: dict[str, TuyaBLECategoryButtonMapping] = {
    "szjqr": TuyaBLECategoryButtonMapping(
        products={
            **dict.fromkeys(
                ["3yqdo5yt", "xhf790if"],  # CubeTouch 1s and II
                [
                    TuyaBLEFingerbotModeMapping(dp_id=1),
                ],
            ),
            **dict.fromkeys(
                [
                    "blliqpsj",
                    "ndvkgsrm",
                    "yiihr7zh", 
                    "neq16kgd"
                ],  # Fingerbot Plus
                [
                    TuyaBLEFingerbotModeMapping(dp_id=2),
                ],
            ),
            **dict.fromkeys(
                [
                    "ltak7e1p",
                    "y6kttvd6",
                    "yrnk7mnn",
                    "nvr2rocq",
                    "bnt7wajf",
                    "rvdceqjh",
                    "5xhbk964",
                ],  # Fingerbot
                [
                    TuyaBLEFingerbotModeMapping(dp_id=2),
                ],
            ),
        },
    ),
    "jtmspro": TuyaBLECategoryButtonMapping(
        products={
            "hc7n0urm": [
                TuyaBLEButtonMapping(
                    dp_id=0,
                    description=ButtonEntityDescription(
                        key="force_lock",
                        translation_key="force_lock",
                        icon="mdi:lock-check",
                        entity_category=EntityCategory.CONFIG,
                    ),
                    force_add=True,
                    service_force=SERVICE_FORCE_LOCK,
                ),
                TuyaBLEButtonMapping(
                    dp_id=0,
                    description=ButtonEntityDescription(
                        key="force_unlock",
                        translation_key="force_unlock",
                        icon="mdi:lock-open-check",
                        entity_category=EntityCategory.CONFIG,
                    ),
                    force_add=True,
                    service_force=SERVICE_FORCE_UNLOCK,
                ),
            ],
        },
    ),
    "znhsb": TuyaBLECategoryButtonMapping(
        products={
            "cdlandip":  # Smart water bottle
            [
                TuyaBLEButtonMapping(
                    dp_id=109,
                    description=ButtonEntityDescription(
                        key="bright_lid_screen",
                    ),
                ),
            ],
        },
    ),
}


def get_mapping_by_device(device: TuyaBLEDevice) -> list[TuyaBLECategoryButtonMapping]:
    category = mapping.get(device.category)
    if category is not None and category.products is not None:
        product_mapping = category.products.get(device.product_id)
        if product_mapping is not None:
            return product_mapping
        if category.mapping is not None:
            return category.mapping
        else:
            return []
    else:
        return []


class TuyaBLEButton(TuyaBLEEntity, ButtonEntity):
    """Representation of a Tuya BLE Button."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: DataUpdateCoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLEButtonMapping,
        config_entry_id: str | None = None,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._mapping = mapping
        self._config_entry_id = config_entry_id

    def _lock_entity_id_for_force(self) -> str | None:
        if not self._config_entry_id:
            return None
        ent_reg = er.async_get(self.hass)
        manual_uid = f"{self._device.device_id}-manual_lock"
        for reg_entry in ent_reg.entities.values():
            if reg_entry.config_entry_id != self._config_entry_id:
                continue
            if reg_entry.domain != LOCK_ENTITY_DOMAIN:
                continue
            if reg_entry.unique_id == manual_uid:
                return reg_entry.entity_id
        for reg_entry in ent_reg.entities.values():
            if (
                reg_entry.config_entry_id == self._config_entry_id
                and reg_entry.domain == LOCK_ENTITY_DOMAIN
            ):
                return reg_entry.entity_id
        return None

    async def async_press(self) -> None:
        """Handle the button press."""
        if self._mapping.service_force:
            lock_eid = self._lock_entity_id_for_force()
            if not lock_eid:
                _LOGGER.warning(
                    "%s: no lock entity for force button (config %s)",
                    self._device.address,
                    self._config_entry_id,
                )
                return
            # Use integration-domain services (registered in __init__.py).
            # lock.force_* from async_register_entity_service is not always
            # resolvable the same way across HA versions / reload races.
            await self.hass.services.async_call(
                DOMAIN,
                self._mapping.service_force,
                {"entity_id": lock_eid},
                blocking=True,
            )
            return
        datapoint = self._device.datapoints.get_or_create(
            self._mapping.dp_id,
            TuyaBLEDataPointType.DT_BOOL,
            False,
        )
        if datapoint:
            await datapoint.set_value(not bool(datapoint.value))

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        result = super().available
        if result and self._mapping.is_available:
            result = self._mapping.is_available(self, self._product)
        return result


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Tuya BLE sensors."""
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    mappings = get_mapping_by_device(data.device)
    entities: list[TuyaBLEButton] = []
    for map_item in mappings:
        if map_item.force_add or data.device.datapoints.has_id(
            map_item.dp_id, map_item.dp_type
        ):
            entities.append(
                TuyaBLEButton(
                    hass,
                    data.coordinator,
                    data.device,
                    data.product,
                    map_item,
                    config_entry_id=entry.entry_id
                    if map_item.service_force
                    else None,
                )
            )
    async_add_entities(entities)
