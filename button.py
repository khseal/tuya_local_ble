"""Force-command buttons for Raykube A1 Ultra."""
from __future__ import annotations

from dataclasses import dataclass
import logging

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.components.lock import DOMAIN as LOCK_ENTITY_DOMAIN
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    DOMAIN,
    SERVICE_FORCE_LOCK,
    SERVICE_FORCE_UNLOCK,
    SUPPORTED_CATEGORY,
    SUPPORTED_PRODUCT_ID,
)
from .devices import TuyaBLEData, TuyaBLEEntity, TuyaBLEProductInfo
from .tuya_ble import TuyaBLEDevice

_LOGGER = logging.getLogger(__name__)


@dataclass
class TuyaBLEButtonMapping:
    description: ButtonEntityDescription
    service_force: str


RAYKUBE_BUTTONS = [
    TuyaBLEButtonMapping(
        description=ButtonEntityDescription(
            key="force_lock",
            translation_key="force_lock",
            icon="mdi:lock-check",
            entity_category=EntityCategory.CONFIG,
        ),
        service_force=SERVICE_FORCE_LOCK,
    ),
    TuyaBLEButtonMapping(
        description=ButtonEntityDescription(
            key="force_unlock",
            translation_key="force_unlock",
            icon="mdi:lock-open-check",
            entity_category=EntityCategory.CONFIG,
        ),
        service_force=SERVICE_FORCE_UNLOCK,
    ),
]


def get_mapping_by_device(device: TuyaBLEDevice) -> list[TuyaBLEButtonMapping]:
    if device.category == SUPPORTED_CATEGORY and device.product_id == SUPPORTED_PRODUCT_ID:
        return RAYKUBE_BUTTONS
    return []


class TuyaBLEButton(TuyaBLEEntity, ButtonEntity):
    """Button invoking a Raykube force service."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: DataUpdateCoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLEButtonMapping,
        config_entry_id: str,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._mapping = mapping
        self._config_entry_id = config_entry_id

    def _lock_entity_id_for_force(self) -> str | None:
        ent_reg = er.async_get(self.hass)
        manual_uid = f"{self._device.device_id}-manual_lock"
        for reg_entry in ent_reg.entities.values():
            if (
                reg_entry.config_entry_id == self._config_entry_id
                and reg_entry.domain == LOCK_ENTITY_DOMAIN
                and reg_entry.unique_id == manual_uid
            ):
                return reg_entry.entity_id
        for reg_entry in ent_reg.entities.values():
            if (
                reg_entry.config_entry_id == self._config_entry_id
                and reg_entry.domain == LOCK_ENTITY_DOMAIN
            ):
                return reg_entry.entity_id
        return None

    async def async_press(self) -> None:
        lock_eid = self._lock_entity_id_for_force()
        if not lock_eid:
            _LOGGER.warning(
                "%s: no lock entity for force button (config %s)",
                self._device.address,
                self._config_entry_id,
            )
            return
        await self.hass.services.async_call(
            DOMAIN,
            self._mapping.service_force,
            {"entity_id": lock_eid},
            blocking=True,
        )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            TuyaBLEButton(
                hass,
                data.coordinator,
                data.device,
                data.product,
                mapping,
                config_entry_id=entry.entry_id,
            )
            for mapping in get_mapping_by_device(data.device)
        ]
    )
