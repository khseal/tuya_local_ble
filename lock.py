"""Lock entity for Raykube A1 Ultra."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.components.lock import LockEntity, LockEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import config_validation as cv, entity_platform
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    DOMAIN,
    SERVICE_FORCE_LOCK,
    SERVICE_FORCE_UNLOCK,
    SUPPORTED_CATEGORY,
    SUPPORTED_PRODUCT_ID,
)
from .devices import TuyaBLEData, TuyaBLEEntity, TuyaBLEProductInfo
from .tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice

_LOGGER = logging.getLogger(__name__)

STATE_LOCKED = "locked"
STATE_UNLOCKED = "unlocked"
STATE_UNKNOWN = "unknown"


@dataclass
class TuyaBLELockMapping:
    dp_id: int
    dp_id_lock: int
    dp_id_unlock: int
    description: LockEntityDescription


RAYKUBE_LOCK = TuyaBLELockMapping(
    dp_id_unlock=6,
    dp_id_lock=46,
    dp_id=47,
    description=LockEntityDescription(key="manual_lock"),
)


def get_mapping_by_device(device: TuyaBLEDevice) -> list[TuyaBLELockMapping]:
    if device.category == SUPPORTED_CATEGORY and device.product_id == SUPPORTED_PRODUCT_ID:
        return [RAYKUBE_LOCK]
    return []


class TuyaBLELock(TuyaBLEEntity, LockEntity):
    """Representation of the Raykube A1 Ultra lock."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: DataUpdateCoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLELockMapping,
    ) -> None:
        super().__init__(hass, coordinator, device, product, mapping.description)
        self._mapping = mapping
        self._current_state = STATE_UNKNOWN
        self._target_state = None
        self._commanded = False
        self._commanded_timer = None
        self._isjammed = False
        self._cmd_watchdog_unsub: CALLBACK_TYPE | None = None
        self._update_attrs()

    async def async_will_remove_from_hass(self) -> None:
        self._cancel_cmd_watchdog()
        await super().async_will_remove_from_hass()

    def _cancel_cmd_watchdog(self) -> None:
        if self._cmd_watchdog_unsub is not None:
            self._cmd_watchdog_unsub()
            self._cmd_watchdog_unsub = None

    @callback
    def _async_cmd_watchdog(self, _now: datetime) -> None:
        """Stop waiting when the device did not report a new bolt state."""
        self._cmd_watchdog_unsub = None
        if not self._commanded:
            return
        if self._current_state != self._target_state:
            _LOGGER.warning(
                "%s: %s command ended without DP 47; physical state is unknown",
                self._device.address,
                self._target_state,
            )
            self._current_state = STATE_UNKNOWN
            self._isjammed = False
        self._commanded = False
        self._update_attrs()
        self.async_write_ha_state()

    @property
    def is_locked(self) -> bool | None:
        if self._current_state == STATE_UNKNOWN:
            return None
        return self._current_state == STATE_LOCKED

    @property
    def is_locking(self) -> bool:
        return (
            self._current_state == STATE_UNLOCKED
            and self._target_state == STATE_LOCKED
            and self._commanded
        )

    @property
    def is_unlocking(self) -> bool:
        return (
            self._current_state == STATE_LOCKED
            and self._target_state == STATE_UNLOCKED
            and self._commanded
        )

    @property
    def is_jammed(self) -> bool:
        return self._isjammed

    @property
    def should_poll(self) -> bool:
        return False

    def _update_attrs(self) -> None:
        self._attr_is_locking = self.is_locking
        self._attr_is_unlocking = self.is_unlocking
        self._attr_is_locked = self.is_locked
        self._attr_is_unlocked = (
            None
            if self._current_state == STATE_UNKNOWN
            else self._current_state == STATE_UNLOCKED
        )
        self._attr_is_jammed = self.is_jammed
        self._attr_changed_by = super().changed_by

    async def async_lock(self, **kwargs: Any) -> None:
        await self._set_lock_state(STATE_LOCKED)

    async def async_unlock(self, **kwargs: Any) -> None:
        await self._set_lock_state(STATE_UNLOCKED)

    async def async_force_unlock(self) -> None:
        """Unlock even if HA already shows unlocked; the lock may beep."""
        await self._set_lock_state(STATE_UNLOCKED, force=True)

    async def async_force_lock(self) -> None:
        """Lock even if HA already shows locked; the lock may beep."""
        await self._set_lock_state(STATE_LOCKED, force=True)

    async def _set_lock_state(self, state: str, *, force: bool = False) -> None:
        if (
            self._commanded
            and self._commanded_timer is not None
            and datetime.now() > self._commanded_timer + timedelta(seconds=15)
        ):
            _LOGGER.warning(
                "%s: previous %s command stale (no state update), resetting",
                self._device.address,
                self._target_state,
            )
            self._commanded = False
            self._cancel_cmd_watchdog()
            if self._current_state != self._target_state:
                self._current_state = STATE_UNKNOWN

        # Avoid an audible duplicate command when the desired state is already
        # confirmed by DP 47. Force services intentionally bypass this check.
        if (
            not force
            and self._current_state == state
            and not self._isjammed
            and not self._commanded
        ):
            _LOGGER.debug(
                "%s: lock already %s, skip duplicate command", self._device.address, state
            )
            return
        if self._commanded and self._target_state == state:
            _LOGGER.debug(
                "%s: %s command already in flight, skip duplicate",
                self._device.address,
                state,
            )
            return

        self._isjammed = False
        self._target_state = state
        self._commanded = True
        self._commanded_timer = datetime.now()
        self._cancel_cmd_watchdog()
        self._cmd_watchdog_unsub = async_call_later(
            self.hass, 30, self._async_cmd_watchdog
        )
        self._update_attrs()
        self.async_write_ha_state()

        dp_id = (
            self._mapping.dp_id_unlock
            if state == STATE_UNLOCKED
            else self._mapping.dp_id_lock
        )
        datapoint = self._device.datapoints.get_or_create(
            dp_id, TuyaBLEDataPointType.DT_BOOL, False
        )
        self._hass.async_create_task(self._execute_lock_command(datapoint, state))

    async def _execute_lock_command(self, datapoint, state: str) -> None:
        try:
            await datapoint.set_value(True)
        except Exception:
            _LOGGER.exception("%s: %s command failed", self._device.address, state)
            if self._commanded and self._target_state == state:
                self._commanded = False
                self._isjammed = True
                self._cancel_cmd_watchdog()
                self._update_attrs()
                self.async_write_ha_state()

    def update_device_state(self) -> None:
        datapoint = self._device.datapoints[self._mapping.dp_id]
        if not datapoint:
            return
        self._current_state = STATE_UNLOCKED if datapoint.value else STATE_LOCKED
        if self._commanded:
            if self._current_state != self._target_state:
                if datetime.now() > self._commanded_timer + timedelta(seconds=12):
                    self._isjammed = True
                    self._commanded = False
                    self._cancel_cmd_watchdog()
            else:
                self._commanded = False
                self._isjammed = False
                self._cancel_cmd_watchdog()

    @callback
    def _handle_coordinator_update(self) -> None:
        self.update_device_state()
        self._update_attrs()
        self.async_write_ha_state()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            TuyaBLELock(
                hass, data.coordinator, data.device, data.product, mapping
            )
            for mapping in get_mapping_by_device(data.device)
        ]
    )

    entity_platform.async_get_current_platform().async_register_entity_service(
        SERVICE_FORCE_UNLOCK,
        cv.make_entity_service_schema({}),
        "async_force_unlock",
    )
    entity_platform.async_get_current_platform().async_register_entity_service(
        SERVICE_FORCE_LOCK,
        cv.make_entity_service_schema({}),
        "async_force_lock",
    )
