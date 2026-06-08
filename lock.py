"""The Tuya BLE integration."""
from __future__ import annotations

from dataclasses import dataclass, field

import logging
from typing import Callable
from datetime import datetime, timedelta

from homeassistant.components.lock import (
    LockEntityDescription,
    LockEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import config_validation as cv, entity_platform
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later, async_track_time_interval
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN, SERVICE_FORCE_LOCK, SERVICE_FORCE_UNLOCK
from .devices import TuyaBLEData, TuyaBLEEntity, TuyaBLEProductInfo
from .tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice

_LOGGER = logging.getLogger(__name__)

TuyaBLELockIsAvailable = Callable[["TuyaBLELock", TuyaBLEProductInfo], bool] | None

from typing import Any

STATE_LOCKED = "locked"
STATE_UNLOCKED = "unlocked"
STATE_LOCKING = "locking"
STATE_UNLOCKING = "unlocking"
STATE_UNKNOWN = "unknown"

@dataclass
class TuyaBLELockMapping:
    dp_id: int
    dp_id_lock: int
    dp_id_unlock: int
    dp_id_nop: int
    keep_connect_timer: int
    description: LockEntityDescription
    force_add: bool = True
    keep_connect: bool = False
    dp_type: TuyaBLEDataPointType | None = None
    is_available: TuyaBLELockIsAvailable = None

@dataclass
class TuyaBLELockMapping(TuyaBLELockMapping):
    description: LockEntityDescription = field(
        default_factory=lambda: LockEntityDescription(
            key="push",
            translation_key="push",
        )
    )
    is_available: TuyaBLELockIsAvailable = None

@dataclass
class TuyaBLECategoryLockMapping:
    products: dict[str, list[TuyaBLELockMapping]] | None = None
    mapping: list[TuyaBLELockMapping] | None = None


mapping: dict[str, TuyaBLECategoryLockMapping] = {
    "jtmspro": TuyaBLECategoryLockMapping(
        products={
            "rlyxv7pe":  # Gimdow Smart Lock
            [
                TuyaBLELockMapping(
                    dp_id_unlock=6,
                    dp_id_lock=46,
                    dp_id=47,
                    # refer to sdk, dp 52 is for deleting temp password
                    # should be safe as a dummy keep alive message
                    dp_id_nop=52,
                    keep_connect=True,
                    keep_connect_timer=60,
                    description=LockEntityDescription(
                        key="manual_lock"
                    ),
                ),
            ],
            "hc7n0urm":  # A1 Ultra-JM Smart Lock
            [
                TuyaBLELockMapping(
                    dp_id_unlock=6,
                    dp_id_lock=46,
                    dp_id=47,
                    # refer to sdk, dp 52 is for deleting temp password
                    # should be safe as a dummy keep alive message
                    dp_id_nop=52,
                    keep_connect=False,
                    keep_connect_timer=60,
                    description=LockEntityDescription(
                        key="manual_lock"
                    ),
                ),
            ],
        }
    ), 
}


def get_mapping_by_device(device: TuyaBLEDevice) -> list[TuyaBLECategoryLockMapping]:
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


class TuyaBLELock(TuyaBLEEntity, LockEntity):
    """Representation of a Tuya BLE Lock."""

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
        self._datapoint_nop = None
        self._isjammed = False
        self._remove_keepalive: CALLBACK_TYPE | None = None
        # Cancels a pending self-heal that clears _commanded if the device
        # never sends a state DP update after a command.
        self._cmd_watchdog_unsub: CALLBACK_TYPE | None = None
        self._update_attrs()

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        if not self._mapping.keep_connect:
            return
        self._datapoint_nop = self._device.datapoints.get_or_create(
            self._mapping.dp_id_nop,
            TuyaBLEDataPointType.DT_BOOL,
            False,
        )
        self._remove_keepalive = async_track_time_interval(
            self.hass,
            self._async_keepalive,
            timedelta(seconds=self._mapping.keep_connect_timer),
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._remove_keepalive is not None:
            self._remove_keepalive()
            self._remove_keepalive = None
        self._cancel_cmd_watchdog()
        await super().async_will_remove_from_hass()

    def _cancel_cmd_watchdog(self) -> None:
        if self._cmd_watchdog_unsub is not None:
            self._cmd_watchdog_unsub()
            self._cmd_watchdog_unsub = None

    @callback
    def _async_cmd_watchdog(self, _now: datetime) -> None:
        """Clear the in-flight flag if the device never reported new state.

        Some firmware revisions of hc7n0urm acknowledge the V4 command but do
        not push a follow-up DP 47 update. Without this watchdog, _commanded
        would stay True forever and the dedupe path would block any further
        lock/unlock commands from HA.
        """
        self._cmd_watchdog_unsub = None
        if not self._commanded:
            return
        if self._current_state != self._target_state:
            _LOGGER.warning(
                "%s: %s command timed out without state update; marking jammed",
                self._device.address,
                self._target_state,
            )
            self._isjammed = True
        self._commanded = False
        self._update_attrs()
        self.async_write_ha_state()

    @callback
    def _async_keepalive(self, _now: datetime) -> None:
        """Periodic BLE keepalive (Gimdow only; hc7n0urm has keep_connect=False)."""
        if not self._coordinator.connected or self._datapoint_nop is None:
            return
        self.hass.async_create_task(self._datapoint_nop.set_value(True))

    @property
    def is_locked(self) -> bool | None:
        """Return true if device is locked."""
        if self._current_state == STATE_UNKNOWN:
            return None
        return self._current_state == STATE_LOCKED

    @property
    def is_locking(self) -> bool:
        """Return true if device is locking."""
        return (
            self._current_state == STATE_UNLOCKED
            and self._target_state == STATE_LOCKED
            and self._commanded
        )

    @property
    def is_unlocking(self) -> bool:
        """Return true if device is unlocking."""
        return (
            self._current_state == STATE_LOCKED
            and self._target_state == STATE_UNLOCKED
            and self._commanded
        )

    @property
    def is_jammed(self) -> bool | None:
        """Return true if device is jammed."""
        return self._isjammed

    # Alarm properties
    @property
    def should_poll(self) -> bool: return False

    def _update_attrs(self) -> None:
        self._attr_is_locking = self.is_locking
        self._attr_is_unlocking = self.is_unlocking
        self._attr_is_locked = self.is_locked
        # Until the first DP arrives we genuinely do not know the bolt state.
        # `not None == True` would have lied that the lock is unlocked and let
        # automations send a redundant lock command on every HA restart.
        self._attr_is_unlocked = (
            None if self._current_state == STATE_UNKNOWN
            else self._current_state == STATE_UNLOCKED
        )
        self._attr_is_jammed = self.is_jammed
        self._attr_changed_by = super().changed_by

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the device."""
        await self._set_lock_state(STATE_LOCKED)

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the device."""
        await self._set_lock_state(STATE_UNLOCKED)

    async def async_force_unlock(self) -> None:
        """Unlock even if HA already shows unlocked (sends BLE again, may beep)."""
        await self._set_lock_state(STATE_UNLOCKED, force=True)

    async def async_force_lock(self) -> None:
        """Lock even if HA already shows locked (sends BLE again, may beep)."""
        await self._set_lock_state(STATE_LOCKED, force=True)

    async def _set_lock_state(self, state: str, *, force: bool = False) -> None:
        # Self-heal a stale in-flight flag. If a previous command finished on
        # the device but no DP update came back, _commanded would otherwise
        # wedge the dedupe path below and the user could not issue any new
        # command until the watchdog fires.
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
                self._isjammed = True

        # Skip a true no-op only when nothing is pending and there is no error.
        # The lock beeps on every received ATT write, so re-sending lock when
        # already locked is audible noise; but if a previous command has not
        # completed, we must let this one through so the user is not stuck.
        if (
            not force
            and self._current_state == state
            and not self._isjammed
            and not self._commanded
        ):
            _LOGGER.debug(
                "%s: lock already %s, skip duplicate command",
                self._device.address,
                state,
            )
            return
        if self._commanded and self._target_state == state:
            _LOGGER.debug(
                "%s: %s command already in flight, skip duplicate",
                self._device.address,
                state,
            )
            return

        # Issuing a new command clears any prior jammed flag — we are about to
        # find out the real outcome.
        self._isjammed = False
        self._target_state = state
        self._commanded = True
        self._commanded_timer = datetime.now()
        self._cancel_cmd_watchdog()
        cmd_watchdog_sec = (
            30 if self._device.product_id == "hc7n0urm" else 15
        )
        self._cmd_watchdog_unsub = async_call_later(
            self.hass, cmd_watchdog_sec, self._async_cmd_watchdog,
        )
        self._update_attrs()
        self.async_write_ha_state()

        if self._target_state == STATE_UNLOCKED:
            dp_id = self._mapping.dp_id_unlock
        else:
            dp_id = self._mapping.dp_id_lock

        datapoint = self._device.datapoints.get_or_create(
            dp_id,
            TuyaBLEDataPointType.DT_BOOL,
            False,
        )

        # Fire-and-forget keeps the HA service call snappy; the wrapper
        # surfaces a hard failure as is_jammed instead of swallowing it
        # silently in the BLE stack.
        self._hass.async_create_task(self._execute_lock_command(datapoint, state))

    async def _execute_lock_command(self, datapoint, state: str) -> None:
        try:
            await datapoint.set_value(True)
        except Exception:
            _LOGGER.exception(
                "%s: %s command failed",
                self._device.address,
                state,
            )
            if self._commanded and self._target_state == state:
                self._commanded = False
                self._isjammed = True
                self._cancel_cmd_watchdog()
                self._update_attrs()
                self.async_write_ha_state()


    def update_device_state(self):
        datapoint = self._device.datapoints[self._mapping.dp_id]
        if datapoint:
            if datapoint.value:
                self._current_state = STATE_UNLOCKED
            else:
                self._current_state = STATE_LOCKED
            if self._commanded:
                if ( self._current_state != self._target_state):
                    if ( datetime.now() > self._commanded_timer + timedelta(seconds = 12) ):
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
    entities: list[TuyaBLELock] = []
    for mapping in mappings:
        if mapping.force_add or data.device.datapoints.has_id(
            mapping.dp_id, mapping.dp_type
        ):
            entities.append(
                TuyaBLELock(
                    hass,
                    data.coordinator,
                    data.device,
                    data.product,
                    mapping,
                )
            )
    async_add_entities(entities)

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