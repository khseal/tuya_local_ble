"""The Tuya BLE integration."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from homeassistant.const import CONF_ADDRESS, CONF_DEVICE_ID
from homeassistant.core import HomeAssistant

from .tuya_ble import (
    AbstaractTuyaBLEDeviceManager,
    TuyaBLEDeviceCredentials,
)

from .const import (
    CONF_CRED_FILE,
    CONF_PRODUCT_MODEL,
    CONF_UUID,
    CONF_LOCAL_KEY,
    CONF_CATEGORY,
    CONF_PRODUCT_ID,
    CONF_DEVICE_NAME,
    CONF_PRODUCT_NAME,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

CONF_TUYA_DEVICE_KEYS = [
    CONF_UUID,
    CONF_LOCAL_KEY,
    CONF_DEVICE_ID,
    CONF_CATEGORY,
    CONF_PRODUCT_ID,
    CONF_DEVICE_NAME,
    CONF_PRODUCT_MODEL,
    CONF_PRODUCT_NAME,
]


def _sync_load_devices_json(path: str) -> tuple[dict[str, Any], str | None]:
    """Read and parse devices.json in a worker thread (blocking I/O)."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        _LOGGER.warning("Credentials file not found: %s", path)
        return {}, "file_not_found"
    except json.JSONDecodeError as err:
        _LOGGER.error(
            "Invalid JSON in %s (line %s, column %s): %s",
            path,
            err.lineno,
            err.colno,
            err.msg,
        )
        return {}, "invalid_json"
    except OSError as err:
        _LOGGER.error("Cannot read %s: %s", path, err)
        return {}, "read_error"

    if not isinstance(raw, dict):
        _LOGGER.error("Root of %s must be a JSON object, got %s", path, type(raw))
        return {}, "invalid_structure"
    return raw, None


class HASSTuyaBLEDeviceManager(AbstaractTuyaBLEDeviceManager):
    """Cloud connected manager of the Tuya BLE devices credentials."""

    def __init__(self, hass: HomeAssistant, data: dict[str, Any]) -> None:
        assert hass is not None
        self._hass = hass
        self._data = data
        self._devicedata: dict[str, Any] = {}
        self._credentials_loaded = False
        self._load_error: str | None = None

    @property
    def load_error(self) -> str | None:
        """Set after async_load_devices_file: invalid_json, file_not_found, etc."""
        return self._load_error

    async def async_load_devices_file(self) -> None:
        """Load devices.json via executor (avoid blocking the event loop)."""
        if self._credentials_loaded:
            return
        path = os.path.join(self._hass.config.config_dir, CONF_CRED_FILE)
        self._devicedata, self._load_error = await asyncio.to_thread(
            _sync_load_devices_json, path
        )
        self._credentials_loaded = True

    async def get_device_credentials(
        self,
        address: str,
        force_update: bool = False,
        save_data: bool = False,
    ) -> TuyaBLEDeviceCredentials | None:
        """Get credentials of the Tuya BLE device."""
        await self.async_load_devices_file()

        credentials: dict[str, Any] | None = self._devicedata.get(address)
        result: TuyaBLEDeviceCredentials | None = None

        if credentials:
            result = TuyaBLEDeviceCredentials(
                credentials.get(CONF_UUID, ""),
                credentials.get(CONF_LOCAL_KEY, ""),
                credentials.get(CONF_DEVICE_ID, ""),
                credentials.get(CONF_CATEGORY, ""),
                credentials.get(CONF_PRODUCT_ID, ""),
                credentials.get(CONF_DEVICE_NAME, ""),
                credentials.get(CONF_PRODUCT_MODEL, ""),
                credentials.get(CONF_PRODUCT_NAME, ""),
                credentials.get("unlock_token", ""),
            )
            _LOGGER.debug("Retrieved: %s", result)

        return result

    @property
    def data(self) -> dict[str, Any]:
        return self._data
