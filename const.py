"""Constants for the Raykube A1 Ultra BLE integration."""
from __future__ import annotations

from typing_extensions import Final

DOMAIN: Final = "tuya_local_ble"
SUPPORTED_CATEGORY: Final = "jtmspro"
SUPPORTED_PRODUCT_ID: Final = "hc7n0urm"

DEVICE_METADATA_UUIDS: Final = "uuids"
DEVICE_DEF_MANUFACTURER: Final = "Tuya"
SET_DISCONNECTED_DELAY = 10 * 60

CONF_UUID: Final = "uuid"
CONF_LOCAL_KEY: Final = "local_key"
CONF_CATEGORY: Final = "category"
CONF_PRODUCT_ID: Final = "product_id"
CONF_DEVICE_NAME: Final = "device_name"
CONF_PRODUCT_MODEL: Final = "product_model"
CONF_PRODUCT_NAME: Final = "product_name"
CONF_CRED_FILE = DOMAIN + "/devices.json"

BATTERY_STATE_LOW: Final = "low"
BATTERY_STATE_NORMAL: Final = "normal"
BATTERY_STATE_HIGH: Final = "high"

SERVICE_FORCE_UNLOCK: Final = "force_unlock"
SERVICE_FORCE_LOCK: Final = "force_lock"
