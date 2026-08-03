"""Constants for the Proton MikroTik WireGuard integration."""

DOMAIN = "proton_mikrotik_wg"
DEFAULT_WG_INTERFACE = "wg-proton"
DEFAULT_WG_DEVICE_NAME = "ha-wg-proton"

SERVICE_PROVISION_WIREGUARD = "provision_wireguard"

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_TOTP = "totp"

CONF_UID = "uid"
CONF_ACCESS_TOKEN = "access_token"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_SCOPE = "scope"

CONF_WG_DEVICE_NAME = "wg_device_name"
CONF_WG_SERIAL_NUMBER = "wg_serial_number"
CONF_WG_CLIENT_PRIVATE_KEY = "wg_client_private_key"
CONF_WG_CLIENT_PUBLIC_KEY = "wg_client_public_key"
CONF_WG_SERVER_PUBLIC_KEY = "wg_server_public_key"
CONF_WG_ENDPOINT_HOST = "wg_endpoint_host"
CONF_WG_ENDPOINT_PORT = "wg_endpoint_port"
CONF_WG_CLIENT_ADDRESS = "wg_client_address"
CONF_WG_EXPIRATION_TIME = "wg_expiration_time"

CONF_MIKROTIK_HOST = "mikrotik_host"
CONF_MIKROTIK_USERNAME = "mikrotik_username"
CONF_MIKROTIK_PASSWORD = "mikrotik_password"
CONF_MIKROTIK_PORT = "mikrotik_port"
CONF_MIKROTIK_USE_SSL = "mikrotik_use_ssl"
CONF_MIKROTIK_WAN_GATEWAY = "mikrotik_wan_gateway"

DEFAULT_MIKROTIK_PORT = 8729
DEFAULT_MIKROTIK_USE_SSL = True

SERVICE_APPLY_WIREGUARD = "apply_wireguard"
