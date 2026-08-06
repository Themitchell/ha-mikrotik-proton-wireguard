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
CONF_WG_SERVER_NAME = "wg_server_name"
CONF_WG_PROVISIONED_AT = "wg_provisioned_at"
CONF_WG_SLOTS = "wg_slots"
CONF_TUNNEL_COUNT = "tunnel_count"
CONF_VPN_EXIT_COUNTRY = "vpn_exit_country"

MIN_TUNNEL_COUNT = 1
MAX_TUNNEL_COUNT = 20
DEFAULT_TUNNEL_COUNT = 3
VPN_EXIT_COUNTRY_ANY = "any"

CONF_MIKROTIK_HOST = "mikrotik_host"
CONF_MIKROTIK_USERNAME = "mikrotik_username"
CONF_MIKROTIK_PASSWORD = "mikrotik_password"
CONF_MIKROTIK_PORT = "mikrotik_port"
CONF_MIKROTIK_USE_SSL = "mikrotik_use_ssl"
CONF_MIKROTIK_WAN_GATEWAY = "mikrotik_wan_gateway"

DEFAULT_MIKROTIK_PORT = 8729
DEFAULT_MIKROTIK_USE_SSL = True

SERVICE_APPLY_WIREGUARD = "apply_wireguard"

CONF_EGRESS_ENABLED = "egress_enabled"
CONF_VPN_BYPASS_CIDRS = "vpn_bypass_cidrs"

CONF_WG_REFRESH_INTERVAL = "wg_refresh_interval"
CONF_WG_REFRESH_LAST_AT = "wg_refresh_last_at"
WG_REFRESH_DAILY = "daily"
WG_REFRESH_WEEKLY = "weekly"
WG_REFRESH_MONTHLY = "monthly"
DEFAULT_WG_REFRESH_INTERVAL = WG_REFRESH_MONTHLY
WG_REFRESH_INTERVALS = (WG_REFRESH_DAILY, WG_REFRESH_WEEKLY, WG_REFRESH_MONTHLY)
