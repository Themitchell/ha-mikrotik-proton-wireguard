"""Create Proton VPN WireGuard credentials via the certificate API."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol

_LOGGER = logging.getLogger(__name__)

DEFAULT_WG_PORT = 51820
DEFAULT_CLIENT_ADDRESS = "10.2.0.2/32"
HA_WG_DEVICE_PREFIX = "ha-wg-proton"
CERTIFICATE_PAGE_SIZE = 50
# Proton logical Features bits: Secure Core=1, TOR=2 (same as Proton WebClients).
FEATURE_SECURE_CORE = 1
FEATURE_TOR = 2
FEATURE_SECURE_CORE_OR_TOR = FEATURE_SECURE_CORE | FEATURE_TOR


class ProtonApiSession(Protocol):
    """Minimal session surface needed to register a WireGuard certificate."""

    def api_request(
        self,
        endpoint: str,
        jsondata: dict[str, Any] | None = None,
        *,
        method: str | None = None,
    ) -> dict[str, Any]:
        ...


@dataclass(frozen=True)
class ProtonLogicalServer:
    """One shared Proton logical server used as the WireGuard peer."""

    name: str
    entry_ip: str
    x25519_public_key: str
    load: int = 100
    score: float = 100.0
    tier: int = 0


@dataclass(frozen=True)
class WireGuardKeyPair:
    """WireGuard X25519 key material (standard base64 encodings)."""

    private_key: str
    public_key: str


@dataclass(frozen=True)
class WireGuardCredential:
    """Ready-to-apply Proton WireGuard peer config (no Proton DNS)."""

    device_name: str
    serial_number: str
    client_private_key: str
    client_public_key: str
    server_public_key: str
    endpoint_host: str
    endpoint_port: int
    client_address: str
    expiration_time: int
    dns: str | None = None


def generate_wireguard_keypair() -> WireGuardKeyPair:
    """Generate a local WireGuard X25519 keypair (no Proton API call)."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes_raw()
    public_raw = private.public_key().public_bytes_raw()
    return WireGuardKeyPair(
        private_key=base64.b64encode(private_raw).decode("ascii"),
        public_key=base64.b64encode(public_raw).decode("ascii"),
    )


def list_logical_servers(
    session: ProtonApiSession,
    *,
    max_tier: int | None = None,
) -> list[ProtonLogicalServer]:
    """Fetch online shared Proton logical servers suitable for plain WireGuard.

    Mirrors Proton's WireGuard UI filters: online, not Secure Core/TOR, optional
    max account tier, and at least one instance with an X25519 public key.
    """
    payload = session.api_request("/vpn/logicals", method="get")
    servers: list[ProtonLogicalServer] = []
    for logical in payload.get("LogicalServers") or []:
        if logical.get("Status") != 1:
            continue
        features = int(logical.get("Features") or 0)
        if features & FEATURE_SECURE_CORE_OR_TOR:
            continue
        tier = int(logical.get("Tier") or 0)
        if max_tier is not None and tier > max_tier:
            continue
        instances = [
            instance
            for instance in (logical.get("Servers") or [])
            if instance.get("X25519PublicKey")
        ]
        if not instances:
            continue
        instance = instances[0]
        servers.append(
            ProtonLogicalServer(
                name=str(logical["Name"]),
                entry_ip=str(instance["EntryIP"]),
                x25519_public_key=str(instance["X25519PublicKey"]),
                load=int(logical.get("Load") or 100),
                score=float(logical.get("Score") or 100.0),
                tier=tier,
            )
        )
    return servers


def pick_least_loaded_server(
    servers: list[ProtonLogicalServer],
) -> ProtonLogicalServer:
    """Return the online server with the lowest Proton Score (best first)."""
    if not servers:
        raise ValueError("no Proton servers available")
    return min(servers, key=lambda server: server.score)


def create_wireguard_credential(
    session: ProtonApiSession,
    *,
    server: ProtonLogicalServer,
    keys: WireGuardKeyPair,
    device_name: str,
) -> WireGuardCredential:
    """Register a persistent WireGuard certificate for one Proton server."""
    payload = {
        "ClientPublicKey": keys.public_key,
        "Mode": "persistent",
        "DeviceName": device_name,
        "Features": {
            "peerName": server.name,
            "peerIp": server.entry_ip,
            "peerPublicKey": server.x25519_public_key,
            "platform": "Linux",
            "NetShieldLevel": 0,
            "RandomNAT": True,
            "PortForwarding": False,
            "SplitTCP": True,
            "SafeMode": False,
        },
    }
    response = session.api_request("/vpn/v1/certificate", payload, method="post")
    return WireGuardCredential(
        device_name=str(response.get("DeviceName") or device_name),
        serial_number=str(response["SerialNumber"]),
        client_private_key=keys.private_key,
        client_public_key=keys.public_key,
        server_public_key=server.x25519_public_key,
        endpoint_host=server.entry_ip,
        endpoint_port=DEFAULT_WG_PORT,
        client_address=DEFAULT_CLIENT_ADDRESS,
        expiration_time=int(response["ExpirationTime"]),
        dns=None,
    )


def list_persistent_certificates(session: ProtonApiSession) -> list[dict[str, Any]]:
    """Return all persistent WireGuard certificates on the Proton account."""
    offset = 0
    certificates: list[dict[str, Any]] = []
    while True:
        payload = session.api_request(
            "/vpn/v1/certificate/all"
            f"?Mode=persistent&Offset={offset}&Limit={CERTIFICATE_PAGE_SIZE}",
            method="get",
        )
        batch = list(payload.get("Certificates") or [])
        certificates.extend(batch)
        if len(batch) < CERTIFICATE_PAGE_SIZE:
            return certificates
        offset += CERTIFICATE_PAGE_SIZE


def delete_certificate(session: ProtonApiSession, *, serial_number: str) -> None:
    """Revoke one persistent WireGuard certificate by serial number."""
    session.api_request(
        "/vpn/v1/certificate",
        {"SerialNumber": serial_number},
        method="delete",
    )


def _is_ha_managed_device_name(
    device_name: str, *, name_prefix: str = HA_WG_DEVICE_PREFIX
) -> bool:
    return device_name == name_prefix or device_name.startswith(f"{name_prefix}-")


def cleanup_previous_ha_certificates(
    session: ProtonApiSession,
    *,
    keep_serial: str,
    name_prefix: str = HA_WG_DEVICE_PREFIX,
) -> tuple[list[str], list[str]]:
    """Best-effort delete older HA-managed certs; keep the newly provisioned one.

    Returns (deleted_serials, failure_messages). Delete may fail with Proton
    scope errors (9100); callers should treat that as non-fatal.
    """
    deleted: list[str] = []
    failed: list[str] = []
    for cert in list_persistent_certificates(session):
        serial = str(cert.get("SerialNumber") or "")
        name = str(cert.get("DeviceName") or "")
        if not serial or serial == keep_serial:
            continue
        if not _is_ha_managed_device_name(name, name_prefix=name_prefix):
            continue
        try:
            delete_certificate(session, serial_number=serial)
        except Exception as err:  # noqa: BLE001 — best-effort cleanup
            failed.append(f"{serial}: {err}")
            continue
        deleted.append(serial)
    return deleted, failed


def fetch_vpn_max_tier(session: ProtonApiSession) -> int | None:
    """Return account MaxTier from /vpn, or None if unavailable.

    None means do not filter by tier (still exclude Secure Core/TOR).
    """
    try:
        payload = session.api_request("/vpn", method="get")
    except Exception:  # noqa: BLE001 — fall back to unscoped server list
        return None
    vpn = payload.get("VPN") or {}
    if "MaxTier" not in vpn:
        return None
    return int(vpn["MaxTier"])


def provision_wireguard_credential(
    session: ProtonApiSession,
    *,
    device_name: str,
    server: ProtonLogicalServer | None = None,
) -> WireGuardCredential:
    """Generate keys, register a certificate, and clean up prior HA certs."""
    if server is None:
        max_tier = fetch_vpn_max_tier(session)
        server = pick_least_loaded_server(
            list_logical_servers(session, max_tier=max_tier)
        )
    keys = generate_wireguard_keypair()
    cred = create_wireguard_credential(
        session,
        server=server,
        keys=keys,
        device_name=device_name,
    )
    deleted, failed = cleanup_previous_ha_certificates(
        session, keep_serial=cred.serial_number
    )
    if deleted:
        _LOGGER.info("Deleted previous HA WireGuard certs: %s", ", ".join(deleted))
    if failed:
        _LOGGER.warning(
            "Could not delete previous HA WireGuard certs "
            "(delete may need Proton account UI): %s",
            "; ".join(failed),
        )
    return cred
