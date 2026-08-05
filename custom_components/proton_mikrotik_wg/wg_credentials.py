"""Create Proton VPN WireGuard credentials via the certificate API."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

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
    exit_country: str = ""


@dataclass(frozen=True)
class WireGuardKeyPair:
    """Keys for MikroTik (X25519) and Proton's certificate API (Ed25519)."""

    private_key: str
    public_key: str
    api_public_key: str


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
    """Generate Proton-compatible keys: Ed25519 for API, X25519 for WireGuard.

    Proton's certificate endpoint rejects standard ``wg genkey`` X25519 public
    keys ("Unable to read the key, please provide a valid EC key"). The account
    UI posts a raw Ed25519 public key (base64 of 32 bytes) and uses the X25519
    private key derived from that Ed25519 seed in the WireGuard config.
    """
    import base64
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    ed_private = Ed25519PrivateKey.generate()
    seed = ed_private.private_bytes_raw()
    api_public_key = base64.b64encode(
        ed_private.public_key().public_bytes_raw()
    ).decode("ascii")

    digest = bytearray(hashlib.sha512(seed).digest()[:32])
    digest[0] &= 248
    digest[31] &= 127
    digest[31] |= 64
    x_private = X25519PrivateKey.from_private_bytes(bytes(digest))
    return WireGuardKeyPair(
        private_key=base64.b64encode(x_private.private_bytes_raw()).decode("ascii"),
        public_key=base64.b64encode(
            x_private.public_key().public_bytes_raw()
        ).decode("ascii"),
        api_public_key=api_public_key,
    )


def list_logical_servers(
    session: ProtonApiSession,
    *,
    max_tier: int | None = None,
    exit_country: str | None = None,
) -> list[ProtonLogicalServer]:
    """Fetch online shared Proton logical servers suitable for plain WireGuard.

    Mirrors Proton's WireGuard UI filters: online, not Secure Core/TOR, optional
    max account tier, optional ExitCountry, and at least one instance with an
    X25519 public key.
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
        country = str(logical.get("ExitCountry") or "").upper()
        if exit_country and country != exit_country.upper():
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
                exit_country=country,
            )
        )
    return servers


def list_exit_countries(
    session: ProtonApiSession,
    *,
    max_tier: int | None = None,
) -> list[str]:
    """Return sorted unique ExitCountry codes from usable WireGuard logicals."""
    countries = {
        server.exit_country
        for server in list_logical_servers(session, max_tier=max_tier)
        if server.exit_country
    }
    return sorted(countries)


def pick_least_loaded_server(
    servers: list[ProtonLogicalServer],
) -> ProtonLogicalServer:
    """Return the online server with the lowest Proton Score (best first)."""
    if not servers:
        raise ValueError("no Proton servers available")
    return min(servers, key=lambda server: server.score)


def pick_best_servers(
    servers: list[ProtonLogicalServer],
    *,
    count: int,
) -> list[ProtonLogicalServer]:
    """Return up to ``count`` distinct logicals ordered by best (lowest) Score.

    Distinct means unique logical name and unique entry IP.
    """
    if count < 1:
        raise ValueError("count must be at least 1")
    if not servers:
        raise ValueError("no Proton servers available")
    ordered = sorted(servers, key=lambda server: server.score)
    picked: list[ProtonLogicalServer] = []
    used_names: set[str] = set()
    used_ips: set[str] = set()
    for server in ordered:
        if server.name in used_names or server.entry_ip in used_ips:
            continue
        picked.append(server)
        used_names.add(server.name)
        used_ips.add(server.entry_ip)
        if len(picked) >= count:
            return picked
    raise ValueError(
        f"not enough distinct Proton servers: need {count}, found {len(picked)}"
    )


def create_wireguard_credential(
    session: ProtonApiSession,
    *,
    server: ProtonLogicalServer,
    keys: WireGuardKeyPair,
    device_name: str,
) -> WireGuardCredential:
    """Register a persistent WireGuard certificate for one Proton server."""
    payload = {
        "ClientPublicKey": keys.api_public_key,
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
    keep_serial: str | None = None,
    keep_serials: set[str] | frozenset[str] | None = None,
    name_prefix: str = HA_WG_DEVICE_PREFIX,
) -> tuple[list[str], list[str]]:
    """Best-effort delete older HA-managed certs; keep listed serials.

    Returns (deleted_serials, failure_messages). Delete may fail with Proton
    scope errors (9100); callers should treat that as non-fatal.
    """
    keep = set(keep_serials or ())
    if keep_serial is not None:
        keep.add(keep_serial)
    deleted: list[str] = []
    failed: list[str] = []
    for cert in list_persistent_certificates(session):
        serial = str(cert.get("SerialNumber") or "")
        name = str(cert.get("DeviceName") or "")
        if not serial or serial in keep:
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


def _slot_device_name(slot: int, *, stamp: str | None = None) -> str:
    from datetime import datetime, timezone

    if stamp is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{HA_WG_DEVICE_PREFIX}-{slot}-{stamp}"


def provision_wireguard_slots(
    session: ProtonApiSession,
    *,
    count: int,
    existing: Mapping[int, WireGuardCredential] | None = None,
    slot: int | None = None,
    exit_country: str | None = None,
) -> dict[int, WireGuardCredential]:
    """Provision ``count`` tunnels (or one ``slot``) on distinct Proton servers."""
    if count < 1:
        raise ValueError("count must be at least 1")
    current = dict(existing or {})
    slots_to_provision = [slot] if slot is not None else list(range(1, count + 1))
    for target in slots_to_provision:
        if target < 1 or target > count:
            raise ValueError(f"slot must be between 1 and {count}, got {target}")

    country = exit_country or None
    if country and country.lower() == "any":
        country = None

    max_tier = fetch_vpn_max_tier(session)
    available = list_logical_servers(
        session, max_tier=max_tier, exit_country=country
    )

    if slot is None:
        servers = pick_best_servers(available, count=count)
        result: dict[int, WireGuardCredential] = {}
        for index, server in enumerate(servers, start=1):
            keys = generate_wireguard_keypair()
            result[index] = create_wireguard_credential(
                session,
                server=server,
                keys=keys,
                device_name=_slot_device_name(index),
            )
    else:
        used_ips = {
            cred.endpoint_host for s, cred in current.items() if s != slot and s <= count
        }
        candidates = [
            server for server in available if server.entry_ip not in used_ips
        ]
        server = pick_best_servers(candidates or available, count=1)[0]
        keys = generate_wireguard_keypair()
        result = {
            s: cred for s, cred in current.items() if s <= count and s != slot
        }
        result[slot] = create_wireguard_credential(
            session,
            server=server,
            keys=keys,
            device_name=_slot_device_name(slot),
        )

    keep = {cred.serial_number for cred in result.values()}
    deleted, failed = cleanup_previous_ha_certificates(session, keep_serials=keep)
    if deleted:
        _LOGGER.info("Deleted previous HA WireGuard certs: %s", ", ".join(deleted))
    if failed:
        _LOGGER.warning(
            "Could not delete previous HA WireGuard certs "
            "(delete may need Proton account UI): %s",
            "; ".join(failed),
        )
    return dict(sorted(result.items()))
