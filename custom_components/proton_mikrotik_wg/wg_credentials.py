"""Create Proton VPN WireGuard credentials via the certificate API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

DEFAULT_WG_PORT = 51820
DEFAULT_CLIENT_ADDRESS = "10.2.0.2/32"


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


def list_logical_servers(session: ProtonApiSession) -> list[ProtonLogicalServer]:
    """Fetch online shared Proton logical servers with at least one instance."""
    payload = session.api_request("/vpn/logicals", method="get")
    servers: list[ProtonLogicalServer] = []
    for logical in payload.get("LogicalServers") or []:
        if logical.get("Status") != 1:
            continue
        instances = logical.get("Servers") or []
        if not instances:
            continue
        instance = instances[0]
        servers.append(
            ProtonLogicalServer(
                name=str(logical["Name"]),
                entry_ip=str(instance["EntryIP"]),
                x25519_public_key=str(instance["X25519PublicKey"]),
                load=int(logical.get("Load") or 100),
            )
        )
    return servers


def pick_least_loaded_server(
    servers: list[ProtonLogicalServer],
) -> ProtonLogicalServer:
    """Return the online server with the lowest reported load."""
    if not servers:
        raise ValueError("no Proton servers available")
    return min(servers, key=lambda server: server.load)


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


def provision_wireguard_credential(
    session: ProtonApiSession,
    *,
    device_name: str,
    server: ProtonLogicalServer | None = None,
) -> WireGuardCredential:
    """Generate keys and register a certificate for the least-loaded server."""
    chosen = server or pick_least_loaded_server(list_logical_servers(session))
    keys = generate_wireguard_keypair()
    return create_wireguard_credential(
        session,
        server=chosen,
        keys=keys,
        device_name=device_name,
    )
