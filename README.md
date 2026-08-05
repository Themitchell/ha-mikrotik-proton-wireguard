# Proton MikroTik WireGuard

Home Assistant **custom integration** that logs into Proton VPN, provisions
**N** WireGuard certificates (1–20, default **3**), applies them to MikroTik
`wg-proton-1` … `wg-proton-N`, and exposes a switch for **ECMP** whole-home
egress across those tunnels.

## Layout

```
AGENTS.md
custom_components/proton_mikrotik_wg/   # drop into HA /config/custom_components/
tests/
```

## Setup (user)

### HACS (recommended)

1. HACS → Custom repositories → add
   `https://github.com/Themitchell/ha-mikrotik-proton-wireguard`
   (category: Integration).
2. Download **Proton MikroTik WireGuard**, then restart Home Assistant.
3. **Settings → Devices & services → Add integration → Proton MikroTik WireGuard**.
4. Enter Proton account email and password (login is verified).
5. If 2FA is enabled, enter the TOTP code.

### Manual

1. Copy `custom_components/proton_mikrotik_wg` to HA `/config/custom_components/`.
2. Restart Home Assistant, then Add integration as above.

### Proton session

- Stores session tokens on the config entry (not your password)
- Refreshes tokens on startup and every 12 hours
- Marks the entry as needing reauth if refresh fails

Login uses a gpg-free HTTP/SRP client so it works on typical Home Assistant
containers (no system `gpg` required). Use your Proton **account** email
(e.g. `you@proton.me`), not OpenVPN credentials.

### Configure MikroTik (options)

Settings → Devices & services → Proton MikroTik WireGuard → **Configure**:

| Field | Typical value |
|-------|----------------|
| Host | `mikrotik.lan` |
| Username / password | RouterOS API user |
| Port | `8729` (api-ssl) |
| Use SSL | on |
| WAN gateway | ISP gateway **name or IP** (e.g. `zen` for PPPoE) |
| Tunnel count | `3` (1–20 simultaneous Proton tunnels) |
| VPN exit country | `Any` (default) or one ISO code from Proton’s live server list |

Connectivity is checked with `/system/resource` over api-ssl. Ensure the HA
host is allowed to reach the API port (input accept above any “drop non-admin”
rules). Proton accounts often cap WireGuard configs (~10); provision will
surface Proton’s error if you exceed the account limit.

**Exit country** limits every provisioned slot to servers in that Proton
`ExitCountry`. Choose **Any** for the previous behaviour (best Score worldwide).
The dropdown is built from usable online servers for your account tier; if the
list cannot be fetched, the form still offers Any plus any previously saved
country.

### Provision WireGuard certificates

Developer tools → **Actions** → `proton_mikrotik_wg.provision_wireguard`

Keys match Proton’s account UI: raw Ed25519 public key for the certificate
API, X25519 for the MikroTik WireGuard peer.

- Omitting **slot** provisions **all** tunnels (1…`tunnel_count`) on **distinct**
  Proton servers (best Score, no Secure Core/TOR), optionally restricted to the
  configured exit country.
- Optional **slot** (1–20) reprovisions one tunnel only (same country filter).
- Provision fails if fewer than `tunnel_count` distinct servers match the filter.
- Device labels: `ha-wg-proton-{slot}-YYYYMMDD-HHMMSS` (UTC).
- Best-effort delete of older `ha-wg-proton*` certs, keeping current slot
  serials. Non-HA configs are left alone.

Credentials are stored as `wg_slots` on the config entry (legacy single-key
entries migrate to slot 1 on read).

### Apply tunnel-only to the router

Developer tools → **Actions** → `proton_mikrotik_wg.apply_wireguard`

For each stored slot ≤ `tunnel_count`:

- `/interface/wireguard` `wg-proton-{slot}` + peer
- `/ip/address` `10.2.0.2/32` with `network=10.2.0.1`
- `/ip/route` endpoint `/32` via WAN (comment `proton-wg-endpoint-{slot}`)

Also removes legacy bare `wg-proton` and numbered interfaces above
`tunnel_count`. Does **not** change default LAN egress, kill-switch, or DNS.
Do not push Proton DNS `10.2.0.1` to clients. The inbound remote-access
WireGuard interface (`wireguard`) is left alone.

### VPN egress switch (ECMP)

Entity: **Proton VPN egress** (`switch.proton_vpn_egress`).

| State | Effect on MikroTik |
|-------|--------------------|
| On | For each active slot: WAN-list member, masq (`proton-wg-masq-{slot}`), equal-cost default `0.0.0.0/0` via `10.2.0.1%wg-proton-{slot}` (`proton-wg-egress-{slot}`); WAN `default-route-distance=2` |
| Off | Removes those routes/NAT/WAN members; restores WAN `default-route-distance=1` |

There is **no kill-switch**: when the VPN is off or down, traffic uses the ISP.
Desired on/off state is stored in options and re-applied after HA restarts.

Typical order: configure MikroTik (tunnel count + optional exit country) →
provision → `apply_wireguard` → toggle egress on.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest   # enforces 100% coverage
```

See [AGENTS.md](AGENTS.md) for TDD and commit workflow.
