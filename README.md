# Proton MikroTik WireGuard

Home Assistant **custom integration** that logs into Proton VPN, provisions one
WireGuard certificate, applies it to a MikroTik `wg-proton` interface, and
exposes a switch to send whole-home traffic out through Proton VPN.

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

HACS needs a GitHub **Release** with a semver tag (e.g. `0.2.0`);
installing from a bare commit SHA will fail.

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

### Provision a WireGuard certificate

Developer tools → **Actions** → `proton_mikrotik_wg.provision_wireguard`

Default device label: `ha-wg-proton` (custom names must start with `ha-`).
The credential is stored on the config entry. Persistent configs also appear
under Proton account → Downloads → WireGuard configuration (~1 year validity).

### Configure MikroTik (options)

Settings → Devices & services → Proton MikroTik WireGuard → **Configure**:

| Field | Typical value |
|-------|----------------|
| Host | `mikrotik.lan` |
| Username / password | RouterOS API user |
| Port | `8729` (api-ssl) |
| Use SSL | on |
| WAN gateway | ISP gateway **name or IP** (e.g. `zen` for PPPoE) |

Connectivity is checked with `/system/resource` over api-ssl. Ensure the HA
host is allowed to reach the API port (input accept above any “drop non-admin”
rules).

### Apply tunnel-only to the router

Developer tools → **Actions** → `proton_mikrotik_wg.apply_wireguard`

This creates or updates:

- `/interface/wireguard` `wg-proton` + peer
- `/ip/address` `10.2.0.2/32` on `wg-proton`
- `/ip/route` endpoint `/32` via WAN gateway (comment `proton-wg-endpoint`)

It does **not** change default LAN egress, NAT, kill-switch, or DNS. Do not
push Proton DNS `10.2.0.1` to clients. The inbound remote-access WireGuard
interface (`wireguard`) is left alone.

### VPN egress switch

Entity: **Proton VPN egress** (`switch.proton_vpn_egress`).

| State | Effect on MikroTik |
|-------|--------------------|
| On | Default `0.0.0.0/0` via `wg-proton` (comment `proton-wg-egress`), masquerade out `wg-proton` (`proton-wg-masq`), WAN `default-route-distance=2` |
| Off | Removes those routes/NAT; restores WAN `default-route-distance=1` (normal ISP) |

There is **no kill-switch**: when the VPN is off or down, traffic uses the ISP.
Desired on/off state is stored in options and re-applied after HA restarts.

Typical order: provision → configure MikroTik → `apply_wireguard` → toggle the
egress switch on.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest   # enforces 100% coverage
```

See [AGENTS.md](AGENTS.md) for TDD and commit workflow.
