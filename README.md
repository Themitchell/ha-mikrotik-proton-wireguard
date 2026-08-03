# Proton MikroTik WireGuard

Home Assistant **custom integration** focused on Proton VPN session management
(login, 2FA, token refresh). MikroTik WireGuard provisioning comes later.

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
4. Enter Proton account username and password (login is verified).
5. If 2FA is enabled, enter the TOTP code.

HACS needs a GitHub **Release** with a semver tag (e.g. `0.1.0`);
installing from a bare commit SHA will fail.

### Manual

1. Copy `custom_components/proton_mikrotik_wg` to HA `/config/custom_components/`.
2. Restart Home Assistant, then Add integration as above.

The integration then:

- Stores session tokens on the config entry (not your password)
- Refreshes tokens on startup
- Refreshes again every 12 hours
- Marks the entry as needing reauth if refresh fails
- Prompts for password (and 2FA if needed) to renew the session

Login uses a gpg-free HTTP/SRP client so it works on typical Home Assistant
containers (no system ``gpg`` required). Use your Proton **account** email
(e.g. ``you@proton.me``), not OpenVPN credentials.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest   # enforces 100% coverage
```

See [AGENTS.md](AGENTS.md) for TDD and commit workflow.
