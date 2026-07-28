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

1. Copy `custom_components/proton_mikrotik_wg` to HA `/config/custom_components/`.
2. Restart Home Assistant.
3. **Settings → Devices & services → Add integration → Proton MikroTik WireGuard**.
4. Enter Proton account username and password (login is verified).
5. If 2FA is enabled, enter the TOTP code.

The integration then:

- Stores session tokens on the config entry (not your password)
- Refreshes tokens on startup
- Refreshes again every 12 hours
- Marks the entry as needing reauth if refresh fails

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest   # enforces 100% coverage
```

See [AGENTS.md](AGENTS.md) for TDD and commit workflow.
