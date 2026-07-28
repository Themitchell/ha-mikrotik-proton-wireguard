# Proton MikroTik WireGuard

Home Assistant **custom integration** scaffold: Proton VPN WireGuard on a single
MikroTik interface for whole-home egress.

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

The config entry stores Proton session tokens (not your password). MikroTik
router settings and tunnel provisioning come in later steps.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest   # enforces 100% coverage on library modules
```

See [AGENTS.md](AGENTS.md) for TDD and commit workflow.
