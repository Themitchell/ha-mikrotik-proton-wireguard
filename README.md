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
4. Enter Proton account username and password.

MikroTik router settings and tunnel provisioning come in later steps.

See [AGENTS.md](AGENTS.md) for TDD and commit workflow.
