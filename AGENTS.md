# Proton MikroTik WireGuard agent guidance

## Project context

- This repo is a Home Assistant **custom integration** that creates/rotates a
  single Proton VPN WireGuard credential and applies it to **one** MikroTik
  WireGuard interface for whole-home egress.
- Install path at runtime: `/config/custom_components/proton_mikrotik_wg/`
  (HA config PVC). Not an add-on; HA runs on Kubernetes.
- Pure library modules under `custom_components/proton_mikrotik_wg/` are unit
  tested without Home Assistant installed. Do not import `homeassistant` from
  modules that unit tests import (keep HA wiring in dedicated integration
  modules when those land).
- Proton account API is unofficial; prefer session tokens + injectable HTTP
  transport. Do not call live Proton or MikroTik from unit tests.
- Single WireGuard interface only for now (e.g. `wg-proton`). Do not add a
  multi-peer pool or multi-interface rotation unless the user asks.
- DNS hard rule: LAN clients use Pi-hole only; never push Proton DNS
  (`10.2.0.1`) to clients; do not leak internal DNS names.
- Kill-switch (VPN on) and intentional ISP bypass are separate behaviours.

## Development process

- Follow strict TDD, one test per cycle:
  1. Add one test for one behaviour.
  2. Run it and confirm it fails for the expected reason.
  3. Write only enough production code to pass.
  4. Refactor while keeping all tests green.
- Work through **one test / one thin feature at a time** and ask for user
  confirmation before starting the next step.
- After each completed thin feature (tests green + docs touched if needed),
  **commit** (on a feature branch) before continuing.
- Prefer small commits over large batches. Do not implement the next feature
  in the same commit as the previous one unless the user asks.
- Use injected fakes/mocks for HTTP and RouterOS; tests must not require a
  live Proton account, MikroTik, or running Home Assistant.
- Aim for 100% code coverage on library modules (`proton_auth`, `schemas`,
  `const`, etc.). `pytest` is configured with `--cov-fail-under=100`.
  Home Assistant entry modules (`config_flow.py`, `__init__.py`) are omitted
  from the gate until a HA test harness is added — do not put business logic
  only in those files.
- Cover new code and close gaps shown by
  `pytest --cov-report=term-missing`.
- Prefer clear application errors while preserving underlying exceptions as
  causes.
- Add concise docstrings to modules and public classes, functions, and
  methods.
- Do not add speculative abstractions or unrelated features (no HA dashboard
  polish, no Secure Core profiles, no multi-iface pools until requested).

## Documentation

- Keep docs in sync with behaviour changes in the same change set when
  practical.
- Update [README.md](README.md) when install, HA drop-in path, MikroTik
  prep, or DNS/kill-switch behaviour changes.
- Do not leave docs describing removed or outdated behaviour.
- Do not commit real Proton/MikroTik secrets.

## Git and pull requests

- Always create a new feature branch from an up-to-date `main` before making
  changes. Do not commit on `main` or on an unrelated existing branch.
- Open changes as a pull request when a remote exists and the user wants one.
- Keep PRs narrowly scoped to the thin feature just completed.

## Commit messages

- Summarize the change in a subject of about 50 characters or fewer.
- Separate the subject from an optional body with a blank line.
- Wrap body text at about 72 characters.
- Explain the problem and why the change is needed rather than how the code
  works.
- Document important side effects or unintuitive consequences.
- Put issue references at the end, for example `Resolves: #123`.

## Commands

- `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"` — local setup.
- `.venv/bin/pytest` — run unit tests with 100% coverage gate.
- `.venv/bin/pytest -q` — quiet test run after each TDD step.
