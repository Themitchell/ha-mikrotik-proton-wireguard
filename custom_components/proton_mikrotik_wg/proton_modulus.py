"""Extract Proton SRP modulus from a PGP clearsigned message without gpg."""

from __future__ import annotations

import base64

_BEGIN_MSG = "-----BEGIN PGP SIGNED MESSAGE-----"
_BEGIN_SIG = "-----BEGIN PGP SIGNATURE-----"


def extract_srp_modulus(armored: str) -> bytes:
    """Return the base64-decoded modulus body from a clearsigned PGP message.

    Home Assistant images typically lack a system ``gpg`` binary, so we parse
    the clearsigned payload instead of verifying via GnuPG. The signature is
    not checked here; SRP still requires a correct password.
    """
    if _BEGIN_MSG not in armored or _BEGIN_SIG not in armored:
        raise ValueError("not a clearsigned PGP modulus message")

    # Drop armor header + optional Hash: line(s), keep payload until signature.
    after_header = armored.split(_BEGIN_MSG, 1)[1]
    body_and_rest = after_header.split(_BEGIN_SIG, 1)[0]
    lines = body_and_rest.replace("\r\n", "\n").split("\n")
    # Skip leading blank / Hash header lines.
    while lines and (not lines[0].strip() or lines[0].startswith("Hash:")):
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    payload = "".join(line.strip() for line in lines if line.strip())
    if not payload:
        raise ValueError("empty clearsigned PGP modulus payload")
    try:
        return base64.b64decode(payload, validate=True)
    except Exception as err:  # noqa: BLE001
        # Some pythons use binascii.Error; keep message stable.
        raise ValueError("invalid base64 in clearsigned PGP modulus") from err
