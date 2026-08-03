"""Tests for PGP clearsigned SRP modulus extraction (no system gpg)."""

from __future__ import annotations

import base64

import pytest

from proton_mikrotik_wg.proton_modulus import extract_srp_modulus


SAMPLE_CLEARSIGNED = (
    "-----BEGIN PGP SIGNED MESSAGE-----\n"
    "Hash: SHA256\n"
    "\n"
    "SGVsbG9Nb2R1bHVzUGFkZGluZ0hlcmUhSGVsbG9Nb2R1bHVzUGFkZGluZ0hlcmUh\n"
    "-----BEGIN PGP SIGNATURE-----\n"
    "Version: ProtonMail\n"
    "\n"
    "wnUEARYIABAFAlwB1j4JEDUFhcTpUY8mAAAB\n"
    "=TdF9\n"
    "-----END PGP SIGNATURE-----\n"
)


def test_extract_srp_modulus_decodes_clearsigned_body():
    body = "SGVsbG9Nb2R1bHVzUGFkZGluZ0hlcmUhSGVsbG9Nb2R1bHVzUGFkZGluZ0hlcmUh"
    expected = base64.b64decode(body)
    assert extract_srp_modulus(SAMPLE_CLEARSIGNED) == expected


def test_extract_srp_modulus_rejects_missing_markers():
    with pytest.raises(ValueError, match="clearsigned"):
        extract_srp_modulus("not a pgp message")


def test_extract_srp_modulus_rejects_empty_payload():
    empty = (
        "-----BEGIN PGP SIGNED MESSAGE-----\n"
        "Hash: SHA256\n"
        "\n"
        "\n"
        "-----BEGIN PGP SIGNATURE-----\n"
        "-----END PGP SIGNATURE-----\n"
    )
    with pytest.raises(ValueError, match="empty"):
        extract_srp_modulus(empty)


def test_extract_srp_modulus_rejects_invalid_base64():
    bad = (
        "-----BEGIN PGP SIGNED MESSAGE-----\n"
        "Hash: SHA256\n"
        "\n"
        "!!!!not-base64!!!!\n"
        "-----BEGIN PGP SIGNATURE-----\n"
        "-----END PGP SIGNATURE-----\n"
    )
    with pytest.raises(ValueError, match="invalid base64"):
        extract_srp_modulus(bad)
