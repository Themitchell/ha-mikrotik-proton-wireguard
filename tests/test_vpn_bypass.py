"""Tests for VPN bypass CIDR multiline parsing."""

from __future__ import annotations

import pytest

from proton_mikrotik_wg.vpn_bypass import parse_vpn_bypass_cidrs


def test_parse_vpn_bypass_cidrs_normalizes_hosts_and_networks():
    text = """
    # TV
    10.0.5.50
    10.0.30.0/24

    """
    assert parse_vpn_bypass_cidrs(text) == ["10.0.5.50/32", "10.0.30.0/24"]


def test_parse_vpn_bypass_cidrs_rejects_invalid_line():
    with pytest.raises(ValueError, match="invalid VPN bypass CIDR"):
        parse_vpn_bypass_cidrs("not-an-ip")


def test_parse_vpn_bypass_cidrs_rejects_ipv6():
    with pytest.raises(ValueError, match="invalid VPN bypass CIDR"):
        parse_vpn_bypass_cidrs("2001:db8::1")


def test_parse_vpn_bypass_cidrs_empty_returns_empty():
    assert parse_vpn_bypass_cidrs("") == []
    assert parse_vpn_bypass_cidrs("# only comments\n\n") == []
