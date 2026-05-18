"""Tests pentru construire CLI args nmap + validare target."""
import pytest
from agent.nmap_runner import (
    build_nmap_args, validate_cidr, validate_lan_target, NmapRunnerError,
)


def test_build_args_localhost_only():
    args = build_nmap_args(targets=["127.0.0.1"], top_ports=1000,
                           xml_out="result.xml")
    assert "-sV" in args
    assert "-O" in args
    assert "--top-ports" in args
    assert "1000" in args
    assert "--script" in args
    assert "vulnwatch-audit" in args
    assert "-oX" in args
    assert "result.xml" in args
    assert "127.0.0.1" in args


def test_build_args_with_lan():
    args = build_nmap_args(targets=["127.0.0.1", "192.168.1.0/24"],
                           top_ports=1000, xml_out="result.xml")
    assert "127.0.0.1" in args
    assert "192.168.1.0/24" in args


def test_build_args_all_ports():
    args = build_nmap_args(targets=["127.0.0.1"], top_ports=None,
                           all_ports=True, xml_out="result.xml")
    assert "-p-" in args
    assert "--top-ports" not in args


def test_validate_cidr_ok():
    validate_cidr("192.168.1.0/24")  # nu ridica
    validate_cidr("10.0.0.0/24")    # /24, nu /8
    validate_cidr("127.0.0.1")      # single host = /32


def test_validate_lan_target_rejects_public():
    with pytest.raises(NmapRunnerError, match="public"):
        validate_lan_target("8.8.8.0/24")


def test_validate_lan_target_rejects_huge():
    with pytest.raises(NmapRunnerError, match="prea mare"):
        validate_lan_target("10.0.0.0/8")


def test_validate_cidr_rejects_invalid_syntax():
    with pytest.raises(NmapRunnerError, match="invalid"):
        validate_cidr("not.a.cidr")
