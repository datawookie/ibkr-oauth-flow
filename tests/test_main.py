from collections.abc import Iterator
import pytest
from pathlib import Path
from unittest.mock import patch, Mock

import yaml

from ibauth import IBKROAuthFlow, auth_from_yaml

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


@pytest.fixture  # type: ignore[misc]
def private_key_file(tmp_path: Path) -> Iterator[Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_file = tmp_path / "key.pem"
    key_file.write_bytes(pem)
    yield key_file


@pytest.fixture  # type: ignore[misc]
def flow(private_key_file: Path) -> IBKROAuthFlow:
    return IBKROAuthFlow(
        client_id="cid",
        client_key_id="kid",
        credential="cred",
        private_key_file=private_key_file,
        domain="api.ibkr.com",
    )


def test_init_valid(flow: IBKROAuthFlow) -> None:
    assert flow.client_id == "cid"
    assert flow.domain == "api.ibkr.com"
    assert flow.private_key is not None


def test_invalid_domain(private_key_file: Path) -> None:
    with pytest.raises(ValueError):
        IBKROAuthFlow("cid", "kid", "cred", private_key_file, domain="not.valid")


@patch("ibauth.auth.get")
def test_check_ip_sets_ip(mock_get: Mock, flow: IBKROAuthFlow) -> None:
    mock_get.return_value.content = b"1.2.3.4"
    ip = flow._check_ip()
    assert ip == "1.2.3.4"
    assert flow.IP == "1.2.3.4"


@patch("ibauth.auth.post")
def test_get_access_token(mock_post: Mock, flow: IBKROAuthFlow) -> None:
    mock_post.return_value.json.return_value = {"access_token": "abc123"}
    flow.get_access_token()
    assert flow.access_token == "abc123"


@patch("ibauth.auth.post")
@patch.object(IBKROAuthFlow, "_check_ip")
def test_get_bearer_token(mock_check_ip: Mock, mock_post: Mock, flow: IBKROAuthFlow) -> None:
    flow.access_token = "abc123"
    mock_check_ip.return_value = "1.2.3.4"
    mock_post.return_value.json.return_value = {"access_token": "bearer123"}

    flow.get_bearer_token()
    assert flow.bearer_token == "bearer123"


@patch("ibauth.auth.post")
def test_ssodh_init_success(mock_post: Mock, flow: IBKROAuthFlow) -> None:
    flow.bearer_token = "bearer123"
    mock_post.return_value.json.return_value = {"status": "ok"}
    flow.ssodh_init()  # should not raise


@patch("ibauth.auth.get")
def test_validate_sso(mock_get: Mock, flow: IBKROAuthFlow) -> None:
    flow.bearer_token = "bearer123"
    mock_get.return_value.json.return_value = {"result": "valid"}
    flow.validate_sso()
    mock_get.assert_called_once()


@patch("ibauth.auth.get")
def test_tickle_success(mock_get: Mock, flow: IBKROAuthFlow) -> None:
    flow.bearer_token = "bearer123"
    mock_get.return_value.json.return_value = {
        "session": "sess1",
        "iserver": {
            "authStatus": {
                "authenticated": True,
                "competing": False,
                "connected": True,
            }
        },
    }
    sid = flow.tickle()
    assert sid == "sess1"
    assert flow.authenticated
    assert flow.connected
    assert not flow.competing


@patch("ibauth.auth.post")
def test_logout_with_token(mock_post: Mock, flow: IBKROAuthFlow) -> None:
    flow.bearer_token = "bearer123"
    flow.logout()
    mock_post.assert_called_once()


def test_logout_without_token(flow: IBKROAuthFlow) -> None:
    flow.bearer_token = None
    # should not raise
    flow.logout()


def test_auth_from_yaml(tmp_path: Path, private_key_file: str) -> None:
    config = {
        "client_id": "cid",
        "client_key_id": "kid",
        "credential": "cred",
        "private_key_file": str(private_key_file),
        "domain": "api.ibkr.com",
    }
    file = tmp_path / "conf.yaml"
    file.write_text(yaml.dump(config))
    flow = auth_from_yaml(file)
    assert isinstance(flow, IBKROAuthFlow)
    assert flow.client_id == "cid"
