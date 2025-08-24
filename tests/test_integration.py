import pytest
from ibauth import auth_from_yaml


@pytest.mark.integration  # type: ignore[misc]
def test_full_auth_flow_real() -> None:
    auth = auth_from_yaml("config.yaml")
    auth.get_access_token()
    auth.get_bearer_token()
    auth.ssodh_init()
    auth.validate_sso()
    for _ in range(3):
        auth.tickle()
    auth.domain = "5.api.ibkr.com"
    auth.tickle()
    auth.logout()
