import json
import math
import logging
from typing import Any
import time
import yaml

from cryptography.hazmat.primitives import serialization
from tenacity import retry, stop_after_attempt, wait_exponential

from .const import GRANT_TYPE, CLIENT_ASSERTION_TYPE, SCOPE, VALID_DOMAINS
from .util import make_jws, get, post, ReadTimeout, HTTPError


class IBKROAuthFlow:
    def __init__(
        self, client_id: str, client_key_id: str, credential: str, private_key_file: str, domain: str = "api.ibkr.com"
    ):
        if not client_id:
            raise ValueError("Required parameter 'client_id' is missing.")

        if not client_key_id:
            raise ValueError("Required parameter 'client_key_id' is missing.")

        if not credential:
            raise ValueError("Required parameter 'credential' is missing.")

        if not private_key_file:
            raise ValueError("Required parameter 'private_key_file' is missing.")

        if domain not in VALID_DOMAINS:
            raise ValueError(f"Invalid domain: {domain}.")
        else:
            self.domain = domain

        self.client_id = client_id
        self.client_key_id = client_key_id
        self.credential = credential

        logging.info(f"Load private key from {private_key_file}.")
        with open(private_key_file, "r") as file:
            self.private_key = serialization.load_pem_private_key(
                file.read().encode(),
                password=None,
            )

        self.access_token = None
        self.bearer_token = None

        # These fields are set in the tickle() method.
        #
        self.authenticated = None
        self.connected = None
        self.competing = None

        self.IP = None

    @property
    def url_oauth2(self) -> str:
        return f"https://{self.domain}/oauth2"

    @property
    def url_gateway(self) -> str:
        return f"https://{self.domain}/gw"

    @property
    def url_client_portal(self) -> str:
        return f"https://{self.domain}"

    @property
    def domain(self) -> str:
        return self._domain

    @domain.setter
    def domain(self, value: str) -> None:
        """
        Set and validate the domain.
        """
        if value not in VALID_DOMAINS:
            raise ValueError(f"Invalid domain: {value}. Must be one of {VALID_DOMAINS}.")
        logging.info(f"Domain: {value}")
        self._domain = value

    def _check_ip(self) -> Any:
        """
        Get public IP address.
        """
        logging.debug("Check public IP.")
        IP = get("https://api.ipify.org", timeout=10).content.decode("utf8")

        logging.info(f"Public IP: {IP}.")
        if self.IP and self.IP != IP:
            logging.warning("🚨 Public IP has changed.")

        self.IP = IP
        return IP

    def _compute_client_assertion(self, url: str) -> Any:
        now = math.floor(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": f"{self.client_key_id}"}

        if url == f"{self.url_oauth2}/api/v1/token":
            claims = {
                "iss": f"{self.client_id}",
                "sub": f"{self.client_id}",
                "aud": "/token",
                "exp": now + 20,
                "iat": now - 10,
            }

        elif url == f"{self.url_gateway}/api/v1/sso-sessions":
            claims = {
                "ip": self.IP,
                "credential": f"{self.credential}",
                "iss": f"{self.client_id}",
                "exp": now + 86400,
                "iat": now,
            }

        logging.debug(f"Header: {header}.")
        logging.debug(f"Claims: {claims}.")

        return make_jws(header, claims, self.private_key)

    def get_access_token(self) -> None:
        """
        Obtain an access token. This is the first step in the authentication
        flow.

        Returns:
            str: The access token.
        """
        url = f"{self.url_oauth2}/api/v1/token"

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        form_data = {
            "grant_type": GRANT_TYPE,
            "client_assertion": self._compute_client_assertion(url),
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "scope": SCOPE,
        }

        logging.info("Request access token.")
        response = post(url=url, headers=headers, data=form_data)

        self.access_token = response.json()["access_token"]

    def get_bearer_token(self) -> None:
        url = f"{self.url_gateway}/api/v1/sso-sessions"

        headers = {
            "Authorization": "Bearer " + self.access_token,  # type: ignore
            "Content-Type": "application/jwt",
        }

        # Initialise IP (it's embedded in the bearer token).
        self._check_ip()

        logging.info("Request bearer token.")
        response = post(url=url, headers=headers, data=self._compute_client_assertion(url))

        self.bearer_token = response.json()["access_token"]

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=5))  # type: ignore
    def ssodh_init(self) -> None:
        """
        Initialise a brokerage session.
        """
        url = f"{self.url_client_portal}/v1/api/iserver/auth/ssodh/init"

        headers = {
            "Authorization": "Bearer " + self.bearer_token,  # type: ignore
            "User-Agent": "python/3.11",
        }

        logging.info("Initiate a brokerage session.")
        try:
            response = post(url=url, headers=headers, json={"publish": True, "compete": True})
        except HTTPError:
            logging.error("⛔ Error initiating a brokerage session.")
            raise

        logging.debug(json.dumps(response.json(), indent=2))

    def validate_sso(self) -> None:
        url = f"{self.url_client_portal}/v1/api/sso/validate"

        headers = {
            "Authorization": "Bearer " + self.bearer_token,  # type: ignore
            "User-Agent": "python/3.11",
        }

        logging.info("Validate brokerage session.")
        response = get(url=url, headers=headers)

        logging.debug(json.dumps(response.json(), indent=2))

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=5))  # type: ignore
    def tickle(self) -> str:
        """
        Keeps session alive.

        Returns:
            Session ID.
        """
        url = f"{self.url_client_portal}/v1/api/tickle"

        headers = {
            "Authorization": "Bearer " + self.bearer_token,  # type: ignore
            "User-Agent": "python/3.11",
        }

        logging.info("Send tickle.")
        try:
            response = get(url=url, headers=headers, timeout=10)
        except (HTTPError, ReadTimeout):
            logging.error("⛔ Error connecting to session.")
            self.get_bearer_token()
            self.ssodh_init()
            raise

        self.session_id: str = response.json()["session"]
        auth_status = response.json()["iserver"]["authStatus"]
        self.authenticated = auth_status["authenticated"]
        self.competing = auth_status["competing"]
        self.connected = auth_status["connected"]

        logging.info(f"Session ID: {self.session_id}")
        logging.info(f"- authenticated: {self.authenticated}")
        logging.info(f"- competing:     {self.competing}")
        logging.info(f"- connected:     {self.connected}")

        logging.debug(json.dumps(response.json(), indent=2))

        return self.session_id

    def logout(self) -> None:
        url = f"{self.url_client_portal}/v1/api/logout"

        headers = {
            "Authorization": "Bearer " + self.bearer_token,  # type: ignore
            "User-Agent": "python/3.11",
        }

        logging.info("Terminate brokerage session.")
        post(url=url, headers=headers)


def auth_from_yaml(path: str) -> IBKROAuthFlow:
    """
    Create an IBKROAuthFlow instance from a YAML configuration file.

    Args:
        path (str): The path to the YAML configuration file.

    Returns:
        IBKROAuthFlow: An instance of IBKROAuthFlow.
    """
    with open(path, "r") as file:
        config = yaml.safe_load(file)

    return IBKROAuthFlow(
        client_id=config["client_id"],
        client_key_id=config["client_key_id"],
        credential=config["credential"],
        private_key_file=config["private_key_file"],
        domain=config.get("domain", "api.ibkr.com"),
    )
