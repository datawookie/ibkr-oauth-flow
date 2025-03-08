import json
import math
import logging
import time

from cryptography.hazmat.primitives import serialization
import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from .const import oauth2Url, gatewayUrl, clientPortalUrl, GRANT_TYPE, CLIENT_ASSERTION_TYPE, SCOPE, audience
from .util import log_response, IP, make_jws


class IBKROAuthFlow:
    def __init__(self, client_id: str, client_key_id: str, credential: str, private_key_file: str):
        if not client_id:
            raise ValueError("Required parameter 'client_id' is missing.")

        if not client_key_id:
            raise ValueError("Required parameter 'client_key_id' is missing.")

        if not credential:
            raise ValueError("Required parameter 'credential' is missing.")

        if not private_key_file:
            raise ValueError("Required parameter 'private_key_file' is missing.")

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

    def _compute_client_assertion(self, url) -> str:
        now = math.floor(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": f"{self.client_key_id}"}

        if url == f"{oauth2Url}/api/v1/token":
            claims = {
                "iss": f"{self.client_id}",
                "sub": f"{self.client_id}",
                "aud": f"{audience}",
                "exp": now + 20,
                "iat": now - 10,
            }

        elif url == f"{gatewayUrl}/api/v1/sso-sessions":
            claims = {
                "ip": IP,
                #'service': "AM.LOGIN",
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
        url = f"{oauth2Url}/api/v1/token"

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        form_data = {
            "grant_type": GRANT_TYPE,
            "client_assertion": self._compute_client_assertion(url),
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "scope": SCOPE,
        }

        logging.info("Request access token.")
        response = requests.post(url=url, headers=headers, data=form_data)
        log_response(response)

        self.access_token = response.json()["access_token"]

    def get_bearer_token(self) -> None:
        url = f"{gatewayUrl}/api/v1/sso-sessions"

        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/jwt",
        }

        logging.info("Request bearer token.")
        response = requests.post(url=url, headers=headers, data=self._compute_client_assertion(url))
        log_response(response)

        self.bearer_token = response.json()["access_token"]

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=5))
    def ssodh_init(self) -> None:
        """
        Initialise a brokerage session.
        """
        url = f"{clientPortalUrl}/v1/api/iserver/auth/ssodh/init"

        headers = {
            "Authorization": "Bearer " + self.bearer_token,
            "User-Agent": "python/3.11",
        }

        logging.info("Initiate a brokerage session.")
        try:
            response = requests.post(url=url, headers=headers, json={"publish": True, "compete": True})
            log_response(response)
        except requests.exceptions.HTTPError:
            logging.error("⛔ Error initiating a brokerage session.")
            raise

        logging.debug(json.dumps(response.json(), indent=2))

    def validate_sso(self) -> None:
        url = f"{clientPortalUrl}/v1/api/sso/validate"

        headers = {
            "Authorization": "Bearer " + self.bearer_token,
            "User-Agent": "python/3.11",
        }

        logging.info("Validate brokerage session.")
        response = requests.get(url=url, headers=headers)
        log_response(response)

        logging.debug(json.dumps(response.json(), indent=2))

    def tickle(self) -> str:
        """
        Keeps session alive.

        Returns:
            Session ID.
        """
        url = f"{clientPortalUrl}/v1/api/tickle"

        headers = {
            "Authorization": "Bearer " + self.bearer_token,
            "User-Agent": "python/3.11",
        }

        logging.info("Send tickle.")
        response = requests.get(url=url, headers=headers)
        log_response(response)

        self.session_id = response.json()["session"]

        logging.info(f"Session ID: {self.session_id}")
        logging.debug(json.dumps(response.json(), indent=2))

        return self.session_id

    def logout(self) -> None:
        url = f"{clientPortalUrl}/v1/api/logout"

        headers = {
            "Authorization": "Bearer " + self.bearer_token,
            "User-Agent": "python/3.11",
        }

        logging.info("Terminate brokerage session.")
        response = requests.post(url=url, headers=headers)
        log_response(response)
