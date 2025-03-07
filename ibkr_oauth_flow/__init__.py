from .const import oauth2Url, gatewayUrl, clientPortalUrl, GRANT_TYPE, CLIENT_ASSERTION_TYPE, SCOPE, audience
from .util import log_response, IP, make_jws

import math
import logging
import time

from cryptography.hazmat.primitives import serialization
import requests


class IBKROAuthFlow:
    def __init__(self, client_id: str, client_key_id: str, credential: str, private_key_file: str):
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

        client_assertion = self._compute_client_assertion(url)

        form_data = {
            "grant_type": GRANT_TYPE,
            "client_assertion": client_assertion,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "scope": SCOPE,
        }

        logging.info("Request access token.")
        token_request = requests.post(url=url, headers=headers, data=form_data)
        log_response(token_request)

        self.access_token = token_request.json()["access_token"]

    def get_bearer_token(self) -> None:
        url = f"{gatewayUrl}/api/v1/sso-sessions"

        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/jwt",
        }

        signed_request = self._compute_client_assertion(url)
        logging.info("Request bearer token.")
        bearer_request = requests.post(url=url, headers=headers, data=signed_request)
        log_response(bearer_request)

        if bearer_request.status_code == 200:
            self.bearer_token = bearer_request.json()["access_token"]
        return

    def ssodh_init(self) -> None:
        """
        Initialise a brokerage session.
        """
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/iserver/auth/ssodh/init"
        json_data = {"publish": True, "compete": True}
        logging.info("Initiate a brokerage session.")
        init_request = requests.post(url=url, headers=headers, json=json_data)
        log_response(init_request)

    def validate_sso(self) -> None:
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/sso/validate"  # Validates the current session for the user
        logging.info("Validate brokerage session.")
        vsso_request = requests.get(
            url=url, headers=headers
        )  # Prepare and send request to /sso/validate endpoint, print request and response.
        log_response(vsso_request)

    def tickle(self) -> None:
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/tickle"  # Tickle endpoint, used to ping the server and/or being the process of opening a websocket connection
        logging.info("Send tickle.")
        tickle_request = requests.get(
            url=url, headers=headers
        )  # Prepare and send request to /tickle endpoint, print request and response.
        log_response(tickle_request)
        return tickle_request.json()["session"]

    def logout(self) -> None:
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/logout"
        logging.info("Terminate brokerage session.")
        logout_request = requests.post(url=url, headers=headers)
        log_response(logout_request)
