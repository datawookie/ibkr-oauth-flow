from .const import oauth2Url, gatewayUrl, clientPortalUrl, GRANT_TYPE, CLIENT_ASSERTION_TYPE, SCOPE, audience
from .util import formatted_HTTPrequest, IP, make_jws

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

        logging.info("Load private key.")
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

        token_request = requests.post(url=url, headers=headers, data=form_data)
        print(formatted_HTTPrequest(token_request))

        self.access_token = token_request.json()["access_token"]

    def get_bearer_token(self) -> None:
        url = f"{gatewayUrl}/api/v1/sso-sessions"

        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/jwt",
        }

        signed_request = self._compute_client_assertion(url)
        bearer_request = requests.post(url=url, headers=headers, data=signed_request)
        print(formatted_HTTPrequest(bearer_request))

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
        init_request = requests.post(url=url, headers=headers, json=json_data)
        print(formatted_HTTPrequest(init_request))

    def validate_sso(self) -> None:
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/sso/validate"  # Validates the current session for the user
        vsso_request = requests.get(
            url=url, headers=headers
        )  # Prepare and send request to /sso/validate endpoint, print request and response.
        print(formatted_HTTPrequest(vsso_request))

    def tickle(self) -> None:
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/tickle"  # Tickle endpoint, used to ping the server and/or being the process of opening a websocket connection
        tickle_request = requests.get(
            url=url, headers=headers
        )  # Prepare and send request to /tickle endpoint, print request and response.
        print(formatted_HTTPrequest(tickle_request))
        return tickle_request.json()["session"]

    def logout(self) -> None:
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/logout"
        logout_request = requests.post(url=url, headers=headers)
        print(formatted_HTTPrequest(logout_request))
