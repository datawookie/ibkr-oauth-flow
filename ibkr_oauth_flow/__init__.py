from .const import oauth2Url, gatewayUrl, clientPortalUrl, GRANT_TYPE, CLIENT_ASSERTION_TYPE, SCOPE
from .util import formatted_HTTPrequest, compute_client_assertion

import logging

from cryptography.hazmat.primitives import serialization
import requests


class IBKROAuthFlow:
    def __init__(self, client_id, client_key_id, credential, private_key_file):
        self.client_id = client_id
        self.client_key_id = client_key_id
        self.credential = credential

        logging.info("Load private key.")

        with open(private_key_file, "r") as file:
            private_key = file.read().encode()

        self.private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
        )

        self.access_token = None
        self.bearer_token = None

    def get_access_token(self) -> str:
        """
        Obtain an access token. This is the first step in the authentication
        flow.

        Returns:
            str: The access token.
        """
        url = f"{oauth2Url}/api/v1/token"

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        client_assertion = compute_client_assertion(
            self.credential, url, self.client_id, self.client_key_id, self.private_key
        )

        form_data = {
            "grant_type": GRANT_TYPE,
            "client_assertion": client_assertion,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "scope": SCOPE,
        }

        token_request = requests.post(url=url, headers=headers, data=form_data)
        print(formatted_HTTPrequest(token_request))

        self.access_token = token_request.json()["access_token"]

    def get_bearer_token(self):
        url = f"{gatewayUrl}/api/v1/sso-sessions"

        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/jwt",
        }

        signed_request = compute_client_assertion(
            self.credential, url, self.client_id, self.client_key_id, self.private_key
        )
        bearer_request = requests.post(url=url, headers=headers, data=signed_request)
        print(formatted_HTTPrequest(bearer_request))

        if bearer_request.status_code == 200:
            self.bearer_token = bearer_request.json()["access_token"]
        return

    def ssodh_init(self):
        """
        Initialise a brokerage session.
        """
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/iserver/auth/ssodh/init"
        json_data = {"publish": True, "compete": True}
        init_request = requests.post(url=url, headers=headers, json=json_data)
        print(formatted_HTTPrequest(init_request))

    def validate_sso(self):
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/sso/validate"  # Validates the current session for the user
        vsso_request = requests.get(
            url=url, headers=headers
        )  # Prepare and send request to /sso/validate endpoint, print request and response.
        print(formatted_HTTPrequest(vsso_request))

    def tickle(self):
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/tickle"  # Tickle endpoint, used to ping the server and/or being the process of opening a websocket connection
        tickle_request = requests.get(
            url=url, headers=headers
        )  # Prepare and send request to /tickle endpoint, print request and response.
        print(formatted_HTTPrequest(tickle_request))
        return tickle_request.json()["session"]

    def logout(self):
        headers = {"Authorization": "Bearer " + self.bearer_token}
        headers["User-Agent"] = "python/3.11"

        url = f"{clientPortalUrl}/v1/api/logout"
        logout_request = requests.post(url=url, headers=headers)
        print(formatted_HTTPrequest(logout_request))
