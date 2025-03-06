from .access_token import getAccessToken as getAccessToken
from .bearer_token import getBearerToken as getBearerToken
from .sso import ssodh_init as ssodh_init, validate_sso as validate_sso
from .tickle import tickle as tickle
from .logout import logoutSession as logoutSession

from .const import oauth2Url, GRANT_TYPE, CLIENT_ASSERTION_TYPE, SCOPE
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

        return token_request.json()["access_token"]
