import requests

from .const import gatewayUrl
from .util import compute_client_assertion, formatted_HTTPrequest


def getBearerToken(access_token: str, credential, clientId, clientKeyId, clientPrivateKey):
    url = f"{gatewayUrl}/api/v1/sso-sessions"

    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/jwt",
    }

    signed_request = compute_client_assertion(credential, url, clientId, clientKeyId, clientPrivateKey)
    bearer_request = requests.post(url=url, headers=headers, data=signed_request)
    print(formatted_HTTPrequest(bearer_request))

    if bearer_request.status_code == 200:
        return bearer_request.json()["access_token"]
    return
