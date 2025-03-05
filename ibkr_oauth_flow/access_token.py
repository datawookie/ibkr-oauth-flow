import requests

from .const import oauth2Url, GRANT_TYPE, CLIENT_ASSERTION_TYPE, SCOPE
from .util import formatted_HTTPrequest, compute_client_assertion

# https://www.interactivebrokers.com/campus/ibkr-api-page/webapi-ref/#tag/Authorization-Token/operation/generateToken


def getAccessToken(credential, clientId, clientKeyId, clientPrivateKey):
    url = f"{oauth2Url}/api/v1/token"

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    client_assertion = compute_client_assertion(credential, url, clientId, clientKeyId, clientPrivateKey)

    form_data = {
        "grant_type": GRANT_TYPE,
        "client_assertion": client_assertion,
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "scope": SCOPE,
    }

    token_request = requests.post(url=url, headers=headers, data=form_data)
    print(formatted_HTTPrequest(token_request))

    return token_request.json()["access_token"]
