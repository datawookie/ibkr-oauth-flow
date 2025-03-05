import requests

from .const import clientPortalUrl
from .util import formatted_HTTPrequest

# https://www.interactivebrokers.com/campus/ibkr-api-page/webapi-ref/#tag/Trading-Session/paths/~1iserver~1auth~1ssodh~1init/post


def ssodh_init(bearer_token):
    """
    Initialise a brokerage session.
    """
    headers = {"Authorization": "Bearer " + bearer_token}
    headers["User-Agent"] = "python/3.11"

    url = f"{clientPortalUrl}/v1/api/iserver/auth/ssodh/init"
    json_data = {"publish": True, "compete": True}
    init_request = requests.post(url=url, headers=headers, json=json_data)
    print(formatted_HTTPrequest(init_request))


def validate_sso(bearer_token):
    headers = {"Authorization": "Bearer " + bearer_token}
    headers["User-Agent"] = "python/3.11"

    url = f"{clientPortalUrl}/v1/api/sso/validate"  # Validates the current session for the user
    vsso_request = requests.get(
        url=url, headers=headers
    )  # Prepare and send request to /sso/validate endpoint, print request and response.
    print(formatted_HTTPrequest(vsso_request))
