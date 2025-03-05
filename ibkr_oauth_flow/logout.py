import requests

from .const import clientPortalUrl
from .util import formatted_HTTPrequest


def logoutSession(bearer_token):
    headers = {"Authorization": "Bearer " + bearer_token}
    headers["User-Agent"] = "python/3.11"

    url = f"{clientPortalUrl}/v1/api/logout"
    logout_request = requests.post(url=url, headers=headers)
    print(formatted_HTTPrequest(logout_request))
