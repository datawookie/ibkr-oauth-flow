import requests

from .const import clientPortalUrl
from .util import formatted_HTTPrequest


def tickle(bearer_token):
    headers = {"Authorization": "Bearer " + bearer_token}
    headers["User-Agent"] = "python/3.11"

    url = f"{clientPortalUrl}/v1/api/tickle"  # Tickle endpoint, used to ping the server and/or being the process of opening a websocket connection
    tickle_request = requests.get(
        url=url, headers=headers
    )  # Prepare and send request to /tickle endpoint, print request and response.
    print(formatted_HTTPrequest(tickle_request))
    return tickle_request.json()["session"]
