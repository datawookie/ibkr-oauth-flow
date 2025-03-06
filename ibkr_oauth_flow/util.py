import json
import pprint
import time
import jwt

from requests import Response

from .const import *

RESP_HEADERS_TO_PRINT = ["Cookie", "Cache-Control", "Content-Type", "Host"]


def formatted_HTTPrequest(resp: Response) -> str:
    """Print request and response legibly."""
    req = resp.request
    rqh = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
    rqh = rqh.replace(", ", ",\n    ")
    rqb = req.body if req.body else ""

    try:
        rsb = f"\n{pprint.pformat(resp.json())}\n" if resp.text else ""
    except json.JSONDecodeError:
        rsb = resp.text
    rsh = "\n".join([f"{k}: {v}" for k, v in resp.headers.items() if k in RESP_HEADERS_TO_PRINT])

    return_str = "\n".join(
        [
            "-----------REQUEST-----------",
            f"{req.method} {req.url}",
            "",
            rqh,
            f"{rqb}",
            "",
            "-----------RESPONSE-----------",
            f"{resp.status_code} {resp.reason}",
            rsh,
            f"{rsb}\n",
        ]
    )
    return return_str


def make_jws(header, claims, clientPrivateKey):
    # Set expiration time.
    claims["exp"] = int(time.time()) + 600
    claims["iat"] = int(time.time())

    return jwt.encode(claims, clientPrivateKey, algorithm="RS256", headers=header)
