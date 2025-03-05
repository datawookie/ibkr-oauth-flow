import json
import pprint
import jwt
import time
import math

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


def compute_client_assertion(credential, url, clientId, clientKeyId, clientPrivateKey):
    now = math.floor(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": f"{clientKeyId}"}

    if url == f"{oauth2Url}/api/v1/token":
        claims = {
            "iss": f"{clientId}",
            "sub": f"{clientId}",
            "aud": f"{audience}",
            "exp": now + 20,
            "iat": now - 10,
        }

    elif url == f"{gatewayUrl}/api/v1/sso-sessions":
        claims = {
            "ip": IP,
            #'service': "AM.LOGIN",
            "credential": f"{credential}",
            "iss": f"{clientId}",
            "exp": now + 86400,
            "iat": now,
        }

    assertion = make_jws(header, claims, clientPrivateKey)
    return assertion
