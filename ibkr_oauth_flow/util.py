import time
import jwt
import curlify
import logging

from requests import Response

from .const import *

RESP_HEADERS_TO_PRINT = ["Cookie", "Cache-Control", "Content-Type", "Host"]


def log_response(resp: Response) -> None:
    logging.debug(f"Request:  {curlify.to_curl(resp.request)}")
    logging.debug(f"Response: {resp.status_code} {resp.text}")


def make_jws(header, claims, clientPrivateKey):
    # Set expiration time.
    claims["exp"] = int(time.time()) + 600
    claims["iat"] = int(time.time())

    return jwt.encode(claims, clientPrivateKey, algorithm="RS256", headers=header)
