import time
import jwt
import curlify
import logging
from typing import Any

from requests import Response

from .const import *

RESP_HEADERS_TO_PRINT = ["Cookie", "Cache-Control", "Content-Type", "Host"]


def log_response(response: Response) -> None:
    logging.debug(f"Request:  {curlify.to_curl(response.request)}")
    logging.debug(f"Response: {response.status_code} {response.text}")
    response.raise_for_status()


def make_jws(header: dict[str, Any], claims: dict[str, Any], clientPrivateKey: Any) -> Any:
    # Set expiration time.
    claims["exp"] = int(time.time()) + 600
    claims["iat"] = int(time.time())

    return jwt.encode(claims, clientPrivateKey, algorithm="RS256", headers=header)
