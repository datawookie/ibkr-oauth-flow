import logging
import time

import yaml

import ibkr_oauth_flow

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)7s] %(message)s",
)

logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

with open("config.yaml", "r") as file:
    config = yaml.safe_load(file)

    CLIENT_ID = config.get("client_id")
    CLIENT_KEY_ID = config.get("client_key_id")
    CREDENTIAL = config.get("credential")
    PRIVATE_KEY_FILE = config.get("private_key_file")

if __name__ == "__main__":
    auth = ibkr_oauth_flow.IBKROAuthFlow(CLIENT_ID, CLIENT_KEY_ID, CREDENTIAL, PRIVATE_KEY_FILE)

    auth.get_access_token()
    auth.get_bearer_token()

    auth.ssodh_init()
    auth.validate_sso()

    # This will keep session alive.
    for _ in range(3):
        auth.tickle()
        time.sleep(10)

    auth.logout()
