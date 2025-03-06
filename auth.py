import logging

import yaml

import ibkr_oauth_flow

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)7s] %(message)s",
)

with open("config.yaml", "r") as file:
    config = yaml.safe_load(file)

    CLIENT_ID = config.get("client_id")
    CLIENT_KEY_ID = config.get("client_key_id")
    CREDENTIAL = config.get("credential")
    PRIVATE_KEY_FILE = config.get("private_key_file")

if __name__ == "__main__":
    auth = ibkr_oauth_flow.IBKROAuthFlow(CLIENT_ID, CLIENT_KEY_ID, CREDENTIAL, PRIVATE_KEY_FILE)

    access_token = auth.get_access_token()
    bearer_token = auth.get_bearer_token(access_token)

    auth.ssodh_init(bearer_token)
    auth.validate_sso(bearer_token)

    # This will keep session alive.
    auth.tickle(bearer_token)

    auth.logout(bearer_token)
