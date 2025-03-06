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

# # Private key in current directory.
# #
# path_to_PrivateKey = "privatekey.pem"


# with open(path_to_PrivateKey, "r") as file:
#     clientPrivateKey = file.read().encode()

# private_key = serialization.load_pem_private_key(
#     clientPrivateKey,
#     password=None,
# )

if __name__ == "__main__":
    # access_token = ibkr_oauth_flow.getAccessToken(credential, clientId, clientKeyId, clientPrivateKey)
    # bearer_token = ibkr_oauth_flow.getBearerToken(access_token, credential, clientId, clientKeyId, clientPrivateKey)
    # ibkr_oauth_flow.ssodh_init(bearer_token)
    # ibkr_oauth_flow.validate_sso(bearer_token)
    # # This will keep session alive.
    # session_token = ibkr_oauth_flow.tickle(bearer_token)
    # ibkr_oauth_flow.logoutSession(bearer_token)

    auth = ibkr_oauth_flow.IBKROAuthFlow(CLIENT_ID, CLIENT_KEY_ID, CREDENTIAL, PRIVATE_KEY_FILE)

    access_token = auth.get_access_token()
