import yaml

from cryptography.hazmat.primitives import serialization

import ibkr_oauth_flow

with open("config.yaml", "r") as file:
    config = yaml.safe_load(file)

clientId = config.get("clientId")
clientKeyId = config.get("clientKeyId")
credential = config.get("credential")

# Private key in current directory.
#
path_to_PrivateKey = "privatekey.pem"


with open(path_to_PrivateKey, "r") as file:
    clientPrivateKey = file.read().encode()

private_key = serialization.load_pem_private_key(
    clientPrivateKey,
    password=None,
)

if __name__ == "__main__":
    access_token = ibkr_oauth_flow.getAccessToken(credential, clientId, clientKeyId, clientPrivateKey)
    bearer_token = ibkr_oauth_flow.getBearerToken(access_token, credential, clientId, clientKeyId, clientPrivateKey)
    ibkr_oauth_flow.ssodh_init(bearer_token)
    ibkr_oauth_flow.validate_sso(bearer_token)
    session_token = ibkr_oauth_flow.tickle(bearer_token)
    ibkr_oauth_flow.logoutSession(bearer_token)
