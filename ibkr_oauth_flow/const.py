import requests

# Get public IP address.
#
IP = requests.get("https://api.ipify.org").content.decode("utf8")

host = "api.ibkr.com"
oauth2Url = "https://api.ibkr.com/oauth2"
gatewayUrl = "https://api.ibkr.com/gw"
clientPortalUrl = "https://api.ibkr.com"
audience = "/token"

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
SCOPE = "sso-sessions.write"
GRANT_TYPE = "client_credentials"
