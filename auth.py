import logging
import time

import ibkr_oauth_flow

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)7s] %(message)s",
)

logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

if __name__ == "__main__":
    auth = ibkr_oauth_flow.auth_from_yaml("config.yaml")

    auth.get_access_token()
    auth.get_bearer_token()

    auth.ssodh_init()
    auth.validate_sso()

    # This will keep session alive.
    for _ in range(3):
        auth.tickle()
        time.sleep(10)

    auth.logout()
