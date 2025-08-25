import yaml
from pathlib import Path

from .logger import logger
from .auth import IBKROAuthFlow

__all__ = [
    "IBKROAuthFlow",
    "auth_from_yaml",
]


def auth_from_yaml(path: str | Path) -> IBKROAuthFlow:
    """
    Create an IBKROAuthFlow instance from a YAML configuration file.

    Args:
        path (str | Path): The path to the YAML configuration file.

    Returns:
        IBKROAuthFlow: An instance of IBKROAuthFlow.
    """
    path_absolute = Path(path).resolve()
    logger.info(f"Load configuration from {path_absolute}.")
    with open(path_absolute, "r") as f:
        config = yaml.safe_load(f)

    return IBKROAuthFlow(
        client_id=config["client_id"],
        client_key_id=config["client_key_id"],
        credential=config["credential"],
        private_key_file=config["private_key_file"],
        domain=config.get("domain", "api.ibkr.com"),
    )
