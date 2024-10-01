"""Module constants, setting these affects the mode manager's behavior"""

from ._utils import intenv

__all__ = (
    "REQUEST_SLEEP",
    "FAILURE_SLEEP",
    "EXIT_TIMEOUT",
    "DEVICE_NODE_COUNT",
)

REQUEST_SLEEP = 10
FAILURE_SLEEP = REQUEST_SLEEP
EXIT_TIMEOUT = 60

DEVICE_NODE_COUNT = intenv("DEVICE_NODE_COUNT", 4)
