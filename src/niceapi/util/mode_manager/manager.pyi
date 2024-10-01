from __future__ import annotations

import logging
from contextlib import contextmanager
from threading import Lock, Thread
from typing import TYPE_CHECKING, Mapping, final

from niceapi.api.requests import ApiRequest

from .._tools import _logger_setup
from ._health_check import HealthChecker
from ._nodes import DeviceNodeBase
from .constants import DEVICE_NODE_COUNT, EXIT_TIMEOUT

__all__ = ("ModeManager",)

if TYPE_CHECKING:
    from types import TracebackType
    from typing import (
        Any,
        Dict,
        Generator,
        Iterable,
        Literal,
        MutableMapping,
        Optional,
        SupportsIndex,
        Type,
        TypeVar,
        Union,
    )

    from typing_extensions import Self

    from ...annotations.scenemode import (
        IGNORECASE,
        Example,
        RegEx,
        RegExpr,
        SceneMode,
    )

    N_API = TypeVar("N_API")
    _Exception = TypeVar("_Exception", bound=BaseException)
    DeviceNode = TypeVar("DeviceNode", bound=DeviceNodeBase)

logger: logging.Logger = logging.getLogger(__name__)
_logger_setup(logger, logging.DEBUG)

@final
class ModeManager(Mapping["DeviceNode", "SceneMode"]):
    """Manages device modes and ensures proper scene mode assignment.

    Usage:
    >>> api = ApiRequest()
    >>> mode_manager = ModeManager(api)
    >>> mode_manager.start()
    >>> mode = mode_manager.get_scene_mode(device_node)
    >>> mode_manager.stop()
    """

    task: Optional[Thread]
    nodes: DeviceNode
    nice_api: N_API

    @property
    def healthy(self) -> HealthChecker:
        """Checks the health of the ModeManager and NiceAPI.

        Returns:
            HealthChecker: A status object that evaluates the system health.
        """
    def __init__(
        self,
        api: ApiRequest,
        *,
        device_nodes: DeviceNode = DeviceNodeBase.generate(DEVICE_NODE_COUNT),
        container: Optional[MutableMapping] = ...,
        lock: Optional[Lock] = ...,
    ):
        """Initializes ModeManager.

        Args:
            api: ApiRequest
                The API request instance used for communication.
            device_nodes: DeviceNode, optional
                Device nodes to manage, by default generates based on DEVICE_NODE_COUNT.
            container: Optional[MutableMapping], optional
                Optional container for node and mode storage.
            lock: Optional[Lock], optional
                Optional threading lock for synchronization.
        """
    def __enter__(self) -> Dict[DeviceNode, Optional[SceneMode]]:
        """Context manager entry.

        Returns:
            Dict[DeviceNode, Optional[SceneMode]]: 'Current' device node mapping.

        > 'blocks' updates until exited, any calls to the parent object while inside
        > the 'context' will result in a 'deadlock'
        """
    def __exit__(
        self,
        exc_type: Optional[Type[_Exception]],
        exc_info: Optional[_Exception],
        traceback: Optional[TracebackType],
    ):
        """Context manager exit.

        Cleans up resources and handles any exceptions raised within the context.

        Args:
            exc_type: Optional[Type[_Exception]]
                The type of exception that was raised, if any.
            exc_info: Optional[_Exception]
                The actual exception instance.
            traceback: Optional[TracebackType]
                Traceback object containing the stack trace.
        """
    def __len__(self) -> int:
        """Returns the number of device nodes.

        Returns:
            int: Number of nodes being managed.
        """
    def __iter__(self) -> Iterable[DeviceNode]:
        """Returns an iterator over the device nodes.

        Returns:
            Iterable[DeviceNode]: An iterator of device nodes.
        """
    def __getitem__(
        self,
        index: Union[
            DeviceNode,
            SupportsIndex,
            RegEx[RegExpr[r"^[0-9a-f]$"], IGNORECASE],
            Example[Literal["0001", "ffff", "FFFF"]],
        ],
        /,
    ) -> Optional[SceneMode]:
        """Gets the SceneMode for a given device node or index.

        Args:
            index: Union[DeviceNode, SupportsIndex, RegEx, Example]
                The device node or index to retrieve SceneMode.

        Returns:
            Optional[SceneMode]: The SceneMode if available, otherwise None.
        """
    def _mode_thread(self):
        """Internal thread handling mode operations.

        Manages async mode-related tasks for each device node.
        """
    def _fetch(
        self, __node_index: DeviceNode, *, _retries: int = MODE_RETRIES
    ) -> bool:
        """Fetches the mode information for a device node.

        Args:
            __node_index: DeviceNode
                The device node to fetch mode information for.
            _retries: int, optional
                Number of retries in case of failure, by default MODE_RETRIES.

        Returns:
            bool: True if successful, False otherwise.
        """
    @classmethod
    def daemon_launch(cls, *init_args, **init_kwargs) -> Self:
        """Launches ModeManager in a separate daemon thread.

        Args:
            *init_args: Arguments to initialize the ModeManager.
            **init_kwargs: Keyword arguments to initialize the ModeManager.

        Returns:
            Self: An instance of ModeManager running in daemon mode.
        """
    @contextmanager
    def context_launch(
        self,
        exit_timeout=EXIT_TIMEOUT,
    ) -> Generator[Self, Any, None]:
        """Launches ModeManager in a context manager for automatic cleanup.

        Args:
            exit_timeout: float, optional
                Timeout value for stopping ModeManager, by default EXIT_TIMEOUT.

        Yields:
            Generator[Self, Any, None]: The running ModeManager instance.
        """
    def get_scene_mode(
        self,
        node_id: Union[
            DeviceNode,
            SupportsIndex,
            RegEx[RegExpr[r"^[0-9a-f]$"], IGNORECASE],
        ],
    ) -> Optional[SceneMode]:
        """Retrieves the scene mode for a given node ID.

        Args:
            node_id: Union[DeviceNode, SupportsIndex, RegEx]
                The node ID to retrieve the scene mode.

        Returns:
            Optional[SceneMode]: The SceneMode associated with the node, if any.
        """
    def start(self, daemon: bool = False) -> None:
        """Starts the ModeManager.

        Args:
            daemon: bool, optional
                Whether to run the manager as a daemon, by default False.
        """
    def stop(self, timeout: Optional[float] = EXIT_TIMEOUT) -> None:
        """Stops the ModeManager.

        Args:
            timeout: Optional[float], optional
                Time to wait before force-stopping, by default EXIT_TIMEOUT.
        """
