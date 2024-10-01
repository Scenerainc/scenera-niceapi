from __future__ import annotations

import logging
from contextlib import contextmanager
from threading import Lock, Thread
from time import sleep
from typing import TYPE_CHECKING, Mapping, final

from .._tools import _logger_setup
from ._health_check import HealthChecker
from ._nodes import DeviceNodeBase
from .constants import DEVICE_NODE_COUNT, EXIT_TIMEOUT, REQUEST_SLEEP

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
        ParamSpec,
        SupportsIndex,
        Type,
        TypeVar,
        Union,
    )

    from typing_extensions import Self

    from niceapi import ApiRequest

    from ...annotations.scenemode import (
        IGNORECASE,
        Example,
        RegEx,
        RegExpr,
        SceneMode,
    )

    P = ParamSpec("P")
    T = TypeVar("T")
    _Exception = TypeVar("_Exception", bound=BaseException)
    DeviceNode = TypeVar("DeviceNode", bound=DeviceNodeBase)

logger: logging.Logger = logging.getLogger(__name__)
_logger_setup(logger, logging.DEBUG)


@final
class ModeManager(Mapping["DeviceNode", "SceneMode"]):
    __slots__ = (
        "__nice_api",
        "__data",
        "__nodes",
        "__exit",
        "__task",
        "__lock",
    )

    if TYPE_CHECKING:
        __nice_api: ApiRequest

        __exit: bool
        __nodes: DeviceNode
        __data: Union[
            Mapping[DeviceNode, SceneMode], Dict[DeviceNode, SceneMode]
        ]
        __task: Optional[Thread]
        __lock: Optional[Lock]

    task = property()
    nodes = property()

    @property
    def healthy(self):
        return HealthChecker(self)

    @task.getter
    def task(self) -> Optional[Thread]:
        return self.__task

    @nodes.getter
    def nodes(self) -> DeviceNode:
        return self.__nodes

    @property
    def nice_api(self) -> ApiRequest:
        with self:
            return self.__nice_api

    def __init__(
        self,
        api: ApiRequest,
        /,
        device_nodes: DeviceNode = DeviceNodeBase.generate(DEVICE_NODE_COUNT),
        container: Optional[MutableMapping] = None,
        lock: Optional[Lock] = Lock(),
    ):
        self.__nice_api = api
        self.__lock = lock
        self.__data = container or {}
        self.__task = None
        self.__exit = True
        self.__nodes = device_nodes

    def __enter__(self) -> Dict[DeviceNode, Optional[SceneMode]]:
        if not self.__task:
            logger.warning("Mode accessed without the manager running!")
        if self.__lock is not None:
            self.__lock.acquire(
                blocking=True,
                timeout=60,
            )
        return self.__data

    def __exit__(
        self,
        exc_type: Optional[Type[_Exception]],
        exc_info: Optional[_Exception],
        traceback: Optional[TracebackType],
    ) -> Literal[False]:
        if exc_type is None:
            assert (
                exc_info is None and traceback is None
            ), "This assertion should never fail, placeholder for now"
        if self.__lock is not None:
            self.__lock.release()
        return False

    def __len__(self):
        with self as data:
            return len(data)

    def __iter__(self) -> Iterable[DeviceNode]:
        return iter(self.nodes)

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
        node_id = self.nodes[index]
        with self as data:
            return data.__getitem__(node_id)

    def _mode_thread(self):
        while not self.__exit:
            logger.debug("Mode manager looping over %d nodes", len(self.nodes))
            for node_id in self.nodes:
                try:
                    self._fetch(node_id)
                except TimeoutError as ex:
                    logger.warning(
                        "Timed out fetch scenemode for node %04d (%s)",
                        node_id,
                        ex,
                    )
                sleep(REQUEST_SLEEP)
        logger.debug("Mode thread finished")

    def _fetch(self, __node_index: DeviceNode) -> bool:
        node = self.nodes[__node_index]

        try:
            status, _mode = self.nice_api.get_scene_mode(f"{node:04x}")
            logger.debug(_mode)
            mode: SceneMode = _mode or {}
        except TimeoutError as _e:
            # NOTE (the following to be confirmed)
            # So far it seems something in the niceapi actually ensures
            # this exception never propagates 'upstream',
            # have yet to see this log message appear...
            logger.warning(
                "Timed out getting node: %04X's scenemode configuration, %s",
                node,
                _e,
            )
            raise

        if not status:
            if not self.healthy:
                logger.warning("Api unhealthy, skipping: %04X", node)
                logger.debug("Health: %s", self.healthy)
            logger.debug(
                "requested node: '%04x' does not appear to be configured", node
            )
        previous = self.get(node)
        if previous:
            if previous.get("SceneModeID", "") == mode.get("SceneModeID", ""):
                return
            if logger.isEnabledFor(logging.INFO) and previous and not mode:
                logger.info(
                    "Removing node configuration ('%s')",
                    previous.get("SceneModeID", None),
                )
        with self as data:
            if mode:
                logger.info(
                    "Updating SceneMode to new scenemode ('%s')",
                    mode.get("SceneModeID", None),
                )
            data[node] = mode or None
        return

    @classmethod
    def daemon_launch(cls, *init_args, **init_kwargs) -> Self:
        self = cls(*init_args, **init_kwargs)
        self.start(daemon=True)
        return self

    @contextmanager
    def context_launch(
        self,
        exit_timeout=EXIT_TIMEOUT,
    ) -> Generator[Self, Any, None]:
        try:
            self.start(daemon=False)
            yield self
        finally:
            self.stop(exit_timeout)

    def get_scene_mode(
        self,
        node_id: Union[
            DeviceNode,
            SupportsIndex,
            RegEx[RegExpr[r"^[0-9a-f]$"], IGNORECASE],
        ],
    ) -> Optional[SceneMode]:
        return self.get(node_id)

    def start(self, daemon=True) -> None:
        if self.__task is not None:
            raise RuntimeError("Mode Manager task already exists")
        self.__data = {i: None for i in self.__nodes}
        self.__exit = False
        self.__task = Thread(
            target=self._mode_thread,
            daemon=daemon,
        )
        self.__task.start()

    def stop(self, timeout: Optional[float] = EXIT_TIMEOUT) -> None:
        if self.__task is None:
            raise RuntimeError("Task must be started before joining")
        self.__exit = True
        self.__data.clear()
        self.__task.join(timeout)
        self.__task = None
