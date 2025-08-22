from __future__ import annotations

import typing
import logging

from time import sleep

from .._tools import _logger_setup

__all__ = ("HealthChecker",)

if typing.TYPE_CHECKING:
    from typing import Iterator, Callable, Literal

    from .manager import ModeManager

class HasAvailable(typing.Protocol):
    @property
    def available(self) -> bool:
        ...

logger: logging.Logger = logging.getLogger(__name__)
_logger_setup(logger, logging.DEBUG)


HEALTH_STRING = """Healthy:
niceapi.ApiRequest:
    ManagementObject: {management}
    ManagementEndpoint: {endpoint}
    ControlObject: {control}
niceapi.ModeManager:
    Thread: {thread}"""

@typing.final
class HealthChecker(typing.Mapping[str, bool]):
    __slots__ = ("mode_manager", "__keys")

    @property
    def thread(self) -> bool:
        return bool(
            self.mode_manager.task
            and self.mode_manager.task.is_alive()
        )

    @property
    def control(self) -> bool:
        return bool(self.mode_manager.nice_api.control.is_available)

    @property
    def endpoint(self) -> bool:
        return bool(self.mode_manager.nice_api.endpoint.is_available)

    @property
    def management(self) -> bool:
        return bool(self.mode_manager.nice_api.management.is_available)

    @property
    def percentage(self) -> float:
        points = [int(i) for i in self.values()]
        return (100 / len(points)) * sum(points)

    def __init__(self, mode_manager: ModeManager, /):
        self.mode_manager = mode_manager
        self.__keys = (
            "control",
            "management",
            "endpoint",
            "thread",
        )

    def __len__(self) -> int:
        return len(self.__keys)

    def __iter__(self) -> Iterator[str]:
        return iter(self.__keys)

    def __getitem__(
        self,
        key: Literal[
            "control",
            "management",
            "endpoint",
        ],
    ) -> bool:
        if key not in self.__keys:
            raise KeyError(key)
        return getattr(self, key)

    def __bool__(self) -> bool:
        return bool(
            self.thread
            and self.control
            and self.endpoint
            and self.management
        )

    def __format__(self, format_spec: str) -> str:
        if not format_spec or format_spec == "s":
            return str(self)
        if "%" in format_spec:
            return (r"{:%s}" % format_spec).format(self.percentage)
        return super().__format__(format_spec)

    def __str__(self) -> str:
        """Method to support string formatting"""
        return HEALTH_STRING.format(**self)

    def update_api(self,
                   *method: Callable[..., bool]) -> bool:
        methods = method or (
            self.mode_manager.nice_api.initialize_jose,
            self.mode_manager.nice_api.get_management_end_point,
            self.mode_manager.nice_api.get_management_object,
            self.mode_manager.nice_api.get_control_object,
        )
        for get_method in methods:
            status = get_method()
            if not status:
                logger.error("Failed to update: %r", get_method)
                return False
        return True

    def await_api(self,
                  *object_: HasAvailable,
                  timeout = 360) -> bool:
        objects = object_ or (
            self.mode_manager.nice_api.endpoint,
            self.mode_manager.nice_api.management,
            self.mode_manager.nice_api.control,
        )
        for _ in range(timeout):
            if all(obj.is_available for obj in objects):
                return True
            sleep(1)
        return True
