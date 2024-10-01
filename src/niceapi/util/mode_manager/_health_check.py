from __future__ import annotations

from typing import TYPE_CHECKING, Mapping, final

__all__ = ("HealthChecker",)

if TYPE_CHECKING:
    from typing import Iterator, Literal

    from .manager import ModeManager


HEALTH_STRING = """Healthy:
niceapi.ApiRequest:
    ManagementObject: {management}
    ManagementEndpoint: {endpoint}
    ControlObject: {control}
niceapi.ModeManager:
    Thread: {thread}"""


@final
class HealthChecker(Mapping[str, bool]):
    __slots__ = ("mode_manager", "__keys")

    @property
    def thread(self) -> bool:
        return bool(
            self.mode_manager.task and self.mode_manager.task.is_alive()
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
            self.thread and self.control and self.endpoint and self.management
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
