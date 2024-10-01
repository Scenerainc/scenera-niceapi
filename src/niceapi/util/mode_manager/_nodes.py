from __future__ import annotations

import re
from contextlib import suppress
from enum import EnumMeta, IntEnum
from typing import TYPE_CHECKING

import numpy as np

from .constants import DEVICE_NODE_COUNT

__all__ = (
    "DeviceNodeBase",
    "NodeEnum",
    "NodeEnumMeta",
)

if TYPE_CHECKING:
    from typing import Optional, SupportsIndex, Union

    from numpy import uint16
    from typing_extensions import Self


class NodeEnumMeta(EnumMeta):
    """NodeEnum meta clas"""

    def __getitem__(cls, key: Union[SupportsIndex, str]):
        """Get the node by id as a string or integer"""
        if hasattr(key, "__index__"):
            return cls(key)  # pylint: disable=E1120
        with suppress(ValueError):
            as_int = int(key, base=16) or None
            if not as_int:
                raise ValueError()
            key = f"{as_int:04X}"
        return super().__getitem__(key)

    def __getattr__(cls, name: str):
        """Get the node by string name with a underscore ('_') prefix"""
        match_ = re.match("_[0-9a-z]{4}", name, re.IGNORECASE)
        if match_:
            name = name[1:].upper()
        return super().__getattr__(name)


class NodeEnum(IntEnum, metaclass=NodeEnumMeta):
    """Node enum"""

    def __format__(self, format_spec: str):
        return super(int, self).__format__(format_spec or "04x")

    @classmethod
    def generate(
        cls,
        node_count: uint16 = DEVICE_NODE_COUNT,
        enum_name: Optional[str] = None,
    ) -> Self:
        """Generate NodeEnum based on this Enum"""
        device_node_count = np.uint16(
            node_count
        )  # guarantee a value from 0 to 0xFFFF
        offset = np.uint32(
            1
        )  # offset is type np.uint32 because: np.uint16(0xFFFF) + (np.uint16 or int)(1) == np.uint16(0) (i.e integer OverFlow)
        nodes = [
            (
                f"{i:04X}",
                np.uint16(i),
            )
            for i in range(offset, device_node_count + np.uint32(offset))
        ]
        return cls(
            enum_name
            or getattr(cls, "__name__", "DeviceNode").replace("Base", ""),
            nodes,
        )


class DeviceNodeBase(NodeEnum):
    """Device Node enum, it's members are determined by processing ability of the device.

    > the max nodes a device will ever be able to support is `0xffff`, i.e. every node from `1` to and including `65535` in decimal

    The usage of this enum is slightly 'odd' because an enum's member can not start with a numeric character
    thus to the get Enum member '0001' you can't just do 'EnumName.0001'...

    A few alternatives exist, i.e. to get the Enum member for '0001' all of the following work:

    node_enum = DeviceNode.generate(1)

    - method 1 - prefix the enum member with an underscore ('_') (member: RegEx[r'^_[0-9A-F]{4}$']):
        node_enum._0001

    - method 2 - using __getitem__(..., member: RegEx[r'^[0-9a-fA-F]{4}', re.CASE_INSENSITIVE]) with the NodeID as stored in SceneMode["NodeID"]:
        node_enum['0001']

    - method 3 - using __getitem__(..., member: HexString) (a hexadecimal string as outputted by 'hex(value: SupportsIndex, /) -> HexString')
        node_enum['0x1']

    - method 4 - using __getitem__(..., member: SupportsIndex)
        node_enum[0x1 or 0b1 or 0o1 or 1]

    - method 5 - Using 'getattr(obj: node_enum, member: RegEx[r'^[0-9A-F]{4}$'])'
        member = "0001".upper()
        getattr(node_enum, member)

    - method 6 - using the IntEnum's __call__(..., member: int) to get the member by the integer value
        EnumName(0x1 or 0b1 or 0o1 or 1)

    In reality you likely not have to interact with it this directly, it will the the 'key' of the ModeManager mapping
    """
