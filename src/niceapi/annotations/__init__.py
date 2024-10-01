from . import scenemode
from .scenemode import *

# type: ignore

__local = ("scenemode",)

__all__ = __local + scenemode.__all__

if __name__:
    # Import guard, at the moment this submodule only contains 'annotations' and is incomplete
    import logging

    _IMPORT_WARNING = '''Imported a type annotation  module, instead please guard the import like so:

    >>> from __future__ import annotations # NOTE This converts annotation to strings at runtime,
    >>>                                    # Which avoids NameErrors for undefined variables for the types.
    >>>                                    # Types are not checked at runtime and only benefit developers,
    >>>                                    # Thus the name 'annotations' 
    >>>
    >>> from typing import TYPE_CHECKING # NOTE: TYPE_CHECKING is always False at runtime
    >>>
    >>> from numpy import uint16 # Not strictly required, but helps to annotate the 'size' of the value
    >>>
    >>> if TYPE_CHECKING:
    ...     # As TYPE_CHECKING is always False at runtime the following module
    ...     # is never actually imported 
    ...     from %s import SceneMode
    >>>
    >>> class InvalidSceneMode(Exception):
    ...     """The given SceneMode does not adhere to the specification"""
    ...
    >>> def get_node_id(scene_mode: SceneMode) -> uint16:
    ...     """Example method that parses the NodeID from the SceneMode object
    ...
    ...     Args:
    ...         scene_mode: SceneMode
    ...             A SceneModeLike Dictionary or Mapping,
    ...             > Must support the method "__getitem__(..., key: Literal['NodeID'], /) \
    -> RegEx[Literal[r'^[0-9a-fA-F]{4}$']]: ..."
    ...
    ...     Returns:
    ...         np.uint8:
    ...             The NodeID as an unsigned 16 bit integer
    ...             i.e. a value from   1          to 65535  (decimal)
    ...                  a value from 0x1          to 0xffff (hexadecimal)
    ...                  a value from np.uint16(1) to np.int16(-1).astype(np.uint16)
    ...                  
    ...         > 'Unsigned': Not accepting negative numbers; having only a positive absolute value.
    ...
    ...     Raises:
    ...         InvalidSceneMode:
    ...             the input argument is not SceneModeLike"""
    ...     try:
    ...         node_id = int(scene_mode["NodeID"], base=16)
    ...         return uint8(node_id)
    ...     except (TypeError, ValueError, KeyError, OverFlowError) as _e:
    ...         raise InvalidSceneMode from _e
    ...
    '''
    logging.warning(_IMPORT_WARNING, __name__)
