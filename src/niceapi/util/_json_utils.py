
from __future__ import annotations

from enum     import Enum
from datetime import datetime, timezone
from typing   import (TYPE_CHECKING,
                      SupportsIndex,
                      SupportsInt,
                      MappingView,
                      Iterable,
                      Mapping,)

if TYPE_CHECKING:
    from typing import Dict, Any, TypeVar
    from typing_extensions import Self

    T = TypeVar("T")

def _json_key(key: Any, /):
    if isinstance(key, datetime):
        return key.astimezone(timezone.utc).isoformat()
    if isinstance(key, SupportsIndex, SupportsInt):
        return hex(int(key))
    return key

def json_pre_encode(obj: Any, /):
    """Example usage
    
    >>> import json
    >>> from typing   import Mapping
    >>> from datetime import datetime
    >>> from niceapi.util._json_utils import json_pre_encode
    >>>
    >>> class Sample(Mapping):
    >>>     def __init__(self, data, **kwargs)
    >>>         self.data = data.update(kwargs)
    >>>     def __iter__(self):
    >>>         return iter(self.data)
    >>>     def __len__(self):
    >>>         return len(self.data)
    >>>     def __getitem__(self, *args, **kwargs):
    >>>         return self.data.__getitem__(self)
    >>>
    >>> sample = Sample(one=1, two=2, time=datetime.now())
    >>> json.dumps(sample)
    Traceback (most recent call last):
        File "<stdin>", line 1, in <module>
        File "/usr/lib/python3.10/json/__init__.py", line 231, in dumps
            return _default_encoder.encode(obj)
        File "/usr/lib/python3.10/json/encoder.py", line 199, in encode
            chunks = self.iterencode(o, _one_shot=True)
        File "/usr/lib/python3.10/json/encoder.py", line 257, in iterencode
            return _iterencode(o, 0)
        File "/usr/lib/python3.10/json/encoder.py", line 179, in default
            raise TypeError(f'Object of type {o.__class__.__name__} '
            TypeError: Object of type Sample is not JSON serializable
    >>> json.dumps(sample, default=json_pre_encode)
    {"one": 1, "two": 2, "time": "2024-09-06T03:10:32.131221+00:00"}
    """
    if isinstance(obj, Enum):
        return json_pre_encode(obj.value)
    if isinstance(obj, (Mapping, MappingView, dict)):
        return {_json_key(k): json_pre_encode(v)
                for k,v, in obj.items()}
    if not isinstance(obj, str)       \
       and isinstance(obj, (Iterable)):
        return [json_pre_encode(i) for i in obj]
    return _json_key(obj)


class JavaScriptObjectNotationMap(Mapping):
    if TYPE_CHECKING:
        _json: Dict[str, Any]

    def __iter__(self):
        return iter(self._json)

    def __len__(self):
        return len(self._json)

    def __getitem__(self, *args, **Kwargs):
        return self._json.__getitem__(*args, **Kwargs)

    @property
    def json(self) -> Dict[str, Any]:
        return self._json
