from __future__ import annotations

import base64
import contextlib
import json
import os
import tempfile
import traceback
from datetime import datetime
from logging import (
    INFO,
    FileHandler,
    Formatter,
    Logger,
    StreamHandler,
    getLogger,
)
from time import time
from types import TracebackType
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Generator,
    Iterable,
    List,
    Mapping,
    Optional,
    SupportsIndex,
    Type,
    Union,
)

if TYPE_CHECKING:
    from typing import TypeVar

    T = TypeVar("T")
    DICT_T = Dict[str, T]
    LIST_T = List[str]

LOG_FORMAT: str = (
    "%(asctime)s %(name)s:%(lineno)s %(funcName)s [%(levelname)s]: %(message)s"
)


def _json_key(key: Union[str, SupportsIndex, T]) -> Union[str, T]:
    if isinstance(key, str) or hasattr(key, "__str__"):
        key: str
        return str(key)
    if hasattr(key, "__index__"):
        key: SupportsIndex
        return hex(key)
    key: T
    return key


def _json_encoder_default(
    obj: Any,
    /,
) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if hasattr(obj, "__index__"):
        return int(obj)
    if isinstance(obj, Mapping):
        return {_json_key(k): _json_encoder_default(v) for k, v, in obj}
    if isinstance(obj, Iterable):
        return [_json_encoder_default(i) for i in obj]
    return obj


def _logger_setup(
    logger: Logger, level: Union[int, str], output: Optional[str] = None
) -> None:
    # FORMATTER
    formatter = Formatter(LOG_FORMAT)

    # CONSOLE
    console_handler = StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # FILE
    if output:
        file_handler = FileHandler(output)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # LEVEL
    logger.setLevel(level)


_logger: Logger = getLogger(__name__)
_logger_setup(_logger, INFO)


@contextlib.contextmanager
def _logging_time(
    flag: bool, logger: Logger, msg: str
) -> Generator[None, None, None]:
    start_time = None
    if flag:
        start_time = time()
    try:
        yield
    finally:
        if start_time:
            logger.info(f"{msg} took {time() - start_time}s")


class _TracebackOnException:
    def __enter__(self) -> None:
        pass

    def __exit__(
        self,
        exctype: Optional[Type[BaseException]],
        excinst: Optional[BaseException],
        exctb: Optional[TracebackType],
    ) -> bool:
        ret = exctype is not None
        if ret:
            traceback.print_exception(exctype, excinst, exctb)
        return ret


def _datetime_utcnow() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _datetime_decode(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")


def _base64url_decode(b64url: str) -> bytes:
    return base64.urlsafe_b64decode(b64url + "=" * (4 - len(b64url) % 4))


def _file_update(path: str, data: Any) -> bool:
    tempfile_path = ""

    with _TracebackOnException():
        directory, filename = os.path.split(path)
        if not directory:
            directory = "."
        if not filename:
            _logger.error(f"No filename:{path}")
            return False
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as f:
            f.write(data)
            tempfile_name = f.name
        # logger.info(f"Updating: {path}")
        tempfile_path = os.path.join(directory, tempfile_name)
        os.chmod(tempfile_path, 0o644)
        os.replace(tempfile_path, path)
        return True

    # remove temporary file if exists
    with contextlib.suppress(FileNotFoundError):
        os.remove(tempfile_path)

    return False


def _json_load(path: str) -> Optional[Any]:
    with _TracebackOnException():
        with contextlib.suppress(FileNotFoundError):
            with open(path) as f:
                # logger.info(f"Loading: {path}")
                obj = json.load(f)
                return obj

    return None


def _is_list(jsn: DICT_T, key: str) -> bool:
    value = jsn.get(key, None)
    if value is None:
        _logger.error(f"{key} not found")
        return False
    if not isinstance(value, list):
        _logger.error(f"{key} is not a list")
        return False
    return True


def _has_required_keys(jsn: DICT_T, keys: LIST_T) -> bool:
    lack = [key for key in keys if key not in jsn]
    if lack:
        _logger.error(f"Lack of required parameter(s):{lack}")
        return False
    return True
