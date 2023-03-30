import json
import os
import shutil
import sys
import threading
from logging import INFO, getLogger
from pathlib import Path
from typing import Any, Dict, List, Tuple, Type

from ._tools import _logger_setup

SCENE_MARK_T = Dict[str, Any]
SCENE_DATA_T = Dict[str, Any]
Storage_T = Type["_Storage"]

logger = getLogger(__name__)
_logger_setup(logger, INFO)

STORAGE_DIR = "storage"


class _Storage:
    _sequence_number = 0
    _lock = threading.Lock()
    _ready = False
    _size = 0
    _amount = 0
    _list: List[Tuple[str, int]] = list()

    @classmethod
    def set_size(cls: Storage_T, size: int) -> None:
        storage = Path(STORAGE_DIR)
        if storage.exists():
            shutil.rmtree(storage)
        cls._size = size

    @classmethod
    def store_scene_mark(cls: Storage_T, scene_mark: SCENE_MARK_T) -> None:
        cls._lock.acquire()
        try:
            scene_mark_id = scene_mark["SceneMarkID"]
            filename = (
                f"SceneMark_{scene_mark_id}"
                f"_seq_{cls._get_sequence_number()}.json"
            )
            path = os.path.join(STORAGE_DIR, filename)
            cls._store_text(path, json.dumps(scene_mark))
        except Exception as e:
            logger.error(e)
        cls._lock.release()

    @classmethod
    def store_scene_data(cls: Storage_T, scene_data: SCENE_DATA_T) -> None:
        cls._lock.acquire()
        try:
            scene_data_id = scene_data["DataID"]
            file_type = scene_data["FileType"]
            if file_type == "Image":
                filename = (
                    f"Image_{scene_data_id}"
                    f"_seq_{cls._get_sequence_number()}.json"
                )
            else:
                section = scene_data["Section"]
                last_section = scene_data["LastSection"]
                filename = (
                    f"Video_{scene_data_id}"
                    f"_seq_{cls._get_sequence_number()}"
                    f"_Chunk_{section}_NumberOfChunk_{last_section}.json"
                )
            path = os.path.join(STORAGE_DIR, filename)
            cls._store_text(path, json.dumps(scene_data))
        except Exception as e:
            logger.error(e)
        cls._lock.release()

    @classmethod
    def _get_sequence_number(cls: Storage_T) -> int:
        cls._sequence_number += 1
        return cls._sequence_number

    @classmethod
    def _store_text(cls: Storage_T, path: str, text: str) -> None:
        if not cls._ready:
            Path(STORAGE_DIR).mkdir(exist_ok=True)
            cls._ready = True

        size = sys.getsizeof(text)
        while (cls._amount + size) > cls._size:
            old = cls._list.pop(0)
            Path(old[0]).unlink()
            cls._amount -= old[1]

        new = (path, size)
        cls._list.append(new)
        cls._amount += size

        with open(path, "w") as f:
            f.write(text)
