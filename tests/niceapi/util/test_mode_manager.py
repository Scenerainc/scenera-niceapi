from __future__ import annotations

import unittest
import logging

from time      import sleep
from random    import randint
from threading import Lock
from typing    import TYPE_CHECKING

from src.niceapi.enums             import DeviceNodeBase
from src.niceapi.util.mode_manager import constants, ModeManager

if TYPE_CHECKING:
    from typing import Optional, Tuple, Dict
__all__ = ("TestModeManager",)

test_logger = logging.getLogger()


constants.REQUEST_SLEEP = 1 # NOTE setting this value to 0 makes the test fail
                              # because the 'mode fetching' task in the separate thread
                              # won't have time to start it's loop before the 'exit variable' is set to True
constants.FAILURE_SLEEP = 0
constants.EXIT_TIMEOUT  = 1

#MockApiRequest.get_scene_mode = MockMethod(lambda x: {"NodeID": x, "SceneModeID": f"_{x}"})

class _IsAvailable:
    is_available = True

class MockApiRequest:
    """unittest ApiRequest mock"""
    test_modes: Dict[str, Tuple[bool, Optional[Dict[str, str]]]]
    test_lock : Optional[Lock]
    control    = _IsAvailable()
    management = _IsAvailable()
    endpoint   = _IsAvailable()

    def __init__(self, modes, /, lock = Lock()):
        self.test_modes = modes
        self.test_lock  = lock
        self.control    = _IsAvailable()
        self.management = _IsAvailable()
        self.endpoint   = _IsAvailable()

    def get_scene_mode(self, node_id: str):
        """mock get scenemode"""
        with self.test_lock:
            return self.test_modes[node_id]

class TestModeManager(unittest.TestCase):
    """Mode Manager tests"""
    def setUp(self) -> None:
        """Test setup"""
        self.nodes = DeviceNodeBase.generate(0x5)
        self.niceapi = MockApiRequest
    
    def test_mode_manager(self) -> None:
        """Test for the mode manager
        > We may want to test 'more' later"""
        grace_period  = 0.001 + (constants.REQUEST_SLEEP * len(self.nodes))
        exit_max      = constants.EXIT_TIMEOUT                          \
                      + (constants.FAILURE_SLEEP * len(self.nodes)) \
                      + (constants.REQUEST_SLEEP * len(self.nodes))
        
        _mode_id      = "%08x-65ce-2ca1-9000-000000000001"
        max_modes     = int((len(self.nodes) / 2) // 1)
        none_mode     = {i: None for i in self.nodes}
        mock_modes    = {i: None for i in self.nodes}
        for _ in range(max_modes):
            sample_nodeid      = self.nodes[randint(1, len(self.nodes))]
            sample_scenemodeid = _mode_id % randint(1, 0xffffffff)
            mock_modes[sample_nodeid] = {
                "NodeID": "%04x" %  sample_nodeid,
                "SceneModeID": sample_scenemodeid,
            }
        test_api = self.niceapi({"%04x" % k: (bool(v), v) for k,v, in mock_modes.items()})
        with ModeManager(test_api, self.nodes)  \
                        .context_launch(exit_max) as manager:
            sleep(grace_period)
            self.assertDictEqual(
                dict(manager),
                mock_modes
            )
            with manager.nice_api.test_lock:
                 manager.nice_api.test_modes = {"%04x" % i: (False, None,) for i in self.nodes}
            sleep(grace_period) # ensure it starts the cleanup round before exiting
            unset_modes = dict(manager)

        # Check if the modes ware unset
        self.assertDictEqual(
            unset_modes,
            none_mode
        )

if __name__ == "__main__":
    unittest.main()
