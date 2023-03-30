from typing import Any, Dict, Optional

from ..util._tools import _has_required_keys, _is_list

DICT_T = Dict[str, Any]


class WebAPIScheme:
    """WebAPIScheme class"""

    def __init__(self, authority: str, access_token: Optional[str]) -> None:
        """Constructor

        Parameters
        ----------
        authority : str
            value of NetEndPoint["Scheme"]["Authority"]

        access_token : str or None
            value of NetEndPoint["Scheme"]["AccessToken"]

        """
        self._authority = authority
        self._access_token = access_token

    @property
    def authority(self) -> str:
        """str: get NetEndPoint["Scheme"]["Authority"]"""
        return self._authority

    @property
    def access_token(self) -> Optional[str]:
        """str or None: get NetEndPoint["Scheme"]["AccessToken"]"""
        return self._access_token


def _is_valid_app_endpoint(jsn: DICT_T) -> bool:
    return _has_required_keys(jsn, ["APIVersion", "EndPointID"])


def _is_valid_net_endpoint(jsn: DICT_T) -> bool:
    SCHEME_KEY = "Scheme"
    SCHEME_KEYS = ["Protocol", "Authority"]
    REQUIRED_KEYS = ["APIVersion", "EndPointID", SCHEME_KEY]
    if not _has_required_keys(jsn, REQUIRED_KEYS):
        return False
    if not _is_list(jsn, SCHEME_KEY):
        return False
    for scheme in jsn[SCHEME_KEY]:
        if not _has_required_keys(scheme, SCHEME_KEYS):
            return False
    return True


def _is_valid_endpoint(jsn: DICT_T) -> bool:
    APP_KEY = "AppEndPoint"
    NET_KEY = "NetEndPoint"
    if not _has_required_keys(jsn, [APP_KEY, NET_KEY]):
        return False
    if not _is_valid_app_endpoint(jsn[APP_KEY]):
        return False
    if not _is_valid_net_endpoint(jsn[NET_KEY]):
        return False
    return True
