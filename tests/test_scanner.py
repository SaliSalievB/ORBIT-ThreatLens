import pytest

from orbit.models import ScanOptions
from orbit.scanner import AuthorizationRequired, scan_target


def test_scan_requires_authorization() -> None:
    with pytest.raises(AuthorizationRequired):
        scan_target("example.com", ScanOptions(authorized=False))
