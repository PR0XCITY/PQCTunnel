"""
tests/conftest.py
==================
Shared pytest configuration and fixtures.

When liboqs is not available (native shared library not installed / no cmake
on Windows), automatically skip test_crypto.py and test_session.py with a
clear message rather than raising a hard INTERNALERROR.

test_server.py has no native-library dependency and always runs.
"""

from __future__ import annotations

import sys
import pytest


def pytest_collection_modifyitems(config, items):
    """Skip liboqs-dependent tests when the native library cannot be loaded."""
    try:
        import oqs  # noqa: F401
        _oqs_ok = True
    except (ImportError, RuntimeError, SystemExit):
        _oqs_ok = False

    if _oqs_ok:
        return  # all good — nothing to skip

    skip_no_oqs = pytest.mark.skip(
        reason=(
            "liboqs native shared library not available on this system. "
            "Run inside Docker (see Dockerfile.dev) or install cmake + gcc and "
            "let liboqs-python auto-build the library. "
            "test_server.py has no native-library dependency and still runs."
        )
    )

    LIBOQS_TEST_FILES = {"test_crypto.py", "test_session.py"}

    for item in items:
        if item.fspath.basename in LIBOQS_TEST_FILES:
            item.add_marker(skip_no_oqs)
