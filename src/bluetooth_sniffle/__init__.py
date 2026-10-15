"""Backward-compatibility shim for bluetooth_sniffle -> airtell."""

from __future__ import annotations

import airtell
from airtell import *  # noqa: F401, F403

__version__ = getattr(airtell, "__version__", "0.1.0")
__all__ = getattr(airtell, "__all__", [])
__path__ = airtell.__path__


def __getattr__(name: str):
    return getattr(airtell, name)
