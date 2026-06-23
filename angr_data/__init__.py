from __future__ import annotations

import os

__version__ = "9.2.222.dev0"

_BASE = os.path.dirname(os.path.realpath(__file__))


def get_path(*parts: str) -> str:
    """
    Return the absolute path to a data file or directory bundled inside angr_data.

    Example:
        angr_data.get_path("procedures", "definitions", "win32")
        angr_data.get_path("rust", "analyses", "type_db", "1.39.0.json")
    """
    return os.path.join(_BASE, *parts)
