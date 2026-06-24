from __future__ import annotations

import os


def get_hook_dirs() -> list[str]:
    """
    Entry point for PyInstaller (``pyinstaller40`` / ``hook-dirs``).

    Returns the directory containing this package's PyInstaller hook so that any
    frozen application depending on angr_data automatically bundles its bundled
    data files (the .json definitions and type databases).
    """
    return [os.path.dirname(__file__)]
