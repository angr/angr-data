# PyInstaller hook for angr_data.
#
# angr_data exposes its data files (JSON function/type prototype definitions and
# Rust type databases) on disk via angr_data.get_path(). PyInstaller's import
# analysis cannot see these files because they are loaded by path rather than
# imported, so we collect them explicitly here.
from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("angr_data")
