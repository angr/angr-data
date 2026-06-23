# angr-data

This package holds data files for [angr](https://github.com/angr/angr).
Currently it includes function and type prototype definitions.


## Usage

```python
import angr_data

# Absolute path to a bundled data directory or file:
angr_data.get_path("procedures", "definitions", "win32")
angr_data.get_path("rust", "analyses", "type_db", "1.39.0.json")
```

## Versioning

`angr-data` takes the version number of angr during releases.
We only release a new version of angr-data on PyPI when there are changes to data files since the last `angr-data` release.
Each angr release pins a compatible `angr-data` version (`angr-data~=X.Y.Z`).
