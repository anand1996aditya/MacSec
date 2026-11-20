# Install guide

## Recommended: isolated environment

```bash
git clone <repository-url> MacSec
cd MacSec
./install.sh
./run.sh
```

The installer:

1. checks that the host is macOS;
2. checks Python 3.10 or newer;
3. creates `.venv` inside the repository;
4. installs the package with `pip`;
5. prints the run command.

It never uses `sudo`.

## Custom virtual environment

```bash
./install.sh --venv "$HOME/.venvs/macsec"
MHC_VENV="$HOME/.venvs/macsec" ./run.sh
```

## User or system install

```bash
python3 -m pip install .
```

If `pip` refuses because the environment is externally managed, use the
isolated install instead. Do not use `sudo pip`.

## Verify

```bash
./verify.sh
```

## Run from a USB stick or temporary checkout

The package is pure Python. On another Mac:

```bash
PYTHONPATH=src python3 -m macsec
```

## Uninstall

```bash
rm -rf .venv
```

For a `pip install .` environment, remove the package with pip in that
environment.
