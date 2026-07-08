FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest

# coincurve 20.x (required by bip32 4.x) fails to build with scikit-build-core >= 0.10.
# Pre-install a compatible build toolchain so that pip install -r tests/requirements.txt
# succeeds without hitting the cmake.verbose / scikit-build-core incompatibility.
RUN . /opt/venv/bin/activate && \
    pip install 'scikit-build-core<0.10' hatchling cmake cffi pycparser && \
    pip install 'coincurve==20.0.0' --no-build-isolation
