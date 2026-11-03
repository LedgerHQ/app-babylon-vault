FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest

# coincurve 20.x (required by bip32 4.x) fails to build with scikit-build-core >= 0.10.
# Pre-install a compatible build toolchain so that pip install -r tests/requirements.txt
# succeeds without hitting the cmake.verbose / scikit-build-core incompatibility.
RUN . /opt/venv/bin/activate && \
    pip install 'scikit-build-core<0.10' hatchling cmake cffi pycparser && \
    pip install 'coincurve==20.0.0' --no-build-isolation

# Run as a non-root user rather than UID 0.
#
# UID/GID 1000 is deliberate, not arbitrary: this image is used by bind-mounting the
# repository, and the container user must be able to write build/, unit-tests/build/ and
# tests/snapshots-tmp/ in it. 1000 is the first non-system UID on Debian/Ubuntu, so it
# matches the default developer account and GitHub's runner user. `USER nobody`
# (UID 65534) satisfies a "must not be root" check but cannot write to a mount owned by
# the host user, which breaks every build and test invocation.
#
# Override at build time if your host UID differs:
#   docker build --build-arg APP_UID=$(id -u) --build-arg APP_GID=$(id -g) .
ARG APP_UID=1000
ARG APP_GID=1000
RUN groupadd --gid "${APP_GID}" app 2>/dev/null || true; \
    useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home --shell /bin/bash app 2>/dev/null || true; \
    mkdir -p /home/app && chown -R "${APP_UID}:${APP_GID}" /home/app && \
    chown -R "${APP_UID}:${APP_GID}" /opt/venv

ENV HOME=/home/app
USER app
