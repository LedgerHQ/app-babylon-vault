# Pinned by digest: the v1 tag is mutable, so retargeting it would substitute the
# builder image on every future fuzzing run without any change in this repository.
# Digest corresponds to the v1 tag as of 2026-09-01. Keep the version note on its own
# line — a trailing comment on the FROM line makes it a two-argument FROM, which Docker
# rejects ("FROM requires either one or three arguments").
FROM gcr.io/oss-fuzz-base/base-builder@sha256:8b4a73d83374b298a0a771eeec9a1d44ceff3416a678b7d7946303389d022aca

COPY . $SRC/app-babylon-vault
WORKDIR $SRC/app-babylon-vault

COPY .clusterfuzzlite/build.sh $SRC/

# No USER instruction here, and it is a deliberate exception rather than an oversight.
#
# This image is never run by us: ClusterFuzzLite's build_fuzzers action runs it as
#   docker run --privileged ... --volumes-from <action container> \
#              -e OUT=/github/workspace/build-out <this image> ...
# with no --user flag, so the image's USER decides the build identity, while $OUT arrives
# through --volumes-from from the action's own root-owned container. A non-root user
# therefore cannot write $OUT and build.sh fails at `mv ./build/fuzz_* $OUT`
# (--privileged grants capabilities to root, not an ownership bypass). Verified: the build
# itself runs fine as uid 1000 once $SRC is chowned, so the blocker is solely $OUT.
#
# `USER builder` in particular cannot work — the pinned base-builder image has no such
# account (only system users and nobody), so docker run fails immediately with
# "unable to find user builder".
#
# Risk accepted on the grounds that this is an ephemeral CI build container, not a
# deployed runtime: it holds no secrets, is rebuilt from scratch each run, and is not
# reachable from any network. The dev-tools image in ./Dockerfile, which developers do
# run locally, does drop to a non-root user.
