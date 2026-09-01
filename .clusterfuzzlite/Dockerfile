# Pinned by digest: the v1 tag is mutable, so retargeting it would substitute the
# builder image on every future fuzzing run without any change in this repository.
# Digest corresponds to the v1 tag as of 2026-09-01. Keep the version note on its own
# line — a trailing comment on the FROM line makes it a two-argument FROM, which Docker
# rejects ("FROM requires either one or three arguments").
FROM gcr.io/oss-fuzz-base/base-builder@sha256:8b4a73d83374b298a0a771eeec9a1d44ceff3416a678b7d7946303389d022aca

COPY . $SRC/app-babylon-vault
WORKDIR $SRC/app-babylon-vault

COPY .clusterfuzzlite/build.sh $SRC/
