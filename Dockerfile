# Minimal auditor image for TrueAI Core.
#
# The point of this image is not convenience. It is that an auditor who does not
# trust the wheel on PyPI can rebuild it from source in a known environment and
# compare the bytes with what was published. Every input is therefore pinned:
# the base image by digest, the dependency set by uv.lock, and the build
# timestamp by SOURCE_DATE_EPOCH.
#
#   docker build --build-arg SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) -t trueai-core .
#   docker run --rm trueai-core doctor
#
# See docs/reproducible-builds.md for the full verification procedure.

# python:3.12-slim-bookworm. Pinned by digest so the base cannot be republished
# under the same tag with different contents.
FROM python@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134 AS builder

# A build cannot be reproducible if it embeds the moment it ran. Callers pass the
# commit date; the default is the start of the project's release epoch so an
# unparameterised build is still deterministic rather than merely wrong.
ARG SOURCE_DATE_EPOCH=1735689600
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src

# Dependencies are installed from the lock before the source is copied, so a
# source-only change does not re-resolve anything.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN python -m pip install --no-cache-dir "uv==0.12.5" \
    && python -m uv export --frozen --no-emit-project --no-editable \
        --extra pdf --extra c2pa --extra attestation \
        --format requirements.txt --output-file /tmp/runtime-requirements.txt \
    && python -m uv export --frozen --no-emit-project --no-editable \
        --only-group release \
        --format requirements.txt --output-file /tmp/release-requirements.txt \
    && python -m pip install --no-cache-dir --require-hashes \
        -r /tmp/release-requirements.txt

# The whole source tree, minus what .dockerignore excludes, so the container
# builds from exactly what an offline sdist rebuild would see. Copying a subset
# would silently produce a different source distribution.
COPY . .

# Archive members record file modes, and a copy from a Windows host arrives with
# every file marked executable. Normalising to git's model here makes the built
# artifacts identical no matter which operating system ran `docker build`.
RUN find . -type d -exec chmod 0755 {} + \
    && find . -type f -exec chmod 0644 {} + \
    && chmod 0755 scripts/*.sh

RUN python -m build --no-isolation --outdir /dist \
    && python -m pip install --no-cache-dir --require-hashes \
        --prefix=/runtime -r /tmp/runtime-requirements.txt \
    && python -m pip install --no-cache-dir --no-deps --prefix=/runtime /dist/*.whl \
    && python scripts/record_build_inputs.py --dist /dist

# Copy the dedicated runtime prefix rather than the builder's site-packages. The
# final image therefore carries no uv, build, hatchling, twine, or audit tools.
FROM python@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134 AS runtime

ARG SOURCE_DATE_EPOCH=1735689600
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Detector execution and report ordering must not depend on hash randomization.
    PYTHONHASHSEED=0

COPY --from=builder /runtime/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /runtime/bin/trueai /usr/local/bin/trueai
COPY --from=builder /dist /dist

# Scanning is a read-only activity and the image performs no network access.
RUN useradd --create-home --uid 10001 auditor
USER auditor
WORKDIR /work

ENTRYPOINT ["trueai"]
CMD ["--help"]
