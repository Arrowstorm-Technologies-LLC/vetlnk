# vetlnk static-analysis image — used only by `vetlnk scan -d` when no
# VT_API_KEY is configured. Never executes the analyzed file; only inspects it
# (libmagic type detection, entropy, strings, YARA). vetlnk runs this image
# with --network none, a read-only root filesystem, a non-root user, and a
# hard wall-clock timeout baked into the command itself (see detonate.py) —
# none of that matters if the image still defaults to root, though, so this
# Dockerfile pins a low-privilege user rather than relying solely on the
# `docker run` flags to enforce it.
FROM python:3.12-slim

# `coreutils` (for `timeout`) is already part of python:3.12-slim's base
# layer, but pinned explicitly here so the wall-clock cutoff in detonate.py
# doesn't silently stop working if a future base image drops it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 binutils coreutils \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir python-magic==0.4.27 yara-python==4.5.1

COPY analyze.py /analyze.py
COPY rules /rules

# world-readable regardless of the host's umask at COPY time, since the
# container runs as a non-root, non-owning user below.
RUN chmod -R a+rX /analyze.py /rules

# Fixed, unprivileged, non-login UID/GID — no home directory, no shell.
# `docker run` also passes --user explicitly (belt-and-suspenders in case
# this image is ever rebuilt without this line taking effect).
RUN groupadd --gid 10001 analyzer \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin analyzer
USER 10001:10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

# No ENTRYPOINT/CMD: detonate.py always supplies the full command explicitly
# (wrapped in `timeout ...`) so the wall-clock cutoff can't be bypassed by
# an image that predates it.
