# syntax=docker/dockerfile:1

FROM python:3.13-slim

ARG UID=1000
ARG GID=1000

RUN --mount=type=cache,target=/var/lib/apt/,sharing=locked \
    --mount=type=cache,target=/var/cache/apt/,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    curl

RUN groupadd -g $GID python \
    && useradd -m -s /bin/bash -u $UID -g $GID python

USER python

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python -
ENV PATH=/home/python/.local/bin:$PATH

WORKDIR /app

COPY pyproject.toml poetry.lock README.md /app/
COPY midi/ midi/
COPY okd/ okd/
COPY mtf/ mtf/
COPY sprc/ sprc/
COPY dam_song_tools_cli/ dam_song_tools_cli/

RUN poetry install

ENTRYPOINT [ "poetry", "run", "dam-song-tools" ]
