# Lantern cloud service. Build from the REPOSITORY ROOT (it installs the engine and this service together):
#   docker build -f cloud/Dockerfile -t lantern-cloud .
#   fly deploy . --config cloud/fly.toml --dockerfile cloud/Dockerfile      (also from the repository root)
# gitleaks, the secrets scanner, at one version, built from its source (Go checks what it downloads against its
# public record). Lantern starts it with settings of its own and never with a project's (lantern/security.py).
FROM golang:1.26 AS gitleaks
RUN GOBIN=/out GOTOOLCHAIN=auto CGO_ENABLED=0 go install -ldflags "-X github.com/zricethezav/gitleaks/v8/version.Version=8.30.1" \
      github.com/zricethezav/gitleaks/v8@v8.30.1 \
 && test "$(/out/gitleaks version)" = "8.30.1"

FROM python:3.12-slim
# git clones the repositories people link; npm reads package-lock.json for the dependency audit (lock files only,
# never `npm install`). Nothing from an analysed repository is ever built or run. Tesseract reads the text in
# screenshots dropped into Ask Lantern (through a pipe; images are never written to disk).
RUN apt-get update \
 && apt-get install -y --no-install-recommends git nodejs npm tesseract-ocr \
 && rm -rf /var/lib/apt/lists/*
COPY --from=gitleaks /out/gitleaks /usr/local/bin/gitleaks
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY lantern ./lantern
COPY cloud ./cloud
# The commit being deployed (the deploy workflow passes it), so each Evidence Report can name the exact Lantern to
# install to check it. Only a full 40-character commit is written; anything else leaves it empty.
ARG LANTERN_COMMIT=""
RUN case "$LANTERN_COMMIT" in \
      [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) \
        [ ${#LANTERN_COMMIT} -eq 40 ] && printf 'COMMIT = "%s"\n' "$LANTERN_COMMIT" >> lantern/_build.py ;; \
    esac; true
RUN pip install --no-cache-dir ".[scan,ocr]" ./cloud && rm -rf /src
# The service runs as root, so that it can run each check's steps (unpacking, the dependency audit, the analysis,
# the explanations) as a user of that check's own, a number nobody else has; the steps never run as root
# (cloud/lantern_cloud/apart.py). When it starts it closes its own files to every other user, and with
# LANTERN_CLOUD_STEPS_APART=required it starts no check that it cannot keep apart from the others and from its own
# files. A step's user passes through /home/app to the folder of its own check, and may not list it (the folders on
# that way must let others pass: docs/deploy.md). Until 2026-11-18 the service ran as a user of its own, and every
# check's steps ran as that user.
RUN mkdir -p /home/app/data && chmod 0711 /home/app
WORKDIR /home/app
ENV LANTERN_CLOUD_DB=/home/app/data/lantern_cloud.db \
    LANTERN_CLOUD_RESULTS=/home/app/data/results \
    LANTERN_CLOUD_WORK=/home/app/data/work \
    LANTERN_HOME=/home/app/data/lantern \
    LANTERN_CLONE_MAX_MB=500 \
    LANTERN_CLOUD_STEPS_APART=required \
    PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["uvicorn", "lantern_cloud.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
