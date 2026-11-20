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
# The image starts as root for its switcher alone (cloud/lantern_cloud/switcher.py). The switcher starts the service as
# an ordinary user of its own (`app`: the number the image's user had until 2026-11-18, so what is on the website's
# disk stays the service's) and stays beside it. As root it only gives each check a user of its own, a number nobody
# else has, hands the check's folders to that user before each step and back after it, starts each step (unpacking,
# the dependency audit, the analysis, the explanations) as that user, and stops it with everything it started;
# nothing the service hands it is run as root, and it starts nothing while the service's user could change what it
# runs as root. When it starts, what is on the service's disk (LANTERN_CLOUD_DATA, where every place below must be)
# and is root's, nobody's or a check's user's becomes the service's. The service closes its own files to every other
# user, and with LANTERN_CLOUD_STEPS_APART=required it starts no check that it cannot keep apart from the others and
# from its own files (cloud/lantern_cloud/apart.py). A step's user passes through /home/app and the disk to the
# folder of its own check, and may list neither (docs/deploy.md). From 2026-11-18 to 2026-11-20 the whole service
# ran as root; before that it ran as `app`, and every check's steps ran as that user.
RUN useradd --uid 1000 --user-group --home-dir /home/app/data --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /home/app/data && chown app:app /home/app/data && chmod 0711 /home/app /home/app/data
WORKDIR /home/app
ENV LANTERN_CLOUD_DATA=/home/app/data \
    LANTERN_CLOUD_SERVICE_USER=app \
    LANTERN_CLOUD_DB=/home/app/data/lantern_cloud.db \
    LANTERN_CLOUD_RESULTS=/home/app/data/results \
    LANTERN_CLOUD_WORK=/home/app/data/work \
    LANTERN_HOME=/home/app/data/lantern \
    LANTERN_CLONE_MAX_MB=500 \
    LANTERN_CLOUD_STEPS_APART=required \
    PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "-I", "-m", "lantern_cloud.switcher", "--", \
     "uvicorn", "lantern_cloud.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
