# Lantern cloud service. Build from the REPOSITORY ROOT (it installs the engine and this service together):
#   docker build -f cloud/Dockerfile -t lantern-cloud .
#   fly deploy . --config cloud/fly.toml --dockerfile cloud/Dockerfile      (also from the repository root)
FROM python:3.12-slim
# git clones the repositories people link; npm reads package-lock.json for the dependency audit (lock files only,
# never `npm install`). Nothing from an analysed repository is ever built or run.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git nodejs npm \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home app
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY lantern ./lantern
COPY cloud ./cloud
RUN pip install --no-cache-dir ".[scan]" ./cloud && rm -rf /src
WORKDIR /home/app
USER app
ENV LANTERN_CLOUD_DB=/home/app/data/lantern_cloud.db \
    LANTERN_CLOUD_RESULTS=/home/app/data/results \
    LANTERN_HOME=/home/app/data/lantern \
    PYTHONUNBUFFERED=1
RUN mkdir -p /home/app/data
EXPOSE 8080
CMD ["uvicorn", "lantern_cloud.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
