FROM python:3.12-slim
RUN useradd --create-home app
WORKDIR /app
COPY pyproject.toml ./
COPY lantern_gateway ./lantern_gateway
RUN pip install --no-cache-dir .
USER app
ENV LANTERN_DB=/home/app/data/lantern_gateway.db
RUN mkdir -p /home/app/data
EXPOSE 8080
CMD ["uvicorn", "lantern_gateway.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
