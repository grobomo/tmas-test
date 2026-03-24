FROM python:3.12-slim

LABEL org.opencontainers.image.title="tmas-test-app"
LABEL org.opencontainers.image.description="Sample app for TMAS scanning demo"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="grobomo"
LABEL app.component="api"
LABEL app.team="platform"

WORKDIR /app
COPY app/ .
RUN pip install --no-cache-dir flask
EXPOSE 8080
CMD ["python", "main.py"]
