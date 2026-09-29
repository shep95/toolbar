FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml ./
COPY aiproxy ./aiproxy
RUN pip install --no-cache-dir . && useradd --create-home app
USER app

EXPOSE 8000
# Creates missing tables, then serves. --proxy-headers makes the app see the
# client IP and https scheme reported by the platform's TLS-terminating proxy.
CMD ["sh", "-c", "python -m aiproxy init-db && exec uvicorn aiproxy.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
