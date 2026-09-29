FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml ./
COPY aiproxy ./aiproxy
# Post-deploy tooling (smoke test and the stand-in provider it can use).
COPY scripts ./scripts
COPY bench ./bench
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir . && useradd --create-home app
USER app

EXPOSE 8000
# Creates missing tables, then serves.
# --proxy-headers: trust X-Forwarded-For/-Proto from the platform's TLS proxy.
#   On a bare VPS set FORWARDED_ALLOW_IPS to your reverse proxy's address so
#   clients cannot spoof their IP.
# --no-server-header: do not advertise the server software.
# --no-access-log: the app already logs every request as JSON.
# --log-level warning: uvicorn writes to stderr, which platforms show as errors.
ENV FORWARDED_ALLOW_IPS="*"
CMD ["sh", "-c", "python -m aiproxy init-db && exec uvicorn aiproxy.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips=\"$FORWARDED_ALLOW_IPS\" --no-server-header --no-access-log --log-level warning --timeout-keep-alive 75"]
