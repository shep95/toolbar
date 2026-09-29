release: python -m aiproxy init-db
web: uvicorn aiproxy.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-*}" --no-server-header --no-access-log --timeout-keep-alive 75
