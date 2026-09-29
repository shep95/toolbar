"""Error type raised anywhere in the request pipeline and rendered by the gateway."""

from __future__ import annotations

from fastapi.responses import JSONResponse

_ERROR_TYPES = {
    400: "invalid_request_error",
    401: "authentication_error",
    402: "insufficient_balance",
    403: "permission_error",
    404: "not_found_error",
    413: "request_too_large",
    429: "rate_limit_error",
    502: "upstream_error",
    503: "service_unavailable",
    504: "upstream_timeout",
}


class GatewayError(Exception):
    def __init__(
        self,
        status_code: int,
        outcome: str,
        message: str,
        *,
        headers: dict[str, str] | None = None,
        detail: str | None = None,
        write_audit_row: bool = True,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.outcome = outcome
        self.message = message
        self.headers = headers or {}
        self.detail = detail
        self.write_audit_row = write_audit_row


def error_response(
    status_code: int, outcome: str, message: str, request_id: str, headers: dict[str, str] | None = None
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": message,
                "type": _ERROR_TYPES.get(status_code, "error"),
                "code": outcome,
                "request_id": request_id,
            }
        },
        headers={"X-Request-Id": request_id, **(headers or {})},
    )
