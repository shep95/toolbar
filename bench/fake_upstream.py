"""A minimal, very fast stand-in for an OpenAI-compatible provider.

Used by bench.py so the benchmark measures the proxy, not the provider.
Serves /chat/completions (JSON or SSE) and /models under any path prefix.
"""

import json

REPLY = json.dumps(
    {
        "id": "chatcmpl-bench",
        "object": "chat.completion",
        "created": 0,
        "model": "bench-model",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
    }
).encode()

CHUNKS = [
    b'data: {"id":"c","object":"chat.completion.chunk","created":0,"model":"bench-model","choices":[{"index":0,"delta":{"content":"o"},"finish_reason":null}]}\n\n',
    b'data: {"id":"c","object":"chat.completion.chunk","created":0,"model":"bench-model","choices":[{"index":0,"delta":{"content":"k"},"finish_reason":"stop"}]}\n\n',
    b'data: {"id":"c","object":"chat.completion.chunk","created":0,"model":"bench-model","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}\n\n',
    b"data: [DONE]\n\n",
]


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body"):
            break
    if scope["path"].endswith("/models"):
        payload = b'{"object":"list","data":[{"id":"bench-model","object":"model"}]}'
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": payload})
        return
    if b'"stream": true' in body or b'"stream":true' in body:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/event-stream")]})
        for chunk in CHUNKS:
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b""})
        return
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": REPLY})
