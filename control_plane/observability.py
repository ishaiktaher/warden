"""Structured request logging and optional OpenTelemetry initialization."""

from __future__ import annotations

import json
import logging
import time
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request

from .config import Settings


LOGGER = logging.getLogger("warden.request")
UI_SCRIPT_SHA256 = "B8Py9Zj3EHgqcJyPm14+KH3esXkXitA10RVqgP7c3Nc="


class _RequestTooLarge(RuntimeError):
    pass


class RequestBodyLimitMiddleware:
    """Reject oversized fixed or streamed HTTP request bodies before parsing."""

    def __init__(self, app: Any, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send)
                return
        received = 0
        response_started = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _RequestTooLarge
            return message

        async def tracked_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _RequestTooLarge:
            if not response_started:
                await self._reject(send)

    @staticmethod
    async def _reject(send: Any) -> None:
        body = (
            b'{"error":{"code":"invalid_request","detail":"Request body exceeds '
            b'the configured limit","retryable":false,"request_id":null}}'
        )
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def configure_observability(app: FastAPI, settings: Settings) -> None:
    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=settings.max_request_bytes)
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )
    if settings.otlp_endpoint:
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            provider = TracerProvider(
                resource=Resource.create({"service.name": "warden-control-plane"})
            )
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
            trace.set_tracer_provider(provider)
        except ImportError as exc:
            raise RuntimeError("OpenTelemetry dependencies are not installed") from exc

    @app.middleware("http")
    async def request_observability(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid4())
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if request.url.path == "/docs":
            script_sources = "'self' 'unsafe-inline' https://cdn.jsdelivr.net"
            style_sources = "'self' 'unsafe-inline' https://cdn.jsdelivr.net"
        else:
            script_sources = f"'self' 'sha256-{UI_SCRIPT_SHA256}'"
            style_sources = "'self' 'unsafe-inline'"
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; script-src {script_sources}; "
            f"style-src {style_sources}; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
            "form-action 'self'"
        )
        LOGGER.info(
            json.dumps(
                {
                    "event": "http.request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                },
                sort_keys=True,
            )
        )
        return response
