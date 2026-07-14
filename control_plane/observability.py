"""Structured request logging and optional OpenTelemetry initialization."""

from __future__ import annotations

import json
import logging
import time
from uuid import uuid4

from fastapi import FastAPI, Request

from .config import Settings


LOGGER = logging.getLogger("warden.request")
UI_SCRIPT_SHA256 = "bZC4NDPZslBt+o6rAaFco0H96z0YMTczxAmWB3b7u6o="


def configure_observability(app: FastAPI, settings: Settings) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )
    if settings.otlp_endpoint:
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
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
        LOGGER.info(json.dumps({
            "event": "http.request", "request_id": request_id,
            "method": request.method, "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }, sort_keys=True))
        return response
