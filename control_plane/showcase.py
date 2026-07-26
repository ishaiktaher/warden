"""Read-only public surface for documentation and product evaluation.

This application deliberately does not import or instantiate the control plane.
It is safe to run on a public serverless host without database, Redis, OIDC,
signing, secret-custody, or audit-provider credentials.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator


ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
LOGGER = logging.getLogger(__name__)

app = FastAPI(
    title="Warden Public Showcase",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

DESIGN_PARTNER_RECIPIENT = "connect@vouchins.com"


class DesignPartnerSubmission(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=254)
    company: str = Field(min_length=2, max_length=120)
    role: str = Field(min_length=2, max_length=100)
    company_size: str = Field(min_length=1, max_length=40)
    timeline: str = Field(min_length=1, max_length=60)
    use_case: str = Field(min_length=1, max_length=3000)
    website: str = Field(default="", max_length=0)

    @field_validator("name", "email", "company", "role", "company_size", "timeline", "use_case")
    @classmethod
    def clean_text(cls, value: str) -> str:
        cleaned = " ".join(value.split()) if "\n" not in value else value.strip()
        if not cleaned:
            raise ValueError("must not be blank")
        return cleaned

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        local, separator, domain = value.rpartition("@")
        if not separator or not local or "." not in domain or any(char.isspace() for char in value):
            raise ValueError("enter a valid email address")
        return value.lower()


@app.middleware("http")
async def public_security_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    else:
        response.headers["Cache-Control"] = "public, max-age=300"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://www.vouchins.com; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
def showcase() -> FileResponse:
    return FileResponse(ROOT / "ui" / "showcase.html")


@app.get("/design-partner", include_in_schema=False)
def design_partner() -> FileResponse:
    return FileResponse(ROOT / "ui" / "design-partner.html")


@app.get("/design-partner.js", include_in_schema=False)
def design_partner_script() -> FileResponse:
    return FileResponse(ROOT / "ui" / "design-partner.js", media_type="text/javascript")


def _send_design_partner_email(submission: DesignPartnerSubmission) -> None:
    provider = os.getenv("WARDEN_SHOWCASE_EMAIL_PROVIDER", "smtp").strip().lower()
    ses_smtp_host = os.getenv("SES_SMTP_HOST", "").strip()
    username = (
        os.getenv("WARDEN_SHOWCASE_SMTP_USERNAME", "").strip()
        or os.getenv("SES_SMTP_USER", "").strip()
    )
    sender = (
        os.getenv("WARDEN_SHOWCASE_EMAIL_FROM", "").strip()
        or os.getenv("WARDEN_SHOWCASE_SMTP_FROM", "").strip()
        or os.getenv("SES_FROM_EMAIL", "").strip()
        or username
    )
    if not sender:
        raise RuntimeError("Design partner email sender is not configured")

    message = EmailMessage()
    message["Subject"] = f"Design partner application — {submission.company}"
    message["From"] = sender
    message["To"] = DESIGN_PARTNER_RECIPIENT
    message["Reply-To"] = submission.email
    message.set_content(
        "\n".join(
            (
                "New Warden design partner application",
                "",
                f"Name: {submission.name}",
                f"Work email: {submission.email}",
                f"Company: {submission.company}",
                f"Role: {submission.role}",
                f"Company size: {submission.company_size}",
                f"Timeline: {submission.timeline}",
                "",
                "Use case:",
                submission.use_case,
            )
        )
    )

    if provider == "ses":
        region = (
            os.getenv("WARDEN_SHOWCASE_SES_REGION", "").strip()
            or os.getenv("AWS_REGION", "").strip()
            or os.getenv("AWS_DEFAULT_REGION", "").strip()
        )
        if not region:
            raise RuntimeError("AWS SES region is not configured")
        try:
            import boto3

            boto3.client("ses", region_name=region).send_raw_email(
                Source=sender,
                Destinations=[DESIGN_PARTNER_RECIPIENT],
                RawMessage={"Data": message.as_bytes()},
            )
        except Exception as exc:
            raise RuntimeError("AWS SES delivery failed") from exc
        return

    if provider != "smtp":
        raise RuntimeError("Unsupported showcase email provider")

    host = os.getenv("WARDEN_SHOWCASE_SMTP_HOST", "").strip() or ses_smtp_host
    if not host:
        raise RuntimeError("Design partner SMTP delivery is not configured")
    default_port = "587" if ses_smtp_host else "465"
    port = int(os.getenv("WARDEN_SHOWCASE_SMTP_PORT", default_port))
    password = (
        os.getenv("WARDEN_SHOWCASE_SMTP_PASSWORD", "")
        or os.getenv("SES_SMTP_PASS", "")
    )
    security = os.getenv("WARDEN_SHOWCASE_SMTP_SECURITY", "").strip().lower()
    if not security:
        security = "ssl" if port == 465 else "starttls"
    if security not in {"ssl", "starttls", "none"}:
        raise RuntimeError("Unsupported showcase SMTP security mode")

    context = ssl.create_default_context()
    if security == "ssl":
        smtp_client: smtplib.SMTP = smtplib.SMTP_SSL(
            host, port, timeout=10, context=context
        )
    else:
        smtp_client = smtplib.SMTP(host, port, timeout=10)

    with smtp_client as smtp:
        if security == "starttls":
            smtp.starttls(context=context)
        if username:
            smtp.login(username, password)
        smtp.send_message(message)


@app.post("/api/design-partner", include_in_schema=False)
async def submit_design_partner(submission: DesignPartnerSubmission) -> JSONResponse:
    try:
        await asyncio.to_thread(_send_design_partner_email, submission)
    except (OSError, RuntimeError, smtplib.SMTPException, ValueError):
        LOGGER.exception("Unable to deliver design partner application")
        raise HTTPException(
            status_code=503,
            detail="We couldn't send your application right now. Please try again shortly.",
        ) from None
    return JSONResponse(
        {"message": "Thanks — your application has been sent. We'll be in touch soon."},
        headers={"Cache-Control": "no-store"},
    )


@app.get("/console", include_in_schema=False)
@app.get("/console.html", include_in_schema=False)
def console_overview() -> FileResponse:
    return FileResponse(ROOT / "ui" / "console.html")


@app.get("/showcase.js", include_in_schema=False)
def showcase_script() -> FileResponse:
    return FileResponse(ROOT / "ui" / "showcase.js", media_type="text/javascript")


@app.get("/proof")
def proof() -> dict:
    return json.loads((ROOT / "ui" / "proof.json").read_text(encoding="utf-8"))


@app.get("/documentation", include_in_schema=False)
@app.get("/docs.html", include_in_schema=False)
def documentation() -> FileResponse:
    return FileResponse(ROOT / "ui" / "docs.html")


@app.get("/openapi.html", include_in_schema=False)
def openapi_landing() -> FileResponse:
    return FileResponse(ROOT / "ui" / "openapi.html")


@app.get("/health")
@app.get("/live")
@app.get("/ready")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "warden-public-showcase",
        "mode": "read-only",
    }
