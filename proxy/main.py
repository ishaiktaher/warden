import json
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from proxy.demo_request import infer_authorized_maximum, read_demo_flight_price
from proxy.executor import DodoPaymentError, execute_booking, execute_booking_without_warden_demo
from integrations.hermes import FLIGHT_BOOKING, HermesRoutingError, classify_intent
from audit import record_audit_event
from identity.capability import capability_claims, issue_capability


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UI_PATH = PROJECT_ROOT / "ui" / "index.html"
AUDIT_PATH = PROJECT_ROOT / "audit" / "agent_audit.jsonl"
DEMO_BOOKING_PAGE = PROJECT_ROOT / "mock_site" / "index.html"
DEMO_FLIGHT_RESOURCE = "http://127.0.0.1:8080/"
AUDIT_PUBLIC_FIELDS = frozenset(
    {
        "timestamp", "run_id", "agent", "event", "status", "amount", "max_spend",
        "allowed", "result_count", "trust", "intent", "grant_id", "agent_id",
        "action", "resource", "currency", "reason"
    }
)


class BookingScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["confirm_booking"]
    max_spend: float = Field(ge=0)


class BookingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount: float = Field(gt=0)
    scope: BookingScope
    secret_ref: Literal["dodo_payment_method"] = "dodo_payment_method"
    capability_token: str = Field(min_length=1, max_length=4096)
    resource: Literal["http://127.0.0.1:8080/"] = DEMO_FLIGHT_RESOURCE


class CapabilityIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_spend: float = Field(ge=0)
    agent_id: Literal["booking"] = "booking"
    action: Literal["confirm_booking"] = "confirm_booking"
    currency: Literal["INR"] = "INR"
    resource: Literal["http://127.0.0.1:8080/"] = DEMO_FLIGHT_RESOURCE
    ttl_seconds: int = Field(default=300, ge=1, le=900)


class DemoBookingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instruction: str = Field(min_length=1, max_length=1000)
    gate: Literal["warden", "without_warden"] = "warden"
    confirm_unsafe_test_charge: bool = False

app = FastAPI(title="Warden")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(UI_PATH)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/audit/events")
def audit_events(limit: int = 100) -> dict[str, list[dict]]:
    safe_limit = min(max(limit, 1), 200)
    if not AUDIT_PATH.exists():
        return {"events": []}

    events: list[dict] = []
    for line in AUDIT_PATH.read_text(encoding="utf-8").splitlines()[-safe_limit:]:
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(raw, dict):
            events.append({key: raw[key] for key in AUDIT_PUBLIC_FIELDS if key in raw})
    return {"events": events}


def _issue_and_delegate_capability(max_spend: float, ttl_seconds: int = 300) -> tuple[str, str]:
    token = issue_capability(
        "booking",
        "confirm_booking",
        max_spend,
        "INR",
        DEMO_FLIGHT_RESOURCE,
        ttl_seconds,
    )
    grant_id = str(capability_claims(token)["grant_id"])
    record_audit_event(
        "travel_orchestrator",
        "capability_delegated",
        {
            "status": "success",
            "grant_id": grant_id,
            "agent_id": "booking",
            "action": "confirm_booking",
            "resource": DEMO_FLIGHT_RESOURCE,
        },
    )
    return token, grant_id


@app.post("/capabilities/issue")
async def issue_capability_endpoint(request: CapabilityIssueRequest) -> dict[str, str]:
    try:
        token, grant_id = await run_in_threadpool(
            _issue_and_delegate_capability, request.max_spend, request.ttl_seconds
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return {"capability_token": token, "grant_id": grant_id}


@app.post("/demo/bookings/execute")
async def demo_booking_endpoint(request: DemoBookingRequest) -> dict:
    record_audit_event(
        "travel_orchestrator", "intent_classification_requested", {"status": "started"}
    )
    try:
        intent = await run_in_threadpool(classify_intent, request.instruction)
    except HermesRoutingError as exc:
        record_audit_event(
            "travel_orchestrator", "operation_failed", {"status": "error"}
        )
        raise HTTPException(status_code=503, detail=str(exc)) from None

    public_intent = "flight_booking" if intent == FLIGHT_BOOKING else "other"
    record_audit_event(
        "travel_orchestrator",
        "intent_classification_completed",
        {"status": "success", "intent": public_intent},
    )
    if intent != FLIGHT_BOOKING:
        return {
            "status": "ignored",
            "intent": "other",
            "message": "Hermes classified this as unrelated to flight booking. No booking action was invoked.",
            "audit_events": audit_events(10)["events"],
        }

    try:
        max_spend = infer_authorized_maximum(request.instruction)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    amount = read_demo_flight_price(DEMO_BOOKING_PAGE)

    try:
        if request.gate == "warden":
            capability_token, _ = await run_in_threadpool(
                _issue_and_delegate_capability, max_spend, 300
            )
            result = await run_in_threadpool(
                execute_booking,
                amount,
                {"action": "confirm_booking", "max_spend": max_spend},
                "dodo_payment_method",
                capability_token,
                DEMO_FLIGHT_RESOURCE,
            )
        else:
            if not request.confirm_unsafe_test_charge:
                raise HTTPException(
                    status_code=409,
                    detail="Confirm the intentional Dodo test charge before bypassing Warden",
                )
            result = await run_in_threadpool(
                execute_booking_without_warden_demo, amount, "dodo_payment_method"
            )
    except DodoPaymentError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None

    # The command center never needs payment identifiers.
    return {
        "status": result["status"],
        "reason": result.get("reason"),
        "amount": amount,
        "max_spend": max_spend,
        "gate": request.gate,
        "source": "malicious_demo_page",
        "audit_events": audit_events(10)["events"],
    }


@app.post("/bookings/execute")
async def execute_booking_endpoint(request: BookingRequest) -> dict:
    try:
        return await run_in_threadpool(
            execute_booking,
            request.amount,
            request.scope.model_dump(),
            request.secret_ref,
            request.capability_token,
            request.resource,
        )
    except DodoPaymentError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
