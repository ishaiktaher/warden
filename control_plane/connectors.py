"""Connector registry dispatch. Agents never invoke these adapters directly."""

from __future__ import annotations

from datetime import datetime, timezone
import base64
import ipaddress
import json
import re
import socket
from typing import Any, Callable
from urllib.parse import urlparse, urlsplit, urlunsplit
from uuid import uuid4

import requests
from requests.adapters import HTTPAdapter

from .config import Settings
from .database import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ConnectorError(RuntimeError):
    pass


MAX_CONNECTOR_RESPONSE_BYTES = 1_048_576


class _PinnedTLSAdapter(HTTPAdapter):
    """Connect to a resolved IP while verifying TLS for the original hostname."""

    def __init__(self, hostname: str):
        self.hostname = hostname
        super().__init__(max_retries=0)

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any,
    ) -> None:
        pool_kwargs["assert_hostname"] = self.hostname
        pool_kwargs["server_hostname"] = self.hostname
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


class ConnectorDispatcher:
    def __init__(self, database: Database, settings: Settings):
        self.database = database
        self.settings = settings
        self._local: dict[str, Callable[[str, dict[str, Any]], dict[str, Any]]] = {
            "crm.update_case": self._crm_update,
            "crm.read_case": self._crm_read,
            "email.draft": self._email_draft,
            "jira.create_ticket": self._jira_create,
            "github.read": self._github_read,
        }

    def execute(
        self,
        connector: Any,
        resource: str,
        parameters: dict[str, Any],
        downstream_secret: str | dict[str, Any] | None,
    ) -> dict[str, Any]:
        adapter_type = connector["adapter_type"]
        if adapter_type == "local_emulator":
            return self._generic_local(connector, resource, parameters)
        if adapter_type in {"local", "github_readonly"}:
            adapter = self._local.get(connector["action"])
            if not adapter:
                raise ConnectorError("No local adapter is registered for this action")
            return adapter(resource, parameters)
        if adapter_type in {"rest", "mcp_upstream", "a2a_upstream"}:
            return self._rest(connector, resource, parameters, downstream_secret, adapter_type)
        if adapter_type in {"shell_sandbox", "browser_sandbox", "database"}:
            raise ConnectorError(f"{adapter_type} requires an operator-provisioned sandbox")
        raise ConnectorError("Unsupported connector adapter")

    def _crm_update(self, resource: str, parameters: dict[str, Any]) -> dict[str, Any]:
        case_id = resource.rsplit("/", 1)[-1]
        update = str(parameters.get("update", "")).strip()
        status = str(parameters.get("status", "investigating")).strip()
        if not update:
            raise ConnectorError("CRM update text is required")
        existing = self.database.one("SELECT case_id FROM crm_cases WHERE case_id=?", (case_id,))
        if not existing:
            raise ConnectorError("CRM case does not exist")
        self.database.execute(
            "UPDATE crm_cases SET latest_update=?,status=?,updated_at=? WHERE case_id=?",
            (update, status, _now(), case_id),
        )
        return {"case_id": case_id, "status": status, "updated": True}

    def _crm_read(self, resource: str, parameters: dict[str, Any]) -> dict[str, Any]:
        del parameters
        case_id = resource.rsplit("/", 1)[-1]
        row = self.database.one("SELECT * FROM crm_cases WHERE case_id=?", (case_id,))
        if not row:
            raise ConnectorError("CRM case does not exist")
        return dict(row)

    def _email_draft(self, resource: str, parameters: dict[str, Any]) -> dict[str, Any]:
        case_id = resource.rsplit("/", 1)[-1]
        recipient = str(parameters.get("recipient", "")).strip()
        subject = str(parameters.get("subject", "")).strip()
        body = str(parameters.get("body", "")).strip()
        if not recipient or not subject or not body:
            raise ConnectorError("Recipient, subject and body are required")
        draft_id = f"draft-{uuid4()}"
        self.database.execute(
            "INSERT INTO email_drafts VALUES(?,?,?,?,?,?,?)",
            (draft_id, case_id, recipient, subject, body, "draft", _now()),
        )
        return {"draft_id": draft_id, "status": "draft", "sent": False}

    def _jira_create(self, resource: str, parameters: dict[str, Any]) -> dict[str, Any]:
        case_id = resource.rsplit("/", 1)[-1]
        summary = str(parameters.get("summary", "")).strip()
        description = str(parameters.get("description", "")).strip()
        if not summary or not description:
            raise ConnectorError("Jira summary and description are required")
        ticket_id = f"WARDEN-{1000 + len(self.database.all('SELECT ticket_id FROM jira_tickets'))}"
        self.database.execute(
            "INSERT INTO jira_tickets VALUES(?,?,?,?,?,?)",
            (ticket_id, case_id, summary, description, "open", _now()),
        )
        return {"ticket_id": ticket_id, "status": "open"}

    def _github_read(self, resource: str, parameters: dict[str, Any]) -> dict[str, Any]:
        reference = str(parameters.get("reference", "main"))
        review_id = f"review-{uuid4()}"
        result = "Read-only review completed; no production mutation performed."
        self.database.execute(
            "INSERT INTO github_reviews VALUES(?,?,?,?,?)",
            (review_id, resource, reference, result, _now()),
        )
        return {"review_id": review_id, "result": result, "read_only": True}

    def _generic_local(self, connector: Any, resource: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Owner-configurable local adapter requiring no Python implementation."""
        action = connector["action"]
        if action.endswith((".read", ".get")):
            row = self.database.one(
                "SELECT value,updated_at FROM emulator_resources WHERE resource=?",
                (self.database.namespace(resource),),
            )
            if not row:
                raise ConnectorError("Emulated resource does not exist")
            return {"resource": resource, "value": json.loads(row["value"]), "updated_at": row["updated_at"]}
        value = parameters.get("value", parameters)
        now = _now()
        self.database.execute(
            """INSERT INTO emulator_resources VALUES(?,?,?) ON CONFLICT(resource)
            DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at""",
            (self.database.namespace(resource), json.dumps(value, sort_keys=True), now),
        )
        return {"resource": resource, "updated": True, "value": value, "updated_at": now}

    def _rest(
        self,
        connector: Any,
        resource: str,
        parameters: dict[str, Any],
        secret: str | dict[str, Any] | None,
        adapter_type: str,
    ) -> dict[str, Any]:
        endpoint = connector["endpoint"] or ""
        parsed = urlparse(endpoint)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or host not in self.settings.allowed_egress_hosts:
            raise ConnectorError("REST connector host is not on the egress allowlist")
        if parsed.scheme != "https":
            raise ConnectorError("External connectors must use HTTPS")
        if parsed.username or parsed.password or parsed.fragment:
            raise ConnectorError("Connector endpoint contains forbidden URL components")
        if parsed.port not in (None, 443):
            raise ConnectorError("Connector endpoint must use TCP port 443")
        addresses = self._validate_public_host(host)
        headers = {"Content-Type": "application/json"}
        query_auth: dict[str, str] = {}
        try:
            body: Any
            if adapter_type == "mcp_upstream":
                body = {"method": "tools/call", "params": {"name": connector["action"], "arguments": {"resource": resource, **parameters}}}
            elif adapter_type == "a2a_upstream":
                body = {"message_type": "message:send", "action": connector["action"], "resource": resource, "parameters": parameters}
            else:
                body = {"resource": resource, "parameters": parameters}
            method = (connector["http_method"] or "POST").upper()
            credential = secret if isinstance(secret, dict) else ({"value": secret} if secret else None)
            config = json.loads(connector["credential_config"] or "{}")
            if credential:
                self._inject_credential(
                    headers, query_auth, credential,
                    connector["credential_mode"] or "bearer", config,
                )
            if connector["credential_mode"] == "aws_sigv4" and credential:
                signed_url, signed_headers, signed_body = self._signed_aws_request(
                    method, endpoint, body, headers, query_auth, credential, config
                )
                body = self._pinned_json_request(
                    method, signed_url, host, addresses,
                    headers=signed_headers, data=signed_body,
                )
            else:
                body = self._pinned_json_request(
                    method, endpoint, host, addresses, headers=headers,
                    params=query_auth or None, json_body=body,
                )
        except ConnectorError:
            raise
        except (requests.RequestException, ValueError) as exc:
            raise ConnectorError("Downstream REST connector failed") from exc
        return body if isinstance(body, dict) else {"result": body}

    @staticmethod
    def _pinned_json_request(
        method: str, endpoint: str, hostname: str, addresses: tuple[str, ...], *,
        headers: dict[str, str], params: dict[str, str] | None = None,
        json_body: Any = None, data: Any = None,
    ) -> Any:
        if not addresses:
            raise ConnectorError("Connector hostname has no validated addresses")
        parsed = urlsplit(endpoint)
        address = addresses[0]
        pinned_host = f"[{address}]" if ":" in address else address
        pinned_url = urlunsplit(
            (parsed.scheme, pinned_host, parsed.path, parsed.query, parsed.fragment)
        )
        request_headers = dict(headers)
        request_headers["Host"] = hostname
        request_headers["Accept-Encoding"] = "identity"
        session = requests.Session()
        session.trust_env = False
        session.mount("https://", _PinnedTLSAdapter(hostname))
        response: requests.Response | None = None
        try:
            response = session.request(
                method, pinned_url, headers=request_headers, params=params,
                json=json_body, data=data, timeout=15, allow_redirects=False,
                stream=True,
            )
            if 300 <= response.status_code < 400:
                raise ConnectorError("Connector redirects are not permitted")
            response.raise_for_status()
            content_type = response.headers.get("Content-Type", "").lower()
            if "application/json" not in content_type:
                raise ConnectorError("Connector returned a non-JSON response")
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > MAX_CONNECTOR_RESPONSE_BYTES:
                        raise ConnectorError("Connector response exceeds the 1 MiB limit")
                except ValueError as exc:
                    raise ConnectorError("Connector returned an invalid Content-Length") from exc
            chunks: list[bytes] = []
            received = 0
            for chunk in response.iter_content(chunk_size=65_536):
                if not chunk:
                    continue
                received += len(chunk)
                if received > MAX_CONNECTOR_RESPONSE_BYTES:
                    raise ConnectorError("Connector response exceeds the 1 MiB limit")
                chunks.append(chunk)
            return json.loads(b"".join(chunks))
        finally:
            if response is not None:
                response.close()
            session.close()

    @staticmethod
    def _token(credential: dict[str, Any]) -> str:
        token = credential.get("access_token", credential.get("value"))
        if not isinstance(token, str) or not token:
            raise ConnectorError("Credential does not contain an injectable token")
        return token

    def _inject_credential(
        self, headers: dict[str, str], query: dict[str, str],
        credential: dict[str, Any], mode: str, config: dict[str, Any],
    ) -> None:
        if mode == "bearer":
            token = self._token(credential)
            headers["Authorization"] = f"Bearer {token}"
            return
        if mode == "custom_header":
            token = self._token(credential)
            name = self._header_name(config.get("header_name", "X-API-Key"))
            template = str(config.get("template", "{token}"))
            headers[name] = self._render(template, {"token": token})
            return
        if mode == "basic":
            username = credential.get("username")
            password = credential.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                raise ConnectorError("Basic credential requires username and password")
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
            return
        if mode == "multi_header":
            templates = config.get("headers")
            if not isinstance(templates, dict) or not templates:
                raise ConnectorError("Multi-header credential configuration is invalid")
            values = {key: str(value) for key, value in credential.items() if value is not None}
            if any("{token}" in str(template) for template in templates.values()):
                values["token"] = self._token(credential)
            for name, template in templates.items():
                headers[self._header_name(name)] = self._render(str(template), values)
            return
        if mode == "query":
            token = self._token(credential)
            name = str(config.get("parameter_name", "api_key"))
            if not re.fullmatch(r"[A-Za-z0-9_.~-]{1,100}", name):
                raise ConnectorError("Credential query parameter name is invalid")
            query[name] = self._render(str(config.get("template", "{token}")), {"token": token})
            return
        if mode == "aws_sigv4":
            return
        raise ConnectorError("Unsupported credential injection mode")

    @staticmethod
    def _signed_aws_request(
        method: str, endpoint: str, body: dict[str, Any], headers: dict[str, str],
        query: dict[str, str], credential: dict[str, Any], config: dict[str, Any],
    ) -> tuple[str, dict[str, str], Any]:
        try:
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
            from botocore.credentials import Credentials
        except ImportError as exc:
            raise ConnectorError(
                "AWS SigV4 injection requires requirements/providers/aws.txt"
            ) from exc
        access_key = credential.get("access_key")
        secret_key = credential.get("secret_key")
        if not isinstance(access_key, str) or not isinstance(secret_key, str):
            raise ConnectorError("AWS credential requires access_key and secret_key")
        service = config.get("service")
        region = config.get("region")
        if not isinstance(service, str) or not isinstance(region, str):
            raise ConnectorError("AWS SigV4 requires service and region")
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
        request = AWSRequest(
            method=method, url=endpoint, data=payload, params=query,
            headers=headers,
        )
        SigV4Auth(Credentials(
            access_key, secret_key, credential.get("session_token")
        ), service, region).add_auth(request)
        prepared = request.prepare()
        if not prepared.url:
            raise ConnectorError("AWS SigV4 produced an invalid request URL")
        return prepared.url, dict(prepared.headers), prepared.body

    @staticmethod
    def _header_name(value: Any) -> str:
        name = str(value)
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}", name):
            raise ConnectorError("Credential header name is invalid")
        if name.lower() in {"host", "content-length", "transfer-encoding", "connection"}:
            raise ConnectorError("Credential cannot override a transport header")
        return name

    @staticmethod
    def _render(template: str, values: dict[str, str]) -> str:
        if "\r" in template or "\n" in template:
            raise ConnectorError("Credential template contains forbidden characters")
        try:
            result = template.format_map(values)
        except (KeyError, ValueError) as exc:
            raise ConnectorError("Credential template references an unavailable field") from exc
        if "\r" in result or "\n" in result:
            raise ConnectorError("Rendered credential contains forbidden characters")
        return result

    @staticmethod
    def _validate_public_host(host: str) -> tuple[str, ...]:
        """Reject DNS answers that could reach loopback or private infrastructure."""
        try:
            answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ConnectorError("Connector hostname cannot be resolved") from exc
        if not answers:
            raise ConnectorError("Connector hostname has no addresses")
        addresses: list[str] = []
        for answer in answers:
            address = ipaddress.ip_address(answer[4][0])
            if not address.is_global:
                raise ConnectorError("Connector hostname resolves to a non-public address")
            value = str(address)
            if value not in addresses:
                addresses.append(value)
        return tuple(addresses)
