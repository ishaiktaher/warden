"""Application service composing every control-plane security boundary."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, cast
from uuid import uuid4

from .audit import AuditLedger, redact
from .config import Settings, load_settings
from .connectors import ConnectorDispatcher, ConnectorError
from .credentials import CredentialError, CredentialService
from .crypto import CapabilityError, CapabilityService
from .database import create_database
from .policy import PolicyEngine
from .secrets import SecretsBroker
from .resources import ResourceError, resource_matches
from .rate_limit import RateLimiter


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class ControlPlaneError(RuntimeError):
    pass


class ControlPlane:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        self.database = create_database(self.settings)
        self.audit = AuditLedger(self.database, self.settings)
        self.capabilities = CapabilityService(self.database, self.audit, self.settings)
        self.secrets = SecretsBroker(self.database, self.audit, self.settings)
        self.credentials = CredentialService(
            self.database, self.secrets, self.audit, self.settings
        )
        self.policy = PolicyEngine(self.database)
        self.connectors = ConnectorDispatcher(self.database, self.settings)
        self.rate_limiter = RateLimiter(self.database, self.settings)
        self._ensure_defaults()

    def require_admin(self, supplied: str | None) -> str:
        if not supplied or not hmac.compare_digest(supplied, self.settings.admin_key):
            raise ControlPlaneError("Administrator authentication failed")
        return "control-plane-admin"

    def create_owner(self, owner_id: str, name: str, roles: list[str], actor: str) -> dict[str, Any]:
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        try:
            self.database.execute(
                "INSERT INTO owners VALUES(?,?,?,?,?,?)",
                (owner_id, name, key_hash, _json(sorted(set(roles))), "active", _now()),
            )
        except Exception as exc:
            raise ControlPlaneError("Owner registration failed") from exc
        self.audit.append("owner.registered", actor, payload={"owner_id": owner_id, "roles": roles})
        return {"owner_id": owner_id, "name": name, "roles": roles, "api_key": raw_key}

    def authenticate_owner(self, owner_id: str | None, supplied_key: str | None) -> str:
        if not owner_id or not supplied_key:
            raise ControlPlaneError("Owner authentication failed")
        row = self.database.one("SELECT api_key_hash,status FROM owners WHERE owner_id=?", (owner_id,))
        supplied_hash = hashlib.sha256(supplied_key.encode()).hexdigest()
        if not row or row["status"] != "active" or not hmac.compare_digest(row["api_key_hash"], supplied_hash):
            raise ControlPlaneError("Owner authentication failed")
        return owner_id

    def owner_agents(self, owner_id: str) -> list[dict[str, Any]]:
        rows = self.database.all("SELECT * FROM agents WHERE owner=? ORDER BY agent_id", (owner_id,))
        fields = {"allowed_tools", "allowed_actions", "allowed_data_classifications", "approved_parents", "approved_children"}
        return [self._decode(row, fields) for row in rows]

    # -- Agent registry -------------------------------------------------
    def register_agent(self, manifest: dict[str, Any], actor: str) -> dict[str, Any]:
        required = {
            "agent_id", "name", "owner", "purpose", "model_provider", "agent_version",
            "environment", "risk_tier", "allowed_tools", "allowed_actions",
            "allowed_data_classifications", "max_delegation_depth",
        }
        missing = required - manifest.keys()
        if missing:
            raise ControlPlaneError(f"Agent manifest missing: {', '.join(sorted(missing))}")
        if manifest["environment"] not in {"dev", "test", "prod"}:
            raise ControlPlaneError("Unsupported agent environment")
        if int(manifest["max_delegation_depth"]) < 0:
            raise ControlPlaneError("Delegation depth must be non-negative")
        if self.settings.production:
            tenant = self.database.current_tenant()
            if manifest["owner"] != tenant:
                raise ControlPlaneError("Agent owner must match the authenticated tenant")
            if not manifest["agent_id"].startswith(f"{tenant}--"):
                raise ControlPlaneError("Production agent IDs must be prefixed with '<tenant>--'")
        canonical = _json({key: manifest[key] for key in sorted(manifest) if key != "owner_signature"})
        manifest_hash = hashlib.sha256(canonical.encode()).hexdigest()
        signature = manifest.get("owner_signature")
        now = _now()
        values = (
            manifest["agent_id"], manifest["name"], manifest["owner"], manifest["purpose"],
            manifest["model_provider"], manifest["agent_version"], manifest_hash,
            manifest["environment"], manifest["risk_tier"], _json(manifest["allowed_tools"]),
            _json(manifest["allowed_actions"]), _json(manifest["allowed_data_classifications"]),
            int(manifest["max_delegation_depth"]), _json(manifest.get("approved_parents", [])),
            _json(manifest.get("approved_children", [])), manifest.get("expires_at"),
            manifest.get("review_date"), "pending", None, signature, now, now,
        )
        try:
            self.database.execute(
                "INSERT INTO agents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values
            )
            self.database.execute(
                "INSERT INTO agent_versions VALUES(?,?,?,?,?,?)",
                (manifest["agent_id"], manifest["agent_version"], manifest_hash, canonical, "pending", now),
            )
        except Exception as exc:
            raise ControlPlaneError("Agent registration failed") from exc
        self.audit.append(
            "agent.registered", actor, agent_id=manifest["agent_id"],
            payload={"manifest_hash": manifest_hash, "status": "pending", "owner": manifest["owner"]},
        )
        return self.agent(manifest["agent_id"])

    def update_agent(self, agent_id: str, manifest: dict[str, Any], actor: str) -> dict[str, Any]:
        current = self.database.one("SELECT * FROM agents WHERE agent_id=?", (agent_id,))
        if not current:
            raise ControlPlaneError("Unknown agent")
        if manifest.get("agent_id") != agent_id or manifest.get("owner") != current["owner"]:
            raise ControlPlaneError("Agent identity and owner are immutable")
        canonical = _json({key: manifest[key] for key in sorted(manifest) if key != "owner_signature"})
        manifest_hash = hashlib.sha256(canonical.encode()).hexdigest()
        now = _now()
        try:
            with self.database.connect() as connection:
                connection.execute(
                    """UPDATE agents SET name=?,purpose=?,model_provider=?,agent_version=?,
                    manifest_hash=?,environment=?,risk_tier=?,allowed_tools=?,allowed_actions=?,
                    allowed_data_classifications=?,max_delegation_depth=?,approved_parents=?,
                    approved_children=?,expires_at=?,review_date=?,status='pending',approved_by=NULL,
                    owner_signature=?,updated_at=? WHERE agent_id=?""",
                    (
                        manifest["name"], manifest["purpose"], manifest["model_provider"],
                        manifest["agent_version"], manifest_hash, manifest["environment"],
                        manifest["risk_tier"], _json(manifest["allowed_tools"]),
                        _json(manifest["allowed_actions"]), _json(manifest["allowed_data_classifications"]),
                        int(manifest["max_delegation_depth"]), _json(manifest.get("approved_parents", [])),
                        _json(manifest.get("approved_children", [])), manifest.get("expires_at"),
                        manifest.get("review_date"), manifest.get("owner_signature"), now, agent_id,
                    ),
                )
                connection.execute(
                    "INSERT INTO agent_versions VALUES(?,?,?,?,?,?)",
                    (agent_id, manifest["agent_version"], manifest_hash, canonical, "pending", now),
                )
        except Exception as exc:
            raise ControlPlaneError("Agent version update failed") from exc
        self.audit.append(
            "agent.updated", actor, agent_id=agent_id,
            payload={"agent_version": manifest["agent_version"], "manifest_hash": manifest_hash, "status": "pending"},
        )
        return self.agent(agent_id)

    def approve_agent(self, agent_id: str, actor: str) -> dict[str, Any]:
        if not self.database.one("SELECT agent_id FROM agents WHERE agent_id=?", (agent_id,)):
            raise ControlPlaneError("Unknown agent")
        self.database.execute(
            "UPDATE agents SET status='active',approved_by=?,updated_at=? WHERE agent_id=?",
            (actor, _now(), agent_id),
        )
        self.database.execute(
            "UPDATE agent_versions SET status='approved' WHERE agent_id=? AND agent_version=(SELECT agent_version FROM agents WHERE agent_id=?)",
            (agent_id, agent_id),
        )
        self.audit.append("agent.approved", actor, agent_id=agent_id, decision="allow")
        return self.agent(agent_id)

    def set_agent_status(self, agent_id: str, status: str, actor: str) -> dict[str, Any]:
        if status not in {"pending", "active", "suspended", "retired"}:
            raise ControlPlaneError("Invalid agent lifecycle status")
        self.database.execute(
            "UPDATE agents SET status=?,updated_at=? WHERE agent_id=?", (status, _now(), agent_id)
        )
        self.audit.append(f"agent.{status}", actor, agent_id=agent_id, payload={"status": status})
        return self.agent(agent_id)

    def agent(self, agent_id: str) -> dict[str, Any]:
        row = self.database.one("SELECT * FROM agents WHERE agent_id=?", (agent_id,))
        if not row:
            raise ControlPlaneError("Unknown agent")
        return self._decode(row, {
            "allowed_tools", "allowed_actions", "allowed_data_classifications",
            "approved_parents", "approved_children",
        })

    def list_agents(self) -> list[dict[str, Any]]:
        return [self._decode(row, {"allowed_tools", "allowed_actions", "allowed_data_classifications", "approved_parents", "approved_children"}) for row in self.database.all("SELECT * FROM agents ORDER BY agent_id")]

    # -- Runtime identity ------------------------------------------------
    def create_run(
        self, principal_id: str, agent_id: str, task: str, environment: str,
        parent_run_id: str | None = None,
    ) -> dict[str, Any]:
        agent = self.database.one("SELECT * FROM agents WHERE agent_id=?", (agent_id,))
        if not agent or agent["status"] != "active":
            raise ControlPlaneError("Run requires an active registered agent")
        if agent["expires_at"] and datetime.fromisoformat(agent["expires_at"]) <= datetime.now(timezone.utc):
            raise ControlPlaneError("Agent registration expired")
        if environment != agent["environment"]:
            raise ControlPlaneError("Run environment must match agent environment")
        if parent_run_id and not self.database.one("SELECT run_id FROM runs WHERE run_id=? AND status='active'", (parent_run_id,)):
            raise ControlPlaneError("Parent run is unavailable")
        run_id = str(uuid4())
        runtime_secret = secrets.token_urlsafe(32)
        runtime_secret_hash = hashlib.sha256(runtime_secret.encode()).hexdigest()
        self.database.execute(
            """INSERT INTO runs(
            run_id,principal_id,runtime_secret_hash,agent_id,task,parent_run_id,
            environment,status,created_at,ended_at,revoked_at
            ) VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL)""",
            (run_id, principal_id, runtime_secret_hash, agent_id, task, parent_run_id, environment, "active", _now()),
        )
        self.audit.append(
            "run.created", "runtime-registry", principal_id=principal_id,
            agent_id=agent_id, run_id=run_id, payload={"task": task, "parent_run_id": parent_run_id},
        )
        public_run = dict(self.database.one("SELECT * FROM runs WHERE run_id=?", (run_id,)))
        public_run.pop("runtime_secret_hash", None)
        public_run["runtime_proof"] = runtime_secret
        return public_run

    def create_task(self, run_id: str, description: str, parent_task_id: str | None = None) -> dict[str, Any]:
        run = self.database.one("SELECT * FROM runs WHERE run_id=? AND status='active'", (run_id,))
        if not run:
            raise ControlPlaneError("Task requires an active run")
        task_id = str(uuid4())
        self.database.execute(
            "INSERT INTO tasks VALUES(?,?,?,?,?,?,NULL)",
            (task_id, run_id, parent_task_id, description, "active", _now()),
        )
        self.audit.append(
            "task.created", "runtime-registry", principal_id=run["principal_id"],
            agent_id=run["agent_id"], run_id=run_id, task_id=task_id,
            payload={"description": description, "parent_task_id": parent_task_id},
        )
        return dict(self.database.one("SELECT * FROM tasks WHERE task_id=?", (task_id,)))

    def revoke_run(self, run_id: str, actor: str, reason: str) -> None:
        now = _now()
        with self.database.connect() as connection:
            descendants = [row["run_id"] for row in connection.execute(
                """WITH RECURSIVE tree(run_id) AS (
                SELECT run_id FROM runs WHERE run_id=?
                UNION ALL SELECT runs.run_id FROM runs JOIN tree ON runs.parent_run_id=tree.run_id
                ) SELECT run_id FROM tree""",
                (run_id,),
            )]
            for descendant in descendants:
                connection.execute("UPDATE runs SET status='revoked',revoked_at=? WHERE run_id=?", (now, descendant))
                connection.execute("UPDATE tokens SET status='revoked',revoked_at=? WHERE run_id=?", (now, descendant))
        self._revocation("run", run_id, actor, reason)

    # -- Capabilities and delegation ------------------------------------
    def issue_capability(
        self, *, run_id: str, scopes: list[str], resources: list[str], ttl_seconds: int,
        actor: str = "token-service",
    ) -> tuple[str, dict[str, Any]]:
        run = self.database.one("SELECT * FROM runs WHERE run_id=?", (run_id,))
        if not run or run["status"] != "active":
            raise ControlPlaneError("Capability requires an active run")
        agent = self.database.one("SELECT * FROM agents WHERE agent_id=?", (run["agent_id"],))
        allowed_actions = set(json.loads(agent["allowed_actions"]))
        if not set(scopes).issubset(allowed_actions):
            raise ControlPlaneError("Requested scopes exceed the agent manifest")
        return self.capabilities.issue(
            agent_id=run["agent_id"], run_id=run_id, principal_id=run["principal_id"],
            scopes=scopes, resources=resources, ttl_seconds=ttl_seconds, actor=actor,
        )

    def delegate_capability(
        self, *, parent_token: str, parent_runtime_proof: str, child_run_id: str, scopes: list[str],
        resources: list[str], ttl_seconds: int,
    ) -> tuple[str, dict[str, Any]]:
        parent = self.capabilities.verify(parent_token)
        self._verify_runtime_proof(parent["run_id"], parent_runtime_proof)
        parent_agent = self.agent(parent["agent_id"])
        child_run = self.database.one("SELECT * FROM runs WHERE run_id=?", (child_run_id,))
        if not child_run or child_run["status"] != "active":
            raise ControlPlaneError("Child run is unavailable")
        child_agent = self.agent(child_run["agent_id"])
        if child_agent["agent_id"] not in parent_agent["approved_children"]:
            raise ControlPlaneError("Child relationship is not approved by parent")
        if parent_agent["agent_id"] not in child_agent["approved_parents"]:
            raise ControlPlaneError("Parent relationship is not approved by child")
        depth = int(parent["delegation_depth"]) + 1
        if depth > int(parent_agent["max_delegation_depth"]):
            raise ControlPlaneError("Maximum delegation depth exceeded")
        if child_run["principal_id"] != parent["principal_id"] or child_run["parent_run_id"] != parent["run_id"]:
            raise ControlPlaneError("Child run is not bound to the parent principal and run")
        if not set(scopes).issubset(set(parent["scopes"])):
            raise ControlPlaneError("Child scopes must be narrower than parent scopes")
        if not set(scopes).issubset(set(child_agent["allowed_actions"])):
            raise ControlPlaneError("Child scopes exceed the child manifest")
        try:
            narrower = all(
                any(resource_matches(resource, pattern) for pattern in parent["resources"])
                for resource in resources
            )
        except ResourceError as exc:
            raise ControlPlaneError(str(exc)) from exc
        if not narrower:
            raise ControlPlaneError("Child resources must be narrower than parent resources")
        remaining = max(1, int(parent["exp"]) - int(time.time()))
        token, claims = self.capabilities.issue(
            agent_id=child_agent["agent_id"], run_id=child_run_id,
            principal_id=parent["principal_id"], scopes=scopes, resources=resources,
            ttl_seconds=min(ttl_seconds, remaining), delegation_depth=depth,
            parent_jti=parent["jti"], actor=parent_agent["agent_id"],
        )
        self.database.execute(
            "INSERT INTO delegations VALUES(?,?,?,?,?,?)",
            (str(uuid4()), parent["jti"], claims["jti"], parent_agent["agent_id"], child_agent["agent_id"], _now()),
        )
        return token, claims

    # -- Connector and policy registry ----------------------------------
    def register_connector(self, connector: dict[str, Any], actor: str) -> dict[str, Any]:
        required = {"connector_id", "tool", "action", "adapter_type", "resource_patterns", "required_scopes", "owner", "risk_tier"}
        missing = required - connector.keys()
        if missing:
            raise ControlPlaneError(f"Connector missing: {', '.join(sorted(missing))}")
        if self.settings.production:
            tenant = self.database.current_tenant()
            if connector["owner"] != tenant:
                raise ControlPlaneError("Connector owner must match the authenticated tenant")
            if not connector["connector_id"].startswith(f"{tenant}--"):
                raise ControlPlaneError("Production connector IDs must be prefixed with '<tenant>--'")
        now = _now()
        self.database.execute(
            """INSERT INTO connectors(
            connector_id,tool,action,adapter_type,endpoint,http_method,resource_patterns,
            required_scopes,secret_alias,status,owner,risk_tier,rate_limit_per_minute,
            credential_mode,credential_config,grant_required,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(connector_id) DO UPDATE SET tool=excluded.tool,action=excluded.action,
            adapter_type=excluded.adapter_type,endpoint=excluded.endpoint,http_method=excluded.http_method,
            resource_patterns=excluded.resource_patterns,required_scopes=excluded.required_scopes,
            secret_alias=excluded.secret_alias,status=excluded.status,owner=excluded.owner,
            risk_tier=excluded.risk_tier,rate_limit_per_minute=excluded.rate_limit_per_minute,
            credential_mode=excluded.credential_mode,
            credential_config=excluded.credential_config,
            grant_required=excluded.grant_required,
            updated_at=excluded.updated_at""",
            (
                connector["connector_id"], connector["tool"], connector["action"], connector["adapter_type"],
                connector.get("endpoint"), connector.get("http_method"), _json(connector["resource_patterns"]),
                _json(connector["required_scopes"]), connector.get("secret_alias"), connector.get("status", "active"),
                connector["owner"], connector["risk_tier"], int(connector.get("rate_limit_per_minute", 30)),
                connector.get("credential_mode", "bearer"),
                _json(connector.get("credential_config", {})),
                int(bool(connector.get("grant_required", False))), now, now,
            ),
        )
        self.audit.append("connector.registered", actor, payload={"connector_id": connector["connector_id"], "action": connector["action"], "status": connector.get("status", "active")})
        return self.connector(connector["connector_id"])

    def connector(self, connector_id: str) -> dict[str, Any]:
        row = self.database.one("SELECT * FROM connectors WHERE connector_id=?", (connector_id,))
        if not row:
            raise ControlPlaneError("Unknown connector")
        return self._decode(row, {"resource_patterns", "required_scopes"})

    def list_connectors(self) -> list[dict[str, Any]]:
        return [self._decode(row, {"resource_patterns", "required_scopes"}) for row in self.database.all("SELECT * FROM connectors ORDER BY connector_id")]

    def set_connector_status(self, connector_id: str, status: str, actor: str) -> dict[str, Any]:
        if status not in {"active", "suspended", "retired"}:
            raise ControlPlaneError("Invalid connector status")
        self.database.execute("UPDATE connectors SET status=?,updated_at=? WHERE connector_id=?", (status, _now(), connector_id))
        self.audit.append(f"connector.{status}", actor, payload={"connector_id": connector_id})
        return self.connector(connector_id)

    def seed_policy(
        self, rules: dict[str, Any], actor: str, policy_id: str = "default",
        layer: str = "platform", target_id: str = "*",
    ) -> dict[str, Any]:
        if layer not in {"platform", "tenant", "agent", "connector", "grant"}:
            raise ControlPlaneError("Invalid policy layer")
        if layer != "platform" and not target_id:
            raise ControlPlaneError("Layered policies require a target")
        external_policy_id = policy_id
        policy_id = self.database.namespace(policy_id)
        version_row = self.database.one("SELECT MAX(version) AS version FROM policy_bundles WHERE policy_id=?", (policy_id,))
        version = int(version_row["version"] or 0) + 1
        now = _now()
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE policy_bundles SET status='retired' WHERE policy_id=? AND status='active'",
                (policy_id,),
            )
            connection.execute(
                """INSERT INTO policy_bundles(
                policy_id,version,name,layer,target_id,rules,status,owner,created_at,activated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (policy_id, version, "Agent control policy", layer, target_id,
                 _json(rules), "active", actor, now, now),
            )
        self.audit.append("policy.activated", actor, payload={
            "policy_id": policy_id, "version": version, "layer": layer,
            "target_id": target_id,
        })
        return {"policy_id": external_policy_id, "version": version, "status": "active",
                "layer": layer, "target_id": target_id, "rules": rules}

    def list_policies(self) -> list[dict[str, Any]]:
        return [
            self._decode(row, {"rules"})
            for row in self.database.all(
                """SELECT policy_id,version,name,layer,target_id,rules,status,owner,
                created_at,activated_at FROM policy_bundles
                ORDER BY created_at DESC,version DESC"""
            )
        ]

    # -- Approvals -------------------------------------------------------
    def resolve_approval(self, approval_id: str, approved: bool, actor: str, reason: str = "") -> dict[str, Any]:
        row = self.database.one("SELECT * FROM approvals WHERE approval_id=?", (approval_id,))
        if not row or row["status"] != "pending":
            raise ControlPlaneError("Approval is unavailable")
        status = "approved" if approved else "denied"
        self.database.execute(
            "UPDATE approvals SET status=?,resolved_by=?,resolved_at=?,reason=? WHERE approval_id=?",
            (status, actor, _now(), reason, approval_id),
        )
        self.audit.append(
            "approval.resolved", actor, principal_id=row["requested_by"], agent_id=row["agent_id"],
            run_id=row["run_id"], task_id=row["task_id"], decision="allow" if approved else "deny",
            payload={"approval_id": approval_id, "status": status, "action": row["action"], "resource": row["resource"]},
        )
        return dict(self.database.one("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)))

    def approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        rows = self.database.all("SELECT * FROM approvals WHERE status=? ORDER BY requested_at", (status,)) if status else self.database.all("SELECT * FROM approvals ORDER BY requested_at")
        return [dict(row) for row in rows]

    # -- Mandatory action gateway --------------------------------------
    def execute_action(
        self, *, token: str, task_id: str, connector_id: str, action: str,
        resource: str, parameters: dict[str, Any], data_classification: str,
        environment: str, approval_id: str | None = None,
        grant_id: str | None = None,
        risk_signals: dict[str, Any] | None = None, request_nonce: str,
        runtime_proof: str,
    ) -> dict[str, Any]:
        tool_call_id = str(uuid4())
        claims: dict[str, Any] | None = None
        execution_claimed = False

        def finish(response: dict[str, Any]) -> dict[str, Any]:
            if execution_claimed and claims:
                self._complete_execution(claims["jti"], request_nonce, response)
            return response

        try:
            if self.kill_switch_enabled():
                raise ControlPlaneError("Global action kill switch is enabled")
            claims = self.capabilities.verify(token, expected_action=action, expected_resource=resource)
            self._verify_runtime_proof(claims["run_id"], runtime_proof)
            request_hash = hashlib.sha256(_json({
                "task_id": task_id, "connector_id": connector_id, "action": action,
                "resource": resource, "parameters": parameters,
                "data_classification": data_classification, "environment": environment,
                "approval_id": approval_id, "grant_id": grant_id,
                "risk_signals": risk_signals or {},
            }).encode()).hexdigest()
            run = self.database.one("SELECT * FROM runs WHERE run_id=?", (claims["run_id"],))
            agent = self.database.one("SELECT * FROM agents WHERE agent_id=?", (claims["agent_id"],))
            task = self.database.one("SELECT * FROM tasks WHERE task_id=? AND run_id=?", (task_id, claims["run_id"]))
            connector = self.database.one("SELECT * FROM connectors WHERE connector_id=?", (connector_id,))
            if not task or task["status"] != "active":
                raise ControlPlaneError("Task identity is unavailable")
            if not connector or connector["action"] != action:
                raise ControlPlaneError("Connector does not implement the requested action")
            self._enforce_rate_limit(connector, claims["jti"])
            previous = self._claim_execution(claims["jti"], request_nonce, request_hash)
            if previous is not None:
                return previous
            execution_claimed = True
            grant = None
            if grant_id:
                grant = self.credentials.authorize_grant(
                    grant_id,
                    principal_id=claims["principal_id"],
                    agent_id=claims["agent_id"],
                    action=action,
                    method=connector["http_method"] or "POST",
                    endpoint=connector["endpoint"] or resource,
                )
            self.database.execute(
                "INSERT INTO tool_calls VALUES(?,?,?,?,?,?,?,?,NULL)",
                (tool_call_id, claims["run_id"], task_id, connector_id, action, resource, "requested", _now()),
            )
            self.audit.append(
                "action.requested", claims["agent_id"], principal_id=claims["principal_id"],
                agent_id=claims["agent_id"], run_id=claims["run_id"], task_id=task_id,
                tool_call_id=tool_call_id, payload={
                    "connector_id": connector_id, "action": action,
                    "resource": resource, "data_classification": data_classification,
                    "grant_id": grant_id,
                },
            )
            decision = self.policy.decide(
                agent=agent, run=run, connector=connector, claims=claims, action=action,
                resource=resource, data_classification=data_classification, environment=environment,
                approval_id=approval_id, risk_signals=risk_signals or {}, grant=grant,
            )
            self.audit.append(
                "policy.allowed" if decision.allowed else "policy.denied", "policy-service",
                principal_id=claims["principal_id"], agent_id=claims["agent_id"],
                run_id=claims["run_id"], task_id=task_id, tool_call_id=tool_call_id,
                decision="allow" if decision.allowed else "deny",
                payload={
                    "reason": decision.reason, "action": action, "resource": resource,
                    "grant_id": grant_id, "policy_layers": list(decision.layers),
                },
            )
            if not decision.allowed:
                self.database.execute("UPDATE tool_calls SET status='denied',completed_at=? WHERE tool_call_id=?", (_now(), tool_call_id))
                if decision.approval_required:
                    pending = self._request_approval(claims, task_id, action, resource)
                    return finish({"status": "approval_required", "reason": decision.reason, "approval_id": pending["approval_id"], "tool_call_id": tool_call_id})
                return finish({"status": "denied", "reason": decision.reason, "tool_call_id": tool_call_id})

            if approval_id:
                self._claim_approval(approval_id, claims, task_id, action, resource)

            downstream_secret: str | dict[str, Any] | None = None
            if grant:
                downstream_secret = self.credentials.resolve_credential(
                    grant, run_id=claims["run_id"], task_id=task_id,
                    tool_call_id=tool_call_id, connector_id=connector_id,
                )
            elif connector["secret_alias"]:
                downstream_secret = self.secrets.resolve_for_connector(
                    connector["secret_alias"], connector_id=connector_id, run_id=claims["run_id"],
                    task_id=task_id, tool_call_id=tool_call_id,
                )
            self.audit.append(
                "connector.invoked", "action-gateway", principal_id=claims["principal_id"],
                agent_id=claims["agent_id"], run_id=claims["run_id"], task_id=task_id,
                tool_call_id=tool_call_id, payload={"connector_id": connector_id, "action": action, "resource": resource},
            )
            result = self.connectors.execute(connector, resource, parameters, downstream_secret)
            self.database.execute("UPDATE tool_calls SET status='executed',completed_at=? WHERE tool_call_id=?", (_now(), tool_call_id))
            if approval_id:
                self.database.execute(
                    "UPDATE approvals SET status='consumed' WHERE approval_id=? AND status='executing'",
                    (approval_id,),
                )
                self.audit.append(
                    "approval.consumed", "action-gateway", principal_id=claims["principal_id"],
                    agent_id=claims["agent_id"], run_id=claims["run_id"], task_id=task_id,
                    tool_call_id=tool_call_id, payload={"approval_id": approval_id, "action": action, "resource": resource},
                )
            self.audit.append(
                "action.executed", "action-gateway", principal_id=claims["principal_id"],
                agent_id=claims["agent_id"], run_id=claims["run_id"], task_id=task_id,
                tool_call_id=tool_call_id, decision="allow",
                payload={"connector_id": connector_id, "action": action, "resource": resource, "status": "success"},
            )
            return finish({"status": "executed", "result": redact(result), "tool_call_id": tool_call_id})
        except (CapabilityError, ControlPlaneError, CredentialError, ConnectorError) as exc:
            if approval_id and claims and isinstance(exc, ConnectorError):
                self.database.execute(
                    "UPDATE approvals SET status='uncertain',reason=? WHERE approval_id=? AND status='executing'",
                    ("Downstream result is uncertain; operator reconciliation required", approval_id),
                )
            self.audit.append(
                "action.denied" if not isinstance(exc, ConnectorError) else "action.failed",
                "action-gateway", principal_id=claims.get("principal_id") if claims else None,
                agent_id=claims.get("agent_id") if claims else None,
                run_id=claims.get("run_id") if claims else None, task_id=task_id,
                tool_call_id=tool_call_id, decision="deny",
                payload={"reason": str(exc), "connector_id": connector_id, "action": action, "resource": resource},
            )
            return finish({"status": "denied" if not isinstance(exc, ConnectorError) else "error", "reason": str(exc), "tool_call_id": tool_call_id})

    # -- Revocation, kill switches and demo bootstrap -------------------
    def revoke_token(self, jti: str, actor: str, reason: str) -> None:
        self.capabilities.revoke(jti, actor, reason)
        self._revocation("token", jti, actor, reason)

    def revoke_policy(self, policy_id: str, actor: str, reason: str) -> None:
        policy_id = self.database.namespace(policy_id)
        self.database.execute("UPDATE policy_bundles SET status='revoked' WHERE policy_id=?", (policy_id,))
        self._revocation("policy", policy_id, actor, reason)

    def set_kill_switch(self, enabled: bool, actor: str) -> None:
        key = self.database.namespace("global_kill_switch")
        self.database.execute(
            "INSERT INTO settings VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            (key, "true" if enabled else "false", _now()),
        )
        self.audit.append("kill_switch.changed", actor, payload={"enabled": enabled})

    def kill_switch_enabled(self) -> bool:
        row = self.database.one(
            "SELECT value FROM settings WHERE key=?",
            (self.database.namespace("global_kill_switch"),),
        )
        return bool(row and row["value"] == "true")

    def reconcile_stale_operations(
        self, actor: str, stale_after_seconds: int = 300,
    ) -> dict[str, Any]:
        """Fail closed when a worker disappears after claiming an operation."""
        cutoff = (datetime.now(timezone.utc) - timedelta(
            seconds=stale_after_seconds
        )).isoformat()
        executions = self.database.all(
            """SELECT token_jti,idempotency_key FROM execution_requests
            WHERE status='processing' AND updated_at<? LIMIT 1000""", (cutoff,),
        )
        approvals = self.database.all(
            """SELECT approval_id FROM approvals WHERE status='executing'
            AND COALESCE(resolved_at,requested_at)<? LIMIT 1000""", (cutoff,),
        )
        uncertain = _json({
            "status": "uncertain",
            "reason": "Worker stopped after claiming execution; operator review required",
        })
        now = _now()
        for row in executions:
            self.database.execute(
                """UPDATE execution_requests SET status='uncertain',response_json=?,updated_at=?
                WHERE token_jti=? AND idempotency_key=? AND status='processing'""",
                (uncertain, now, row["token_jti"], row["idempotency_key"]),
            )
        for row in approvals:
            self.database.execute(
                """UPDATE approvals SET status='uncertain',reason=?
                WHERE approval_id=? AND status='executing'""",
                ("Execution outcome requires operator reconciliation", row["approval_id"]),
            )
        result = {
            "status": "completed", "stale_after_seconds": stale_after_seconds,
            "executions_marked_uncertain": len(executions),
            "approvals_marked_uncertain": len(approvals),
        }
        self.audit.append("maintenance.reconciled", actor, payload=result)
        return result

    def bootstrap_support_demo(self, actor: str = "control-plane-admin") -> dict[str, Any]:
        if self.settings.production:
            raise ControlPlaneError("Reference demo bootstrap is disabled in production")
        agents = [
            {
                "agent_id": "support-triage", "name": "Support Triage Agent", "owner": "cx-security",
                "purpose": "Triage enterprise support cases", "model_provider": "local-demo",
                "agent_version": "1.0.0", "environment": "prod", "risk_tier": "high",
                "allowed_tools": ["crm", "email", "jira"],
                "allowed_actions": ["crm.read_case", "crm.update_case", "email.draft", "jira.create_ticket", "github.read"],
                "allowed_data_classifications": ["internal", "sensitive"], "max_delegation_depth": 1,
                "approved_parents": [], "approved_children": ["code-reviewer"],
                "review_date": (datetime.now(timezone.utc) + timedelta(days=90)).date().isoformat(),
            },
            {
                "agent_id": "code-reviewer", "name": "Code Reviewer Agent", "owner": "engineering-security",
                "purpose": "Perform read-only technical review", "model_provider": "local-demo",
                "agent_version": "1.0.0", "environment": "prod", "risk_tier": "medium",
                "allowed_tools": ["github"], "allowed_actions": ["github.read"],
                "allowed_data_classifications": ["internal"], "max_delegation_depth": 0,
                "approved_parents": ["support-triage"], "approved_children": [],
                "review_date": (datetime.now(timezone.utc) + timedelta(days=90)).date().isoformat(),
            },
        ]
        for manifest in agents:
            if not self.database.one("SELECT agent_id FROM agents WHERE agent_id=?", (manifest["agent_id"],)):
                self.register_agent(manifest, actor)
                self.approve_agent(cast(str, manifest["agent_id"]), actor)
        connectors = [
            {"connector_id": "crm-case-read", "tool": "crm", "action": "crm.read_case", "adapter_type": "local", "resource_patterns": ["crm://case/*"], "required_scopes": ["crm.read_case"], "owner": "cx-platform", "risk_tier": "low"},
            {"connector_id": "crm-case-update", "tool": "crm", "action": "crm.update_case", "adapter_type": "local", "resource_patterns": ["crm://case/*"], "required_scopes": ["crm.update_case"], "owner": "cx-platform", "risk_tier": "high"},
            {"connector_id": "email-draft", "tool": "email", "action": "email.draft", "adapter_type": "local", "resource_patterns": ["email://case/*"], "required_scopes": ["email.draft"], "owner": "communications", "risk_tier": "medium"},
            {"connector_id": "jira-create", "tool": "jira", "action": "jira.create_ticket", "adapter_type": "local", "resource_patterns": ["jira://case/*"], "required_scopes": ["jira.create_ticket"], "owner": "engineering", "risk_tier": "high"},
            {"connector_id": "github-read", "tool": "github", "action": "github.read", "adapter_type": "github_readonly", "resource_patterns": ["github://repo/*"], "required_scopes": ["github.read"], "owner": "engineering", "risk_tier": "low"},
        ]
        for connector in connectors:
            self.register_connector(connector, actor)
        if not self.database.one("SELECT policy_id FROM policy_bundles WHERE status='active'"):
            self.seed_policy({}, actor)
        if not self.database.one("SELECT case_id FROM crm_cases WHERE case_id='CASE-1042'"):
            self.database.execute(
                "INSERT INTO crm_cases VALUES(?,?,?,?,?,?,?)",
                ("CASE-1042", "Acme Enterprise", "Enterprise account is broken", "new", "urgent", "Customer requested an immediate update.", _now()),
            )
        return {"agents": [agent["agent_id"] for agent in agents], "connectors": [item["connector_id"] for item in connectors], "case_id": "CASE-1042"}

    def run_support_ticket_scenario(self, principal_id: str, admin_actor: str) -> dict[str, Any]:
        self.bootstrap_support_demo(admin_actor)
        parent_run = self.create_run(principal_id, "support-triage", "Handle urgent support ticket CASE-1042", "prod")
        parent_task = self.create_task(parent_run["run_id"], "Triage, update and coordinate CASE-1042")
        parent_token, parent_claims = self.issue_capability(
            run_id=parent_run["run_id"],
            scopes=["crm.read_case", "crm.update_case", "email.draft", "jira.create_ticket", "github.read"],
            resources=["crm://case/CASE-1042", "email://case/CASE-1042", "jira://case/CASE-1042", "github://repo/acme/support"],
            ttl_seconds=900,
        )
        outcomes: list[dict[str, Any]] = []
        crm_request = dict(
            token=parent_token, task_id=parent_task["task_id"], connector_id="crm-case-update",
            runtime_proof=parent_run["runtime_proof"],
            action="crm.update_case", resource="crm://case/CASE-1042",
            parameters={"update": "Engineering investigation started; customer update pending.", "status": "investigating"},
            data_classification="sensitive", environment="prod", risk_signals={"anomaly_score": 0.1},
            request_nonce=str(uuid4()),
        )
        # Sensitive scope is intentionally added only to the exact retry token.
        sensitive_token, _ = self.capabilities.issue(
            agent_id="support-triage", run_id=parent_run["run_id"], principal_id=principal_id,
            scopes=parent_claims["scopes"] + ["data:sensitive"], resources=parent_claims["resources"],
            ttl_seconds=900, actor="token-service",
        )
        crm_request["token"] = sensitive_token
        pending = self.execute_action(**crm_request)
        outcomes.append({"step": "crm_update_requires_approval", **pending})
        approval = self.resolve_approval(pending["approval_id"], True, admin_actor, "Urgent customer-impacting incident")
        outcomes.append({"step": "crm_approval", "status": approval["status"], "approval_id": approval["approval_id"]})
        crm_request["request_nonce"] = str(uuid4())
        executed = self.execute_action(**crm_request, approval_id=approval["approval_id"])
        outcomes.append({"step": "crm_updated", **executed})
        email = self.execute_action(
            token=parent_token, task_id=parent_task["task_id"], connector_id="email-draft",
            runtime_proof=parent_run["runtime_proof"],
            action="email.draft", resource="email://case/CASE-1042",
            parameters={"recipient": "customer@example.com", "subject": "Update on CASE-1042", "body": "We are actively investigating your enterprise account issue."},
            data_classification="internal", environment="prod",
            request_nonce=str(uuid4()),
        )
        outcomes.append({"step": "email_drafted", **email})
        jira_request = dict(
            token=parent_token, task_id=parent_task["task_id"], connector_id="jira-create",
            runtime_proof=parent_run["runtime_proof"],
            action="jira.create_ticket", resource="jira://case/CASE-1042",
            parameters={"summary": "Enterprise account failure for CASE-1042", "description": "Investigate the account access regression."},
            data_classification="internal", environment="prod",
            request_nonce=str(uuid4()),
        )
        jira_pending = self.execute_action(**jira_request)
        outcomes.append({"step": "jira_requires_approval", **jira_pending})
        jira_approval = self.resolve_approval(jira_pending["approval_id"], True, admin_actor, "Engineering escalation approved")
        jira_request["request_nonce"] = str(uuid4())
        jira = self.execute_action(**jira_request, approval_id=jira_approval["approval_id"])
        outcomes.append({"step": "jira_created", **jira})
        child_run = self.create_run(principal_id, "code-reviewer", "Review technical evidence for CASE-1042", "prod", parent_run["run_id"])
        child_task = self.create_task(child_run["run_id"], "Read-only review of support repository", parent_task["task_id"])
        child_token, child_claims = self.delegate_capability(
            parent_token=parent_token, parent_runtime_proof=parent_run["runtime_proof"],
            child_run_id=child_run["run_id"], scopes=["github.read"],
            resources=["github://repo/acme/support"], ttl_seconds=300,
        )
        review = self.execute_action(
            token=child_token, task_id=child_task["task_id"], connector_id="github-read",
            runtime_proof=child_run["runtime_proof"],
            action="github.read", resource="github://repo/acme/support",
            parameters={"reference": "main"}, data_classification="internal", environment="prod",
            request_nonce=str(uuid4()),
        )
        outcomes.append({"step": "child_code_review", **review, "child_jti": child_claims["jti"]})
        verification = self.audit.verify()
        return {
            "status": "completed" if all(item["status"] in {"approval_required", "approved", "executed"} for item in outcomes) else "partial",
            "principal_id": principal_id, "run_id": parent_run["run_id"],
            "task_id": parent_task["task_id"], "outcomes": outcomes,
            "authority": {"parent_jti": parent_claims["jti"], "child_jti": child_claims["jti"], "child_scopes": child_claims["scopes"]},
            "audit": verification,
        }

    # -- Internal helpers ------------------------------------------------
    def _request_approval(self, claims: dict[str, Any], task_id: str, action: str, resource: str) -> dict[str, Any]:
        approval_id = str(uuid4())
        now = datetime.now(timezone.utc)
        self.database.execute(
            "INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (approval_id, claims["run_id"], task_id, claims["agent_id"], action, resource, "pending", claims["principal_id"], now.isoformat(), None, None, (now + timedelta(minutes=10)).isoformat(), None),
        )
        self.audit.append(
            "approval.requested", "policy-service", principal_id=claims["principal_id"],
            agent_id=claims["agent_id"], run_id=claims["run_id"], task_id=task_id,
            decision="pending", payload={"approval_id": approval_id, "action": action, "resource": resource},
        )
        return dict(self.database.one("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)))

    def _enforce_rate_limit(self, connector: Any, jti: str) -> None:
        if not self.rate_limiter.allow(
            connector["connector_id"], jti, int(connector["rate_limit_per_minute"])
        ):
            raise ControlPlaneError("Connector rate limit exceeded")

    def _claim_execution(
        self, jti: str, idempotency_key: str, request_hash: str
    ) -> dict[str, Any] | None:
        if not idempotency_key or len(idempotency_key) > 200:
            raise ControlPlaneError("A valid idempotency key is required")
        now = _now()
        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM execution_requests WHERE token_jti=? AND idempotency_key=?",
                (jti, idempotency_key),
            ).fetchone()
            if existing:
                if not hmac.compare_digest(existing["request_hash"], request_hash):
                    raise ControlPlaneError("Idempotency key was reused for a different request")
                if existing["status"] == "completed" and existing["response_json"]:
                    response = json.loads(existing["response_json"])
                    response["idempotent_replay"] = True
                    return response
                if existing["status"] == "uncertain":
                    raise ControlPlaneError(
                        "Action outcome is uncertain and requires operator reconciliation"
                    )
                raise ControlPlaneError("Action request is already in progress")
            connection.execute(
                "INSERT INTO execution_requests VALUES(?,?,?,?,?,?,?)",
                (jti, idempotency_key, request_hash, "processing", None, now, now),
            )
        return None

    def _complete_execution(
        self, jti: str, idempotency_key: str, response: dict[str, Any]
    ) -> None:
        self.database.execute(
            """UPDATE execution_requests SET status='completed',response_json=?,updated_at=?
            WHERE token_jti=? AND idempotency_key=? AND status='processing'""",
            (_json(response), _now(), jti, idempotency_key),
        )

    def _claim_approval(
        self, approval_id: str, claims: dict[str, Any], task_id: str,
        action: str, resource: str,
    ) -> None:
        now = _now()
        with self.database.connect() as connection:
            cursor = connection.execute(
                """UPDATE approvals SET status='executing'
                WHERE approval_id=? AND run_id=? AND task_id=? AND agent_id=?
                AND action=? AND resource=? AND status='approved'
                AND (expires_at IS NULL OR expires_at>?)""",
                (approval_id, claims["run_id"], task_id, claims["agent_id"], action, resource, now),
            )
            if cursor.rowcount != 1:
                raise ControlPlaneError("Approval is unavailable or already claimed")

    def _verify_runtime_proof(self, run_id: str, supplied: str) -> None:
        row = self.database.one("SELECT runtime_secret_hash FROM runs WHERE run_id=?", (run_id,))
        supplied_hash = hashlib.sha256((supplied or "").encode()).hexdigest()
        if not row or not row["runtime_secret_hash"] or not hmac.compare_digest(row["runtime_secret_hash"], supplied_hash):
            raise ControlPlaneError("Runtime proof mismatch")

    def _revocation(self, target_type: str, target_id: str, actor: str, reason: str) -> None:
        self.database.execute(
            "INSERT INTO revocations VALUES(?,?,?,?,?,?)",
            (str(uuid4()), target_type, target_id, reason, actor, _now()),
        )
        self.audit.append(f"{target_type}.revoked", actor, payload={"target_id": target_id, "reason": reason})

    def _ensure_defaults(self) -> None:
        key = self.database.namespace("global_kill_switch")
        if not self.database.one("SELECT key FROM settings WHERE key=?", (key,)):
            self.database.execute("INSERT INTO settings VALUES(?,?,?)", (key, "false", _now()))

    @staticmethod
    def _decode(row: Any, json_fields: set[str]) -> dict[str, Any]:
        result = dict(row)
        for field in json_fields:
            result[field] = json.loads(result[field])
        return result
