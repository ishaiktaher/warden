"""Production preflight tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import unittest

from control_plane.config import Settings
from control_plane.preflight import evaluate_production_settings


def valid_settings() -> Settings:
    return Settings(
        database_path=Path("unused.db"),
        data_dir=Path("unused"),
        issuer="warden",
        audience="gateway",
        admin_key="a" * 48,
        environment="prod",
        allowed_egress_hosts=("api.example.com",),
        public_url="https://warden.example.com",
        database_url="postgresql://warden@db/warden?sslmode=require",
        oidc_issuer="https://identity.example.com",
        oidc_audience="https://warden.example.com",
        redis_url="rediss://cache.example.com/0",
        otlp_endpoint="https://telemetry.example.com",
        signing_provider="http",
        secrets_provider="http",
        audit_provider="http",
        signing_provider_url="https://security.example.com",
        secrets_provider_url="https://security.example.com",
        audit_provider_url="https://security.example.com",
        provider_auth_token="workload-token",
    )


class ProductionPreflightTests(unittest.TestCase):
    def test_valid_production_configuration_passes(self) -> None:
        result = evaluate_production_settings(valid_settings())
        self.assertTrue(result.ok)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.warnings, ())

    def test_insecure_and_local_configuration_fails_without_secret_output(self) -> None:
        settings = replace(
            valid_settings(),
            admin_key="replace_me",
            public_url="http://warden.example.com",
            oidc_issuer="http://identity.example.com",
            signing_provider="local",
            secrets_provider="local",
            audit_provider="local",
            provider_auth_token=None,
        )
        result = evaluate_production_settings(settings)
        self.assertFalse(result.ok)
        rendered = str(result.as_dict())
        self.assertNotIn("workload-token", rendered)
        self.assertIn("CONTROL_PLANE_ADMIN_KEY", rendered)
        self.assertIn("WARDEN_SIGNING_PROVIDER", rendered)

    def test_operational_gaps_are_warnings(self) -> None:
        settings = replace(
            valid_settings(),
            allowed_egress_hosts=(),
            auto_migrate=True,
            otlp_endpoint=None,
            redis_url="redis://private-cache/0",
            provider_auth_token=None,
        )
        result = evaluate_production_settings(settings)
        self.assertTrue(result.ok)
        self.assertEqual(len(result.warnings), 5)


if __name__ == "__main__":
    unittest.main()
