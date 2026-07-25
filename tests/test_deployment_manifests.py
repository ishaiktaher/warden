"""Static safety checks for the production deployment contract."""

from __future__ import annotations

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class ProductionManifestTests(unittest.TestCase):
    def test_production_kustomization_is_complete_and_parseable(self) -> None:
        production = ROOT / "deploy" / "production"
        kustomization = yaml.safe_load(
            (production / "kustomization.yaml").read_text(encoding="utf-8")
        )
        resources = kustomization["resources"]
        self.assertEqual(
            {
                "service-account.yaml",
                "deployment.yaml",
                "service.yaml",
                "pod-disruption-budget.yaml",
                "network-policy.yaml",
                "ingress.yaml",
            },
            set(resources),
        )
        for resource in resources:
            path = production / resource
            self.assertTrue(path.is_file(), resource)
            self.assertTrue(list(yaml.safe_load_all(path.read_text(encoding="utf-8"))))
        for bootstrap_resource in ("namespace.yaml", "deployer-role.yaml"):
            path = production / bootstrap_resource
            self.assertTrue(list(yaml.safe_load_all(path.read_text(encoding="utf-8"))))

    def test_every_release_workload_uses_an_immutable_digest_placeholder(self) -> None:
        paths = (
            ROOT / "deploy" / "production" / "deployment.yaml",
            ROOT / "deploy" / "k8s-preflight-job.yaml",
            ROOT / "deploy" / "k8s-migrate-job.yaml",
            ROOT / "deploy" / "k8s-maintenance-cronjobs.yaml",
        )
        placeholder = (
            "ghcr.io/ishaiktaher/warden@sha256:replace-with-reviewed-digest"
        )
        for path in paths:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
            rendered = path.read_text(encoding="utf-8")
            self.assertTrue(documents, path.name)
            self.assertIn(placeholder, rendered, path.name)
            self.assertNotIn("image: latest", rendered, path.name)

    def test_deployment_workflow_orders_safety_gates_before_rollout(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "deploy-production.yml"
        ).read_text(encoding="utf-8")
        provenance = workflow.index("Verify GitHub build provenance")
        preflight = workflow.index("Run strict production preflight")
        migration = workflow.index("Run schema migration")
        rollout = workflow.index("Roll out reviewed release")
        self.assertLess(provenance, preflight)
        self.assertLess(preflight, migration)
        self.assertLess(migration, rollout)


if __name__ == "__main__":
    unittest.main()
