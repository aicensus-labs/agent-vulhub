"""GHCR prune tests use synthetic package payloads and never call the network."""

import json
import unittest
from unittest import mock

from runner import prune as prune_module


def _version(identifier, tags):
    return {"id": identifier, "metadata": {"container": {"tags": tags}}}


class PruneTests(unittest.TestCase):
    def setUp(self):
        self.deleted = []

    def _fake_gh(self, versions, owner_type="Organization", delete_fails=()):
        def runner(args, timeout):
            if args[:2] == ["api", "users/example-owner"]:
                return mock.Mock(returncode=0, stdout=json.dumps({"type": owner_type}), stderr="")
            if args[0] == "api" and "/versions/" in args[-1] and "--method" in args:
                identifier = int(args[-1].rsplit("/", 1)[1])
                self.deleted.append(identifier)
                if identifier in delete_fails:
                    return mock.Mock(returncode=1, stdout="", stderr="denied")
                return mock.Mock(returncode=0, stdout="", stderr="")
            if args[0] == "api":
                return mock.Mock(returncode=0, stdout=json.dumps(versions), stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")
        return runner

    def test_rejects_a_repository_without_owner_and_package(self):
        with self.assertRaisesRegex(ValueError, "lowercase ghcr.io/owner/package"):
            prune_module.prune("ghcr.io/onlyowner")

    def test_dry_run_reports_without_deleting(self):
        versions = [_version(1, ["vulnerable-abc"]), _version(2, []), _version(3, [])]
        with mock.patch.object(prune_module, "_gh", self._fake_gh(versions)):
            outcome = prune_module.prune("ghcr.io/example-owner/example-package")
        self.assertEqual(self.deleted, [])
        self.assertFalse(outcome["applied"])
        self.assertEqual(outcome["tagged"], 1)
        self.assertEqual(outcome["untagged"], 2)
        self.assertEqual(sorted(outcome["deleted"]), [2, 3])

    def test_apply_deletes_only_untagged_versions(self):
        versions = [_version(1, ["vulnerable-abc"]), _version(2, []), _version(3, ["patched-abc"])]
        with mock.patch.object(prune_module, "_gh", self._fake_gh(versions)):
            outcome = prune_module.prune("ghcr.io/example-owner/example-package", apply_changes=True)
        self.assertEqual(self.deleted, [2])
        self.assertEqual(outcome["deleted"], [2])
        self.assertEqual(outcome["failures"], [])

    def test_delete_failures_are_reported_not_raised(self):
        versions = [_version(7, [])]
        with mock.patch.object(prune_module, "_gh", self._fake_gh(versions, delete_fails={7})):
            outcome = prune_module.prune("ghcr.io/example-owner/example-package", apply_changes=True)
        self.assertEqual(outcome["deleted"], [])
        self.assertEqual(len(outcome["failures"]), 1)

    def test_user_owned_packages_use_the_user_endpoint(self):
        versions = [_version(1, [])]
        with mock.patch.object(prune_module, "_gh", self._fake_gh(versions, owner_type="User")):
            outcome = prune_module.prune("ghcr.io/example-owner/example-package")
        self.assertEqual(outcome["endpoint"], "users/example-owner/packages/container/example-package")


if __name__ == "__main__":
    unittest.main()
