"""Fail-closed private staging provenance regression tests; no secrets or network."""
import hashlib
import io
import json
from unittest import TestCase, mock
import zipfile

import sign_candidate as signer

COMMIT = "a" * 40
VERSION = "0.1.4"
TAG = "ci-os-candidate-" + COMMIT


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture(version=VERSION):
    files = {
        "spot_os/VERSION": (version + "\n").encode(),
        "spot_os/trust/spot-os-release.pub": b"mock-test-only-ed25519-public",
        "spot_os/__init__.py": ("VERSION='" + version + "'\nREVISION='signed-os-updates-1'\n").encode(),
        "spot_os/cli.py": b"def main(): pass\n",
    }
    internal = {
        "schema": 1, "kind": "os-installer", "version": version,
        "revision": "signed-os-updates-1", "app_version": "unchanged",
        "base_commit": "b" * 40,
        "files": {name: sha(data) for name, data in files.items()},
    }
    files["spot_os/PACKAGE.json"] = json.dumps(internal).encode()
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_STORED) as archive:
        for name, raw in files.items():
            archive.writestr(name, raw)
    payload = bio.getvalue()
    proof = {
        "schema": 1, "kind": "spot-os-ci-candidate",
        "repository": signer.SOURCE, "source_commit": COMMIT, "version": version,
        "asset": "spot-os-" + version + ".zip", "sha256": sha(payload), "size": len(payload),
    }
    return proof, payload, internal


class ReleaseCandidateTests(TestCase):
    def setup_values(self,version=VERSION):
        proof, payload, internal = fixture(version)
        assets = {
            10: payload,
            11: json.dumps(proof).encode(),
        }
        release = {
            "tag_name": TAG, "draft": False, "prerelease": True,
            "target_commitish": COMMIT,
            "assets": [
                {"name": proof["asset"], "id": 10, "state": "uploaded", "size": len(assets[10])},
                {"name": "proof.json", "id": 11, "state": "uploaded", "size": len(assets[11])},
            ],
        }
        return proof, payload, assets, release

    def github_mock(self, proof, assets, release, log_hash=None, completed=True):
        ci_digest = log_hash if log_hash is not None else proof["sha256"]
        def call(path, token, *, binary=False):
            if path == f"repos/{signer.SOURCE}/branches/main":
                return {"name": "main", "commit": {"sha": COMMIT}}
            if "/actions/workflows/" in path:
                return {"workflow_runs": [{
                    "head_sha": COMMIT, "head_branch": "main",
                    "event": "push", "status": "completed" if completed else "in_progress",
                    "conclusion": "success" if completed else None,
                    "repository": {"id": signer.SOURCE_REPO_ID},
                    "path": ".github/workflows/os-candidate.yml",
                    "id": 500, "run_attempt": 1,
                }]}
            if "/actions/runs/500/jobs" in path:
                return {"jobs": [{"name": "verified-os-candidate", "id": 501,
                                  "status": "completed", "conclusion": "success"}]}
            if "/actions/jobs/501/logs" in path:
                return ("2026-10-25T13:00:00Z SPOT_OS_CANDIDATE_SHA256=" + ci_digest + "\n").encode()
            if path.endswith("/releases?per_page=100"):
                return [release]
            if "/releases/assets/" in path:
                return assets[int(path.rsplit("/", 1)[1])]
            raise AssertionError("unexpected API path " + path)
        return call

    def test_valid_ci_binds_exact_candidate_bytes(self):
        proof, payload, assets, release = self.setup_values()
        with mock.patch.object(signer, "github", self.github_mock(proof, assets, release)):
            p, raw, inner, public = signer.get_candidate(COMMIT, "not-a-real-token")
        self.assertEqual(raw, payload)
        self.assertEqual(p["sha256"], sha(payload))
        self.assertIn(b"mock-test-only", public)

    def test_valid_015_ci_binds_exact_candidate_bytes(self):
        proof, payload, assets, release = self.setup_values("0.1.5")
        with mock.patch.object(signer, "github", self.github_mock(proof, assets, release)):
            p, raw, inner, public = signer.get_candidate(COMMIT, "not-a-real-token")
        self.assertEqual(p["version"], "0.1.5")
        self.assertEqual(p["asset"], "spot-os-0.1.5.zip")
        self.assertEqual(raw, payload)

    def test_valid_016_ci_binds_exact_candidate_bytes(self):
        proof, payload, assets, release = self.setup_values("0.1.6")
        with mock.patch.object(signer, "github", self.github_mock(proof, assets, release)):
            p, raw, _, _ = signer.get_candidate(COMMIT, "not-a-real-token")
        self.assertEqual(p["asset"], "spot-os-0.1.6.zip")
        self.assertEqual(raw, payload)

    def test_016_rejects_wrong_ci_provenance(self):
        proof, _, assets, release = self.setup_values("0.1.6")
        base = self.github_mock(proof, assets, release)
        for field, value in (("conclusion", "failure"), ("head_sha", "b" * 40),
                ("head_branch", "feature"), ("event", "workflow_dispatch"),
                ("event", "pull_request"), ("run_attempt", 2),
                ("repository", {"id": 1}), ("path", ".github/workflows/other.yml")):
            with self.subTest(field=field, value=value):
                def altered(path, token, *, binary=False):
                    result = base(path, token, binary=binary)
                    if "/actions/workflows/" in path:
                        result["workflow_runs"][0][field] = value
                    return result
                with mock.patch.object(signer, "github", altered):
                    with self.assertRaises(RuntimeError):
                        signer.get_candidate(COMMIT, "fake")

    def test_016_rejects_noncurrent_main_and_main_advancing_during_verification(self):
        proof, _, assets, release = self.setup_values("0.1.6")
        base = self.github_mock(proof, assets, release)
        for advance_after in (0, 1):
            calls = []
            def altered(path, token, *, binary=False):
                result = base(path, token, binary=binary)
                if path.endswith("/branches/main"):
                    calls.append(path)
                    if len(calls) > advance_after:
                        result["commit"]["sha"] = "b" * 40
                return result
            with self.subTest(advance_after=advance_after), mock.patch.object(signer, "github", altered):
                with self.assertRaisesRegex(RuntimeError, "current private main"):
                    signer.get_candidate(COMMIT, "fake")

    def test_016_rejects_wrong_staging_or_proof_commit(self):
        for target in ("release", "proof"):
            proof, _, assets, release = self.setup_values("0.1.6")
            if target == "release":
                release["target_commitish"] = "b" * 40
            else:
                proof["source_commit"] = "b" * 40
                assets[11] = json.dumps(proof).encode()
                release["assets"][1]["size"] = len(assets[11])
            with self.subTest(target=target), mock.patch.object(signer, "github", self.github_mock(proof, assets, release)):
                with self.assertRaises(RuntimeError):
                    signer.get_candidate(COMMIT, "fake")

    def test_016_rejects_failed_build_job_even_if_run_claims_success(self):
        proof, _, assets, release = self.setup_values("0.1.6")
        base = self.github_mock(proof, assets, release)
        def altered(path, token, *, binary=False):
            result = base(path, token, binary=binary)
            if "/actions/runs/500/jobs" in path:
                result["jobs"][0]["conclusion"] = "failure"
            return result
        with mock.patch.object(signer, "github", altered):
            with self.assertRaisesRegex(RuntimeError, "job not complete"):
                signer.get_candidate(COMMIT, "fake")

    def test_016_rejects_tampered_zip_with_unchanged_proof(self):
        proof, _, assets, release = self.setup_values("0.1.6")
        assets[10] += b"tampered"
        release["assets"][0]["size"] = len(assets[10])
        with mock.patch.object(signer, "github", self.github_mock(proof, assets, release)):
            with self.assertRaisesRegex(RuntimeError, "ZIP differs from proof"):
                signer.get_candidate(COMMIT, "fake")

    def test_016_rejects_tampered_inner_member_even_with_matching_outer_digest(self):
        proof, payload, assets, release = self.setup_values("0.1.6")
        files = signer.archive_members(payload)
        files["spot_os/cli.py"] += b"changed"
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name, raw in files.items():
                archive.writestr(name, raw)
        assets[10] = stream.getvalue()
        proof.update(size=len(assets[10]), sha256=sha(assets[10]))
        assets[11] = json.dumps(proof).encode()
        for asset in release["assets"]:
            asset["size"] = len(assets[asset["id"]])
        with mock.patch.object(signer, "github", self.github_mock(proof, assets, release)):
            with self.assertRaisesRegex(RuntimeError, "Damaged inner member"):
                signer.get_candidate(COMMIT, "fake")

    def test_only_reviewed_release_sequences_and_predecessors(self):
        self.assertTrue(signer.release_target_valid("0.1.4", 104, "0.1.3", "os-v0.1.4"))
        self.assertTrue(signer.release_target_valid("0.1.5", 105, "0.1.4", "os-v0.1.5"))
        self.assertTrue(signer.release_target_valid("0.1.6", 106, "0.1.4", "os-v0.1.6"))
        for version, sequence, previous, tag in (
            ("0.1.5", 104, "0.1.4", "os-v0.1.5"),
            ("0.1.5", 105, "0.1.3", "os-v0.1.5"),
            ("0.1.5", 105, "0.1.5", "os-v0.1.5"),
            ("0.1.5", 105, "0.1.4", "os-v0.1.4"),
            ("0.1.6", 106, "0.1.5", "os-v0.1.6"),
            ("0.1.6", 105, "0.1.4", "os-v0.1.6"),
            ("0.1.6", 107, "0.1.4", "os-v0.1.6"),
            ("0.1.6", 106, "0.1.3", "os-v0.1.6"),
            ("0.1.6", 106, "0.1.6", "os-v0.1.6"),
            ("0.1.6", 106, "0.1.4", "os-v0.1.5"),
        ):
            self.assertFalse(signer.release_target_valid(version, sequence, previous, tag))

    def test_changed_private_release_zip_and_proof_rejected_by_immutable_ci_digest(self):
        proof, payload, assets, release = self.setup_values("0.1.6")
        good_digest = proof["sha256"]
        altered = payload + b"junk"
        proof["sha256"], proof["size"] = sha(altered), len(altered)
        assets[10] = altered
        assets[11] = json.dumps(proof).encode()
        release["assets"][0]["size"] = len(altered)
        release["assets"][1]["size"] = len(assets[11])
        with mock.patch.object(signer, "github", self.github_mock(proof, assets, release, log_hash=good_digest)):
            with self.assertRaisesRegex(RuntimeError, "CI build digest"):
                signer.get_candidate(COMMIT, "not-a-real-token")

    def test_http_accept_header_matches_github_resource_type(self):
        """Job logs return HTTP 415 with an octet-stream Accept header."""
        from unittest import mock
        from contextlib import contextmanager

        requests = []

        class Response:
            status = 200
            def read(self, size=None):
                return b"SPOT_OS_CANDIDATE_SHA256=" + b"a" * 64 if size == signer.MAX + 1 else b"{}"
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False

        class Opener:
            def open(self, request, timeout=None):
                requests.append(request)
                return Response()

        with mock.patch.object(signer.urllib.request, "build_opener", return_value=Opener()):
            signer.github(f"repos/{signer.SOURCE}/actions/jobs/123/logs", "fake", binary=True)
            signer.github(f"repos/{signer.SOURCE}/releases/assets/123", "fake", binary=True)
            signer.github(f"repos/{signer.SOURCE}/actions/runs/123/jobs", "fake")
        self.assertEqual(requests[0].get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(requests[1].get_header("Accept"), "application/octet-stream")
        self.assertEqual(requests[2].get_header("Accept"), "application/vnd.github+json")

    def test_run_not_completed_rejected(self):
        proof, payload, assets, release = self.setup_values()
        with mock.patch.object(signer, "github", self.github_mock(proof, assets, release, completed=False)):
            with self.assertRaisesRegex(RuntimeError, "successful protected main"):
                signer.get_candidate(COMMIT, "not-a-real-token")

    def test_draft_release_is_not_accessible_to_read_only_token(self):
        proof, payload, assets, release = self.setup_values()
        release["draft"] = True
        with mock.patch.object(signer, "github", self.github_mock(proof, assets, release)):
            with self.assertRaisesRegex(RuntimeError, "Missing uniquely staged"):
                signer.get_candidate(COMMIT, "not-a-real-token")


if __name__ == "__main__":
    import unittest
    unittest.main()
