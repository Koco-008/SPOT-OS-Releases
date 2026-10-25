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


def fixture():
    files = {
        "spot_os/VERSION": b"0.1.4\n",
        "spot_os/trust/spot-os-release.pub": b"mock-test-only-ed25519-public",
        "spot_os/__init__.py": b"VERSION='0.1.4'\nREVISION='signed-os-updates-1'\n",
        "spot_os/cli.py": b"def main(): pass\n",
    }
    internal = {
        "schema": 1, "kind": "os-installer", "version": VERSION,
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
        "repository": signer.SOURCE, "source_commit": COMMIT, "version": VERSION,
        "asset": "spot-os-0.1.4.zip", "sha256": sha(payload), "size": len(payload),
    }
    return proof, payload, internal


class ReleaseCandidateTests(TestCase):
    def setup_values(self):
        proof, payload, internal = fixture()
        assets = {
            10: payload,
            11: json.dumps(proof).encode(),
        }
        release = {
            "tag_name": TAG, "draft": True, "prerelease": True,
            "target_commitish": COMMIT,
            "assets": [
                {"name": "spot-os-0.1.4.zip", "id": 10, "state": "uploaded", "size": len(assets[10])},
                {"name": "proof.json", "id": 11, "state": "uploaded", "size": len(assets[11])},
            ],
        }
        return proof, payload, assets, release

    def github_mock(self, proof, assets, release, log_hash=None, completed=True):
        ci_digest = log_hash if log_hash is not None else proof["sha256"]
        def call(path, token, *, binary=False):
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

    def test_changed_draft_zip_and_proof_rejected_by_immutable_ci_digest(self):
        proof, payload, assets, release = self.setup_values()
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

    def test_run_not_completed_rejected(self):
        proof, payload, assets, release = self.setup_values()
        with mock.patch.object(signer, "github", self.github_mock(proof, assets, release, completed=False)):
            with self.assertRaisesRegex(RuntimeError, "successful protected main"):
                signer.get_candidate(COMMIT, "not-a-real-token")

    def test_missing_draft_release_rejected(self):
        proof, payload, assets, release = self.setup_values()
        release["draft"] = False
        with mock.patch.object(signer, "github", self.github_mock(proof, assets, release)):
            with self.assertRaisesRegex(RuntimeError, "Missing uniquely staged"):
                signer.get_candidate(COMMIT, "not-a-real-token")


if __name__ == "__main__":
    import unittest
    unittest.main()
