"""Independent public SPOT OS signer. Never executes downloaded private-repo code."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import urllib.request
import urllib.error
from urllib.parse import urlsplit
import zipfile

SOURCE = "Koco-008/SPOT"
SOURCE_REPO_ID = 1420310429
PUBLISH = "Koco-008/SPOT-OS-Releases"
WORKFLOW = "os-candidate.yml"
MAX = 32 * 1024 * 1024


def fail(message):
    raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def github(path, token, *, binary=False):
    if not (path.startswith(f"repos/{SOURCE}/actions/") or path.startswith(f"repos/{SOURCE}/releases")):
        fail("Invalid source API path")
    url = "https://api.github.com/" + path
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": ("application/octet-stream" if binary and "/releases/assets/" in path
                   else "application/vnd.github+json"),
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SPOT-OS-independent-release/1",
    })

    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            parsed = urlsplit(newurl)
            host = (parsed.hostname or "").lower()
            if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
                fail("Untrusted artifact redirect")
            # GitHub sends artifact downloads to its signed Azure Blob URLs.
            if (host != "api.github.com" and not host.endswith(".githubusercontent.com")
                    and not re.fullmatch(r"[a-z0-9.-]+\.blob\.core\.windows\.net", host)):
                fail("Untrusted artifact storage host")
            new = super().redirect_request(req, fp, code, msg, headers, newurl)
            if new is not None:
                new.remove_header("Authorization")
            return new

    with urllib.request.build_opener(Redirect()).open(request, timeout=60) as response:
        if response.status != 200:
            fail("GitHub API failure")
        raw = response.read(MAX + 1 if binary else 2_000_001)
        if len(raw) > (MAX if binary else 2_000_000):
            fail("Oversized GitHub response")
        return raw if binary else json.loads(raw)


def archive_members(data, *, outer=False):
    result = {}
    if len(data) > MAX:
        fail("Oversized archive")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        members = z.infolist()
        if not members or len(members) > (5 if outer else 500):
            fail("Invalid member count")
        for info in members:
            n = info.filename
            p = PurePosixPath(n)
            if (n in result or n != str(p) or p.is_absolute() or ".." in p.parts
                    or "\\" in n or ":" in n or info.is_dir()
                    or info.flag_bits & 1 or any(part.startswith(".") for part in p.parts)
                    or stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG)):
                fail("Unsafe archive entry")
            if info.file_size > 8 * 1024 * 1024:
                fail("Oversized member")
            result[n] = z.read(info)
    if sum(map(len, result.values())) > 64 * 1024 * 1024:
        fail("Oversized uncompressed data")
    return result


def get_candidate(commit, token):
    if not re.fullmatch("[a-f0-9]{40}", commit):
        fail("Full reviewed SHA required")
    runs = github(f"repos/{SOURCE}/actions/workflows/{WORKFLOW}/runs?head_sha={commit}&event=push&status=success&per_page=100", token)
    matches = [
        r for r in runs.get("workflow_runs", [])
        if r.get("head_sha") == commit and r.get("head_branch") == "main"
        and r.get("event") == "push" and r.get("conclusion") == "success"
        and r.get("status") == "completed"
        and r.get("repository", {}).get("id") == SOURCE_REPO_ID
        and r.get("path") == ".github/workflows/" + WORKFLOW
    ]
    if len(matches) != 1:
        fail("Expected one successful protected main CI run for this exact commit")
    run = matches[0]
    if not isinstance(run.get("id"), int) or run.get("run_attempt") != 1:
        fail("Ambiguous CI run attempt")
    jobs = github(f"repos/{SOURCE}/actions/runs/{run['id']}/jobs?per_page=100", token)
    checked = [j for j in jobs.get("jobs", []) if j.get("name") == "verified-os-candidate"]
    if len(checked) != 1 or checked[0].get("conclusion") != "success" or checked[0].get("status") != "completed":
        fail("Private CI job not complete")
    # A draft release and its proof.json can be replaced after CI finishes.
    # Bind the downloaded asset to the digest actually printed by the verified
    # successful build job; Actions logs are managed by GitHub, not release editors.
    job_id = checked[0].get("id")
    if not isinstance(job_id, int):
        fail("Missing GitHub Actions job identity")
    log = github(f"repos/{SOURCE}/actions/jobs/{job_id}/logs", token, binary=True)
    candidates = re.findall(rb"(?m)^.*?SPOT_OS_CANDIDATE_SHA256=([a-f0-9]{64})\s*$", log)
    if len(candidates) != 1:
        fail("CI job log must contain exactly one candidate digest")
    actual_ci_hash = candidates[0].decode("ascii")
    # The Actions artifact service may be out of storage. Candidate bytes are
    # staged as a draft prerelease in the SAME private repository, and may only
    # be signed after the corresponding exact-commit private CI passed.
    tag = "ci-os-candidate-" + commit
    releases = github(f"repos/{SOURCE}/releases?per_page=100", token)
    if not isinstance(releases, list):
        fail("Unexpected private releases API response")
    matches = [r for r in releases if r.get("tag_name") == tag
               and r.get("draft") is True and r.get("prerelease") is True
               and r.get("target_commitish") == commit]
    if len(matches) != 1:
        fail("Missing uniquely staged private candidate for reviewed commit")
    release = matches[0]
    assets = release.get("assets", [])
    expected = {"spot-os-0.1.4.zip", "proof.json"}
    if not isinstance(assets, list) or {a.get("name") for a in assets} != expected or len(assets) != 2:
        fail("Private staging release must contain exactly two candidate assets")
    files = {}
    for asset in assets:
        name = asset["name"]
        if (not isinstance(asset.get("id"), int) or asset.get("state") != "uploaded"
                or not isinstance(asset.get("size"), int) or not 0 < asset["size"] <= MAX):
            fail("Malformed private staging asset")
        raw = github(f"repos/{SOURCE}/releases/assets/{asset['id']}", token, binary=True)
        if len(raw) != asset["size"]:
            fail("Private staging asset download size mismatch")
        files[name] = raw
    proof = json.loads(files["proof.json"])
    if set(proof) != {"schema", "kind", "repository", "source_commit", "version", "asset", "sha256", "size"}:
        fail("Unexpected proof fields")
    if proof["schema"] != 1 or proof["kind"] != "spot-os-ci-candidate" or proof["repository"] != SOURCE or proof["source_commit"] != commit:
        fail("Wrong CI artifact provenance")
    version = proof["version"]
    if not re.fullmatch(r"0\.[0-9]+\.[0-9]+", version) or proof["asset"] != f"spot-os-{version}.zip":
        fail("Unexpected candidate version")
    if proof["asset"] != "spot-os-0.1.4.zip":
        fail("Unexpected candidate asset")
    payload = files[proof["asset"]]
    if proof["sha256"] != actual_ci_hash:
        fail("Staged private release differs from the successful CI build digest")
    if len(payload) != proof["size"] or sha(payload) != proof["sha256"]:
        fail("Private CI ZIP differs from proof")
    payloads = archive_members(payload)
    if any(not k.startswith("spot_os/") or "tests" in PurePosixPath(k).parts or "__pycache__" in PurePosixPath(k).parts for k in payloads):
        fail("Untrusted internal files")
    internal = json.loads(payloads.get("spot_os/PACKAGE.json", b"{}"))
    if internal.get("schema") != 1 or internal.get("kind") != "os-installer" or internal.get("version") != version or internal.get("app_version") != "unchanged":
        fail("Wrong internal package manifest")
    hashes = internal.get("files")
    if not isinstance(hashes, dict) or set(hashes) != set(payloads) - {"spot_os/PACKAGE.json"}:
        fail("Wrong inner file set")
    for name, expected_hash in hashes.items():
        if sha(payloads[name]) != expected_hash:
            fail("Damaged inner member")
    if payloads.get("spot_os/VERSION", b"").decode().strip() != version:
        fail("Wrong OS version")
    public = payloads.get("spot_os/trust/spot-os-release.pub")
    if not public:
        fail("No embedded independent OS trust key")
    return proof, payload, internal, public


def main():
    source = os.environ["SOURCE_COMMIT"]
    approved = os.environ.get("APPROVED_COMMIT", "")
    enabled = os.environ.get("SIGNING_ENABLED", "")
    token = os.environ.get("SOURCE_ACTIONS_TOKEN", "")
    key = os.environ.get("OS_SIGNING_KEY", "")
    fingerprint = os.environ.get("PUBLIC_KEY_SHA256", "").lower()
    tag = os.environ["RELEASE_TAG"]
    sequence = int(os.environ["RELEASE_SEQUENCE"])
    previous = os.environ["PREVIOUS_OS"]
    channel = os.environ["RELEASE_CHANNEL"]
    if enabled != "true" or not token or not key or not re.fullmatch("[a-f0-9]{64}", fingerprint):
        fail("Release disabled or missing operator provisioning")
    if approved != source or channel not in ("stable", "prerelease"):
        fail("Source commit / channel not approved")
    proof, payload, internal, public = get_candidate(source, token)
    version = proof["version"]
    if tag != "os-v" + version or previous != "0.1.3" or version != "0.1.4" or sequence != 104:
        fail("First bootstrap must be exactly OS 0.1.4/104 from 0.1.3")
    if sha(public) != fingerprint:
        fail("Embedded OS trust key fingerprint does not match operator verification")
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PublicFormat
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    private = load_pem_private_key(key.encode(), password=None)
    trusted = load_pem_public_key(public)
    if not isinstance(private, Ed25519PrivateKey) or not isinstance(trusted, Ed25519PublicKey):
        fail("OS signer requires Ed25519")
    if private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo) != public:
        fail("Signer/public trust identity differs")
    data = {
        "schema": 1, "kind": "spot-os", "repository": PUBLISH,
        "platform": "raspios-debian13-aarch64", "tag": tag,
        "version": version, "revision": internal["revision"], "sequence": sequence,
        "asset": proof["asset"], "size": proof["size"], "sha256": proof["sha256"],
        "source_commit": source, "channel": channel,
        "notes": "Protected signed SPOT OS " + version + " hardware candidate",
        "requires_os_min": previous, "requires_os_max": previous,
        "requires_app_min": "0.28.12", "reader_protocol": 1, "engine": 1,
        "reboot": False,
    }
    raw = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
    signature = private.sign(raw)
    trusted.verify(signature, raw)
    dest = Path("out")
    dest.mkdir(exist_ok=False)
    (dest / proof["asset"]).write_bytes(payload)
    (dest / "os-update.json").write_bytes(raw)
    (dest / "os-update.json.sig").write_bytes(signature)
    names = [proof["asset"], "os-update.json", "os-update.json.sig"]
    (dest / "SHA256SUMS.txt").write_text("".join(sha((dest / name).read_bytes()) + "  " + name + "\n" for name in names), encoding="ascii")
    print("Signed verified candidate", version, proof["sha256"], source)

if __name__ == "__main__":
    main()
