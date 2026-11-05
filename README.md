> **Repository-Aufteilung (05.11.2026):** [SPOT](https://github.com/Koco-008/SPOT) ist das öffentliche Gesamtprojekt mit Nachbauanleitung. Das Quell-/CI-Repository heisst jetzt **`Koco-008/SPOT-App`** (gleiche GitHub-Repository-ID). Der signierte BMA-Endstand **SPOT OS 0.1.7 Stable** bleibt [hier](https://github.com/Koco-008/SPOT-OS-Releases/releases/tag/os-v0.1.7) unverändert. Künftige Freigaben verwenden weiter ausschliesslich den geschützten öffentlichen Signierworkflow.

# SPOT OS – Official Releases

Official release repository for **SPOT OS**, a Raspberry Pi 5-based operating environment for the SPOT thermal imaging application.

## About

SPOT OS provides a dedicated touchscreen interface, camera integration, system management and secure software updates for SPOT devices.

This repository is used exclusively to distribute official SPOT OS releases.

## Downloads

Signed releases will be available under [Releases](https://github.com/Koco-008/SPOT-OS-Releases/releases).

Each official OS release will contain the installation package, signed release metadata and integrity verification information.

**Release channels:** OS 0.1.7 is already published as a signed **Stable** release. Earlier OS versions may be prereleases. An unsigned source build is not an official OTA package.

## Security

Official automatic updates are cryptographically verified using Ed25519 digital signatures.

- Release signing keys remain private.
- Devices verify signatures using a trusted public key.
- Modified or unsigned packages are rejected by the official automatic updater.
- No GitHub account or access token is required to download public releases.

## Source Code and Licensing

SPOT OS is open-source software licensed under the MIT License. OS runtime source code and relevant license information are included in the distributed source packages.

The complete public OS 0.1.7 runtime source, build instructions and tests are available in **[SPOT-OS](https://github.com/Koco-008/SPOT-OS)**. The project-wide hardware and build guide is **[SPOT](https://github.com/Koco-008/SPOT)**. This repository remains the **only official signed SPOT OS release channel**.

This repository contains release artifacts, not the private development history.

## Hardware

Target platform: Raspberry Pi 5, 64-bit Raspberry Pi OS / Debian 13.

Supported hardware and compatibility requirements are specified in each release.

---

Copyright © SPOT contributors.
# Anonymous post-publication verification

See [the protected release procedure](RELEASE_PROCESS.md) for the exact OS
0.1.6/106 prerelease and 0.1.7/107 stable compatibility policies, workflow inputs and
`SPOT_OS_APPROVED_COMMIT` approval against the actual private `main` commit.

The protected release workflow additionally re-downloads the four actual public
assets without tokens, credential helpers, cookies or proxy credentials.
`signer/verify_public.py` checks the independently pinned OS public-key hash,
Ed25519 signature, exact predecessor/sequence/app/channel/source metadata, ZIP
digest and every packaged member. It never executes downloaded package code.
Existing signer identity, approved-main CI provenance and required environment
review remain unchanged. No release is dispatched by these tests.

Standalone verification for the already published OS 0.1.7 Stable (approved original private source SHA `0e21c1965a4c0eb9238fa9355abe4cf4f48db36a`):

```sh
python signer/verify_public.py --tag os-v0.1.7 --commit 0e21c1965a4c0eb9238fa9355abe4cf4f48db36a --sequence 107 --previous 0.1.6 --fingerprint b142b246c22fd6f56f4207b86bbd5dcef09b122d228af81c0c51130d4309f907
```

OS 0.1.7 has been signed and published as Stable; the subsequent operator test on the original SPOT BMA hardware was confirmed. Future releases continue to require the protected independent signing workflow and their own hardware approval.
