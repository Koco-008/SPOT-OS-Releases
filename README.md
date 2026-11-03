# SPOT OS â€“ Official Releases

Official release repository for **SPOT OS**, a Raspberry Pi 5-based operating environment for the SPOT thermal imaging application.

## About

SPOT OS provides a dedicated touchscreen interface, camera integration, system management and secure software updates for SPOT devices.

This repository is used exclusively to distribute official SPOT OS releases.

## Downloads

Signed releases will be available under [Releases](https://github.com/Koco-008/SPOT-OS-Releases/releases).

Each official OS release will contain the installation package, signed release metadata and integrity verification information.

**Release status:** Signed hardware-test prereleases are distributed through
the existing protected signing workflow. Preparing a signer change does not
publish a release or establish Raspberry Pi hardware acceptance.

## Security

Official automatic updates are cryptographically verified using Ed25519 digital signatures.

- Release signing keys remain private.
- Devices verify signatures using a trusted public key.
- Modified or unsigned packages are rejected by the official automatic updater.
- No GitHub account or access token is required to download public releases.

## Source Code and Licensing

SPOT OS is open-source software licensed under the MIT License. OS runtime source code and relevant license information are included in the distributed source packages.

This repository contains release artifacts, not the private development history.

## Hardware

Target platform: Raspberry Pi 5, 64-bit Raspberry Pi OS / Debian 13.

Supported hardware and compatibility requirements are specified in each release.

---

Copyright Â© SPOT contributors.
# Anonymous post-publication verification

See [the protected release procedure](RELEASE_PROCESS.md) for the exact OS
0.1.6/106 compatibility policy, workflow inputs and
`SPOT_OS_APPROVED_COMMIT` approval against the actual private `main` commit.

The protected release workflow additionally re-downloads the four actual public
assets without tokens, credential helpers, cookies or proxy credentials.
`signer/verify_public.py` checks the independently pinned OS public-key hash,
Ed25519 signature, exact predecessor/sequence/app/channel/source metadata, ZIP
digest and every packaged member. It never executes downloaded package code.
Existing signer identity, approved-main CI provenance and required environment
review remain unchanged. No release is dispatched by these tests.

Standalone verification after the operator-approved 0.1.5 publication:

```sh
python signer/verify_public.py --tag os-v0.1.5 --commit FULL_TESTED_MAIN_SHA --sequence 105 --previous 0.1.4 --fingerprint b142b246c22fd6f56f4207b86bbd5dcef09b122d228af81c0c51130d4309f907
```
