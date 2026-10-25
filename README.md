# SPOT OS – Official Releases

Official release repository for **SPOT OS**, a Raspberry Pi 5-based operating environment for the SPOT thermal imaging application.

## About

SPOT OS provides a dedicated touchscreen interface, camera integration, system management and secure software updates for SPOT devices.

This repository is used exclusively to distribute official SPOT OS releases.

## Downloads

Signed releases will be available under [Releases](https://github.com/Koco-008/SPOT-OS-Releases/releases).

Each official OS release will contain the installation package, signed release metadata and integrity verification information.

**Release status:** Initial release infrastructure is being prepared. No production OS release is available yet.

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

Copyright © SPOT contributors.
