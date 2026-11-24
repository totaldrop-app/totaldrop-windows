<!-- SPDX-FileCopyrightText: 2026 The TotalDrop Contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Microsoft Partner Center Pre-Submission Governance Checklist (Plane A)

This checklist documents every manual human-governance decision and Partner Center action required before reserving `"TotalDrop"` or uploading a `.msixupload` package to the Microsoft Store (per `totaldrop/docs/kararlar/0016-windows-microsoft-store.md` and Microsoft Store Policies v7.20).

Related documentation:
- End-to-end release & ADR 0016 Step 6 runbook: [docs/microsoft-store-release.md](microsoft-store-release.md)
- Ready-to-paste Partner Center certification notes: [docs/store-certification-notes.md](store-certification-notes.md)

> **Hold Gate:** Complete Sections 1 through 4 **before** clicking **Reserve product name** in Partner Center. Do not start the 3-month name reservation clock until the build passes local WACK validation on a dual-architecture `.msixbundle`.

---

## 1. Policy 10.14 Account Type, Non-Convertibility, No Self-Service Transfer & Paths A / B / C

Microsoft Store Policies v7.20 (**Section 10.14**, effective October 22, 2026) require publisher display names and product identities that appear to consumers as a business, organization, or commercial brand to be backed by a verified **Company** account rather than an **Individual** account.

Irreversible Microsoft Partner Center platform constraints:
- **Individual accounts cannot be converted into Company accounts.** Moving to a Company account later requires opening a separate Partner Center account.
- **Reserved MSIX product names and published Store products have no self-service transfer** between Partner Center accounts. Transferring ownership requires manual Microsoft Support escalation and is not guaranteed.

Inspect **Partner Center -> Account settings -> Legal info** (`Publisher display name` and `Windows publisher ID`) and record an explicit maintainer decision choosing one path before reserving `"TotalDrop"`:

- **Path A (Verify Brand on Individual Account):** Contact Partner Center Engage Center to confirm in writing whether an unpaid, non-commercial open-source Individual developer may publish under the display name `"TotalDrop"` under Policy 10.14. Archive the written confirmation before reserving the product name.
- **Path B (Personal Individual Publisher):** Publish under the personal legal name `"Ozan Özdil"` as a non-commercial Individual developer (classified as an EU DSA **non-trader** so no public personal home address or phone number is displayed), and record an ADR 0012 addendum documenting the personal publisher display name exception.
- **Path C (Company Account):** Defer Microsoft Store submission until TotalDrop has a registered legal entity (with D-U-N-S / official government registration documents) and opens a Company Partner Center account, which also unlocks organization team roles (eliminating single-user bus factor) and Microsoft Entra ID integration for `msstore` CLI CI automation.

---

## 2. 3-Month App Name Reservation Clock Warning & Partner Center Identity Capture

1. Reserving an app name in Partner Center (**Apps and games -> + New product -> MSIX or PWA app**) starts a strict **3-month countdown** to submit a package before the reservation expires and returns to the public pool.
2. **Do not reserve `"TotalDrop"` early.** Keep using the temporary test identity (`Name="TotalDrop.TotalDrop"`, `Publisher="CN=TotalDrop"`) across CI and dry-runs until dual-architecture `x64` + `ARM64` `.msixupload` packaging and local WACK verification (`tools/run-wack.ps1`) pass cleanly.
3. Immediately after reserving `"TotalDrop"`, open **Product management -> Product Identity** and copy these exact, case-sensitive values (none of these values are secrets; commit them to `Package.x64.appxmanifest` and `Package.arm64.appxmanifest` in a reviewed release PR):
   - `Package/Identity/@Name` (e.g., `<PublisherPrefix>.TotalDrop`)
   - `Package/Identity/@Publisher` (`CN=<GUID>`, strict RFC 2253 X.500 format)
   - `Package/Properties/PublisherDisplayName` (must match Partner Center Legal Info verbatim)
   - `PackageFamilyName`
   - Store Product ID (`<9N...>`, used for `https://apps.microsoft.com/detail/<9N...>` and `winget install --source msstore <9N...>`)
4. Validate committed manifests with `python3 tools/check-versions.py --store --require-store-identity`.

---

## 3. Account Security Hardening: Passkey / Authenticator 2FA, Zero SMS & `hello@totaldrop.app` Custody

Because Microsoft Store signs uploaded packages with Microsoft's trusted Store certificate and auto-updates all installed users silently, **the Partner Center Microsoft Account is a single point of trust** for every Windows user (ADR 0016):

- [ ] Enable **FIDO2 hardware Passkey** and/or **Microsoft Authenticator** app two-factor authentication on the Partner Center Microsoft Account.
- [ ] **Disable SMS-based recovery and SMS 2FA completely** (protects against SIM-swap account takeover).
- [ ] Enforce strong 2FA and restricted maintainer access on the support and notification mailbox `hello@totaldrop.app`.
- [ ] Maintain an offline, access-controlled recovery record for emergency continuity.
- [ ] Acknowledge the **Individual account bus factor**: an Individual Partner Center account supports only a single MSA owner without multi-user RBAC; transitioning to a Company account (Path C) is required for native multi-maintainer role separation (`@ozdil` + `@sadikkuzu`).

---

## 4. EU Digital Services Act (DSA) Trader vs. Non-Trader Guidance

Partner Center requires an EU Digital Services Act (DSA) self-declaration for visibility in European Union Store markets:

- **Non-Trader (Individual non-commercial open-source developer):** Applies when TotalDrop is distributed strictly free of charge (`$0.00`), with zero ads, zero in-app purchases, zero paid support tiers, and zero commercial activity (ADR 0005). Declaring **Non-Trader** avoids publishing a personal residential address and personal phone number on public EU Store product pages.
- **Trader (Company or commercial activity):** Requires Know-Your-Business (KYB) verification and public display of a business physical address, phone number, and email address on EU Store listings.
- **Maintainer legal verification:** Before completing the EU DSA declaration on an Individual account, verify whether voluntary open-source project donations (ADR 0017) or the `totaldrop.app` website affect non-trader status under current EU guidance.

---

## 5. Individual Manual Web Upload (No Entra ID / No `msstore` CLI) & CI Provenance Caveat

- **Why manual web upload is required:** Individual Partner Center accounts cannot associate a Microsoft Entra ID tenant, which is mandatory to obtain credentials for the Microsoft Store Submission API and `msstore` CLI. Therefore, `.github/workflows/windows-release.yml` intentionally has least-privilege `contents: read` (plus job-scoped `id-token: write` and `attestations: write` for Sigstore OIDC only) and uploads the verified `totaldrop-windows-store-submission` artifact for manual browser upload by the account owner.
- **Artifact integrity verification before upload:**
  1. Download `totaldrop-windows-store-submission` from the tagged `windows-v*` GitHub Actions run.
  2. Verify `sha256sum -c SHA256SUMS` locally.
  3. Verify GitHub Actions Sigstore OIDC build provenance (`actions/attest-build-provenance`, matching all `6/6` ADR 0020 units with `provenance = "sigstore-oidc"`):
     ```bash
     gh attestation verify TotalDrop-<version>.msixupload --repo totaldrop-app/totaldrop-windows
     ```
- **Store re-signing provenance caveat (Threat Model `T12`):** Microsoft Store re-signs every ingested `.msixbundle` with Microsoft's Store signing certificate. End users installing from Microsoft Store cannot verify the GitHub Actions Sigstore OIDC attestation directly against the Store-re-signed binary on disk; provenance guarantees apply to the CI-built `.msixupload` up to the point of Partner Center upload.

---

## 6. Package Flights Closed Testing & Dual-Arch `.msixbundle` Lock-In from Flight #1

- **Mandatory `.msixbundle` inside `.msixupload` from Flight #1:** Microsoft Store permanently locks a product's package format based on its first published package. Uploading a bare standalone `.msix` in Flight #1 breaks seamless updates when later switching to a multi-architecture `.msixbundle`. Always upload `TotalDrop-<version>.msixupload` containing the dual-arch (`x64` + `ARM64`) `.msixbundle` and `.appxsym` debug symbols from Flight #1 onward.
- **Version and identity invariants:**
  - Monotonic 4-part version `Major.Minor.Build.0` with `1 <= Major <= 65535` and `Revision == 0` (e.g., `1.0.1.0` -> `1.0.2.0`).
  - Zero unsigned-package OID `2.25.311729368913984317654407730594956997722`.
  - Zero signing keys/certificates (`.pfx`, `.p12`, `.cer`, `.snk`, `.key`, `.pem`, `.pvk`, `.pepk`, `.jks`, `.keystore`) inside any archive.
  - Zero `x86` slices (64-bit `x64` and `ARM64` only).
- **Closed Flight #1 verification checklist (Customer Group MSA testers on `x64` + `ARM64`):**
  - [ ] Local WACK (`tools/run-wack.ps1`) reports `OVERALL_RESULT="PASS"` and `0` failed tests.
  - [ ] Clean Store install resolves `Microsoft.WindowsAppRuntime.1.8` automatically.
  - [ ] File Explorer top-level **"Send with TotalDrop"** menu works on single files, multiple files, and folders.
  - [ ] End-to-end file and plain-text transfers succeed across LAN and relay (`x64` <-> `ARM64` / Linux / Android).
  - [ ] `totaldrop://` protocol activation, Windows Share Target, background Toast activation, wake lock (`powercfg /requests`), and Private-network UDP firewall rule creation + clean uninstall removal all pass.
  - [ ] Upgrade test from Flight #1 (`1.0.1.0`) to Flight #2 (`1.0.2.0`) succeeds cleanly via Microsoft Store.

---

## 7. `winget --source msstore <9N...>` Verification & No Community `TotalDrop.TotalDrop` Manifest

- **Post-publish verification:** Once the public Store release propagates to the Microsoft Store catalog, verify clean installation on both Windows 11 `x64` and Windows 11 `ARM64` via:
  ```powershell
  winget show --source msstore <9N...>
  winget install --source msstore <9N...>
  ```
- **Explicit ADR 0016 decision against community `microsoft/winget-pkgs` submission:** TotalDrop will **not** submit a community `TotalDrop.TotalDrop` manifest to `microsoft/winget-pkgs` because TotalDrop distributes exclusively through the Microsoft Store with zero standalone external installer URLs. If an unauthorized third party squats `TotalDrop.TotalDrop` in `microsoft/winget-pkgs`, maintainers enforce trademark rights under ADR 0012.
- **Role of repository-local WinGet manifests:** `target-x86_64/winget/app.totaldrop.TotalDrop.x64.yaml` and `target-arm64/winget/app.totaldrop.TotalDrop.arm64.yaml` are repository-local ADR 0020 metadata mirrors for CI schema/version checks and internal documentation only; they are not submitted to `microsoft/winget-pkgs`.
