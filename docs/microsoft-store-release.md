<!-- SPDX-FileCopyrightText: 2026 The TotalDrop Contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TotalDrop for Windows 11 — Microsoft Store Release & ADR 0016 Step 6 Runbook

This runbook is the authoritative end-to-end maintainer guide for building, verifying, certifying, and publishing **TotalDrop for Windows 11** (`x64` and `ARM64`) exclusively through the **Microsoft Store** (per `totaldrop/docs/kararlar/0016-windows-microsoft-store.md`, `totaldrop-core/docs/decisions/0016-windows-microsoft-store.md`, and ADR 0020).

Companion governance and certification documents:
- Pre-submission Partner Center governance checklist (Policy 10.14, account security, EU DSA, Package Flights): [docs/partner-center-checklist.md](partner-center-checklist.md)
- Ready-to-paste Partner Center reviewer submission notes (`rescap:runFullTrust`, `desktop2:FirewallRules`, zero-account walkthrough, no-self-updater): [docs/store-certification-notes.md](store-certification-notes.md)

---

## 1. Store-Only Release Architecture & Non-Negotiable Contracts

1. **Single distribution channel (ADR 0016):** Windows users install TotalDrop strictly from the Microsoft Store (and via `winget install --source msstore <9N...>`, which delegates directly to the Microsoft Store package). TotalDrop does **not** publish standalone `.exe`/`.msi` installers, does **not** purchase an external EV code-signing certificate, and does **not** include any self-updater or background update checker.
2. **Dual-architecture `.msixbundle` inside `.msixupload` from Flight #1:**
   - Every Store submission (starting at the very first closed Package Flight) MUST upload a `.msixupload` archive containing ONE unified dual-architecture `TotalDrop-<version>.msixbundle` (`x64` + `arm64`, zero `x86`) and its `.appxsym` PDB symbol archives (`totaldrop-winui.pdb`, `totaldrop_windows_ffi.pdb`, `totaldrop_explorer_ext.pdb`).
   - Microsoft Store enforces an irreversible format lock-in: once a product publishes a standalone `.msix`, it cannot cleanly migrate existing installations to a `.msixbundle` (and vice versa). Always ship `.msixbundle` inside `.msixupload` from Flight #1.
   - Never pack bare `.msix` packages at the root of `.msixupload` and never include signing keys/certificates (`.pfx`, `.p12`, `.cer`, `.snk`, `.key`, `.pem`, `.pvk`, `.pepk`, `.jks`, `.keystore`) or raw `.pdb`/`.resw` files inside `.msix` or `.msixbundle`.
3. **Store MSIX version projection (`Major >= 1`, `Revision == 0`):**
   - Local development and CI test builds use MSIX version `0.1.1.0` (`Major == 0`) alongside application SemVer `0.1.0-beta.1` and core crate SemVer `0.2.0-beta.5`.
   - Microsoft Store strictly rejects `Major == 0` and reserves the 4th component (`Revision`) for Store re-signing (`Revision` MUST be `0`).
   - Store builds MUST use a monotonically increasing 4-part uint16 quad `Major.Minor.Build.0` where `1 <= Major <= 65535`, `0 <= Minor,Build <= 65535`, and `Revision == 0` (for example `1.0.1.0`, `1.0.2.0`, `1.1.0.0`).
   - The unsigned-package OID `2.25.311729368913984317654407730594956997722` is unconditionally forbidden in all manifests, scripts, and Store packages.
4. **CI build provenance vs. Microsoft Store re-signing boundary:**
   - Tagged `windows-v*` builds on GitHub Actions emit `SHA256SUMS` and Sigstore OIDC build provenance attestations (`actions/attest-build-provenance`, `totaldrop-windows-<version>.sigstore.json`) covering `TotalDrop-<version>.msixbundle` and `TotalDrop-<version>.msixupload`.
   - Microsoft Store strips any prior signature and re-signs the package with Microsoft's Store signing certificate during ingestion. Consequently, end users cannot verify the GitHub Actions Sigstore attestation directly against the Store-re-signed binary installed by Windows; the Partner Center account is the single point of trust for Store delivery (see [docs/partner-center-checklist.md](partner-center-checklist.md) Section 3 & Section 5).

---

## 2. Pre-Flight Local & CI Verification Gates

Before tagging a release or uploading a `.msixupload` to Partner Center, verify every local and CI gate passes with zero errors:

```bash
# Rust workspace formatting, strict lints, and unit/FFI/COM tests
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

# SPDX headers & REUSE 3.3 license compliance
./tools/check-spdx.sh

# Repository version alignment & Store MSIX version guard
python3 tools/check-versions.py
python3 tools/check-versions.py --store-version 1.0.1.0

# Store-projected manifest + identity guard (once Partner Center identity is committed)
python3 tools/check-versions.py --store --require-store-identity

# Deterministic 46 Köşe visual assets, 35-locale .resw parity, and 6 ADR 0020 subplatform units
python3 tools/render-windows-assets.py --check
python3 tools/check-resw-parity.py --check
python3 tools/verify-subplatforms.py

# Deterministic 35-language Microsoft Store listings & built-in bundle/upload verifier self-tests
python3 tools/generate-store-listings.py --check
python3 tools/verify-msix-artifact.py --self-test-bundle
```

When validating localized desktop screenshots prior to Partner Center upload:

```bash
# Validate a flat shared screenshot directory or per-locale directory tree (>= 1 PNG >= 1366x768 per locale)
python3 tools/generate-store-listings.py --screenshots-dir <path-to-screenshots> --out /tmp/store-listings-check
python3 tools/generate-store-listings.py --validate-file /tmp/store-listings-check/store-listings.json \
  --screenshots-dir <path-to-screenshots> --require-screenshots
```

When verifying a downloaded `.msixbundle` and `.msixupload` from `.github/workflows/windows-release.yml`:

```bash
python3 tools/verify-msix-artifact.py \
  --bundle dist/store/TotalDrop-1.0.1.0.msixbundle \
  --msixupload dist/store/TotalDrop-1.0.1.0.msixupload \
  --expected-version 1.0.1.0 \
  --store-mode
```

For dry-run artifacts built with the temporary `CN=TotalDrop` identity, append `--allow-test-identity` (this still enforces `Major >= 1`, `Revision == 0`, X.500 `CN=` syntax, cross-architecture manifest parity, PE32+ hardening, and zero unsigned OID).

---

## 3. Executing `.github/workflows/windows-release.yml`

`.github/workflows/windows-release.yml` builds both `x64` (`windows-latest`) and `ARM64` (`windows-11-arm`) slices with `SOURCE_DATE_EPOCH=1760000000`, `-StoreMode`, and `-EmitSymbols`, verifies each slice, assembles the unified `.msixbundle` and `.msixupload` via `tools/build-msixbundle.ps1`, verifies `SHA256SUMS`, emits Sigstore OIDC build provenance on `windows-v*` tags, and uploads the `totaldrop-windows-store-submission` artifact.

### 3.1 Dry-Run Verification (`workflow_dispatch`)
Before reserving `"TotalDrop"` in Partner Center (or before tagging `main`), run a dry-run via GitHub Actions **Run workflow**:
- `app_version`: `0.1.0-beta.1`
- `store_msix_version`: `1.0.1.0`
- `identity_name`: *(empty)*
- `publisher`: *(empty)*
- `publisher_display_name`: *(empty)*
- `allow_test_identity`: `true`

This exercises the full dual-architecture `x64` + `ARM64` Native AOT + `MakePri.exe` + strict `makeappx.exe pack` + `makeappx.exe bundle` + `.appxsym` + `.msixupload` + `verify-msix-artifact.py --bundle --msixupload --store-mode --allow-test-identity` pipeline without consuming the 3-month Partner Center reservation clock.

### 3.2 Production Tagged Release (`windows-v*`)
1. Complete the Partner Center Policy 10.14 decision, security hardening, and name reservation steps in [docs/partner-center-checklist.md](partner-center-checklist.md).
2. Open a reviewed PR to `main` (approved by `@sadikkuzu` with 100% green `CI`, including both `windows-x64-msix` and `windows-arm64-msix`) updating:
   - `target-x86_64/Package.x64.appxmanifest` and `target-arm64/Package.arm64.appxmanifest` with exact case-sensitive Partner Center `Identity/@Name`, `Identity/@Publisher` (`CN=<GUID>`), `Properties/PublisherDisplayName`, and monotonic Store `Identity/@Version` (`Major >= 1`, `Revision == 0`).
   - `ui-winui3-fluent2/app.manifest`, `ui-winui3-fluent2/TotalDrop.WinUI.csproj`, `target-x86_64/build-x64.ps1`, and `target-arm64/build-arm64.ps1` to match the release version.
   - All companion version-checked files enforced by `tools/check-versions.py` and `tools/verify-msix-artifact.py`: `crates/totaldrop-windows-ffi/{Cargo.toml,src/lib.rs}`, `crates/totaldrop-explorer-ext/Cargo.toml`, `ui-winui3-fluent2/MainWindow.xaml.cs`, `tools/check-versions.py`, `tools/verify-msix-artifact.py`, `subplatforms/*` (`RECIPE.toml`, `build.sh`, `verify.sh`), `target-*/winget/*.yaml`, and `.github/workflows/{ci,pkg-*}.yml`.
   - Verify both `python3 tools/check-versions.py` and `python3 tools/check-versions.py --store --require-store-identity` exit `0`.
3. Tag the merged `main` commit (`git tag -s windows-v<semver> <main-sha> && git push origin windows-v<semver>`).
4. `windows-release.yml` enforces `git merge-base --is-ancestor "$GITHUB_SHA" origin/main`, confirms the tag matches `TotalDrop.WinUI.csproj <Version>`, runs `check-versions.py --store --require-store-identity`, builds and verifies `TotalDrop-<msix-ver>.msixbundle` and `TotalDrop-<msix-ver>.msixupload`, generates Sigstore OIDC build provenance (`actions/attest-build-provenance`), and uploads `totaldrop-windows-store-submission`.
5. Download `totaldrop-windows-store-submission` on a maintainer workstation, verify `sha256sum -c SHA256SUMS` and `gh attestation verify dist/store/TotalDrop-<msix-ver>.msixupload --repo totaldrop-app/totaldrop-windows`, and run local WACK certification before uploading to Partner Center.

---

## 4. Interactive Windows 11 WACK Certification Gate (`tools/run-wack.ps1`)

Microsoft Store certification runs the Windows App Certification Kit (WACK). Because WACK requires an interactive desktop session (non-Session 0, UAC `EnableLUA == 1`, physical display resolution `>= 1024x768` or `>= 768x1024`), it cannot execute inside headless GitHub Actions runners and MUST be run on a real Windows 11 test machine before uploading to Partner Center:

```powershell
# Run WACK against the unified dual-arch bundle (or an ephemeral self-signed local build)
pwsh -NoProfile -File .\tools\run-wack.ps1 `
  -PackagePath .\dist\store\TotalDrop-1.0.1.0.msixbundle `
  -ReportPath .\dist\store\wack-report.xml

# Re-verify an existing WACK XML report in headless automation / CI
pwsh -NoProfile -File .\tools\run-wack.ps1 `
  -CheckReportOnly `
  -ReportPath .\dist\store\wack-report.xml
```

`tools/run-wack.ps1` automatically:
1. Verifies non-Session 0 interactive desktop, UAC `EnableLUA == 1`, and physical display resolution via Win32 `EnumDisplaySettingsW`.
2. Locates `appcert.exe` via Windows Kits registry `KitsRoot10`, standard SDK paths, or `PATH`.
3. Deletes any stale report, runs `appcert.exe reset` cleanly before `appcert.exe test -appxpackagepath <pkg> -reportoutputpath <xml>`.
4. Parses the XML with DTD processing prohibited (`XmlResolver = $null`, catching `XmlException` cleanly) and fails non-zero unless `<REPORT>` declares a single `OVERALL_RESULT="PASS"` attribute (rejecting missing or duplicate case-variant attributes), at least one `<TEST>` element exists, and every `<TEST>` element supplies exactly one `RESULT` value—either the real Windows 11 `appcert.exe` child `<RESULT><![CDATA[...]]></RESULT>` element or a `RESULT="..."` attribute (rejecting missing or duplicate/conflicting values)—whose trimmed uppercase value is in the explicit allowlist (`PASS`, `NOT APPLICABLE`, `SKIPPED`), printing every non-passing test name and raw result explicitly.

---

## 5. Partner Center 6-Module Submission & Package Flights Procedure

Because Individual Microsoft Partner Center accounts cannot attach a Microsoft Entra ID tenant or use the `msstore` CLI Submission API, maintainers upload `TotalDrop-<version>.msixupload` manually through the Partner Center web portal:

1. **Pricing and availability:** Free (`$0.00`), all markets, standard Microsoft Store license, zero in-app purchases, zero subscriptions, zero ads.
2. **Properties:**
   - Category: *Utilities & tools* (or *Productivity*).
   - Privacy Policy URL: `https://totaldrop.app/privacy/` (35 languages).
   - Support contact: `hello@totaldrop.app`.
   - Website: `https://totaldrop.app`.
3. **Age ratings:** Complete the IARC questionnaire accurately (zero user-generated public feeds, zero purchases, zero location sharing, zero data collection).
4. **Packages:**
   - Upload `TotalDrop-<version>.msixupload` (containing the dual-arch `x64` + `ARM64` `.msixbundle` and `.appxsym` symbols — **never** a bare `.msix`).
   - Verify Partner Center parses both `x64` and `ARM64` slices with `Windows.Desktop`, `MinVersion 10.0.19041.0`, and `Microsoft.WindowsAppRuntime.1.8`.
5. **Store listings (35 verified Microsoft Store languages):**
   - Source all localized fields (`Title`, `ShortDescription`, `Description`, 9 `Features` bullets, 7 `SearchTerms`, `ReleaseNotes`, `PrivacyPolicyUrl`, `SupportContact`) directly from `packaging/store-listings/store-listings.json` / `store-listings.csv` (generated by `tools/generate-store-listings.py`).
   - Start Flight #1 with human-reviewed `en` (`en-us`) and `tr` (`tr`) if staged rollout is preferred, expanding to all 35 verified Store languages before public launch.
   - **Mandatory screenshot rule:** Every configured listing language MUST include at least `1` desktop `.png` screenshot (`1366x768` to `3840x2160`, `<= 50 MiB`, max `10` per language) covering Light mode, Dark mode, and RTL layout (`ar`, `fa`, `he`, `ur`), with zero third-party/OS vendor logos or trademarks.
   - **Policy 10.1 accuracy note (`metainfoAbout`):** TotalDrop's shared cross-platform `l10n/app/app_*.arb` `metainfoAbout` intro string mentions *"share a short code or a QR code"*. Before public Store submission, ensure either QR code rendering is enabled on `SendPage` or a Windows-specific `l10n/` description PR aligns the copy strictly with shipped UI behavior (ADR 0016).
6. **Submission options (Notes for certification):**
   - Paste the complete prepared text from [docs/store-certification-notes.md](store-certification-notes.md) covering `rescap:runFullTrust`, `desktop2:FirewallRules`, zero-account reviewer test steps, and the explicit no-self-updater statement.
7. **Package Flights closed testing -> Public promotion:**
   - Submit Flight #1 to a named Partner Center Customer Group of Microsoft Account (MSA) testers covering both Windows 11 `x64` and Windows 11 `ARM64` (Snapdragon X) devices.
   - Expect up to 3 business days for certification review on `runFullTrust` submissions.
   - Verify clean Store install, File Explorer `"Send with TotalDrop"` context menu, Share Target, `totaldrop://` protocol, Send/Receive file + text transfers, Toast notifications, wake lock (`powercfg /requests`), Private-network firewall rule creation + clean uninstall removal, and Windows Store update transition (`1.0.1.0` -> `1.0.2.0`).
   - Promote the certified `.msixupload` to Public release and confirm `winget install --source msstore <9N...>` installs the Store package cleanly on both `x64` and `ARM64`.

---

## 6. Post-Launch ADR 0016 Step 6 Cross-Repository Ecosystem Sync Runbook

Execute these follow-up pull requests **ONLY AFTER** Microsoft Store certification succeeds and the live Store Product ID (`<9N...>`) and final `PackageFamilyName` are assigned. Never commit placeholder values (`<9N...>` with dummy zeroes, all-zero `PackageFamilyName`, or all-zero `InstallerSha256`) as published Store coordinates.

Every PR below follows standard TotalDrop governance (100% English issue, branch, PR with `--reviewer sadikkuzu`, 100% green CI, `@sadikkuzu` approval before rebase-merge):

### 6.1 `totaldrop-site` (Download, Roadmap, Donate & 35-Language Privacy Policy)
1. **`public/donate/index.html` & `public/i18n/*.json`:** Confirm `don.b4` (retired Windows code-signing certificate cost line) remains absent (`0` occurrences) while `don.b3` (Apple Developer Program) is retained.
2. **`public/download/index.html` & `public/i18n/*.json`:**
   - Replace stale `dl.windows.d` (unsigned/donation-funded warning) with the live Microsoft Store link (`https://apps.microsoft.com/detail/<9N...>`, native `x64` & `ARM64`, and `winget install --source msstore <9N...>`).
   - Add Microsoft Store verification guidance to `dl.verify.v1` across all 35 `public/i18n/*.json` files.
3. **`public/roadmap/index.html` & `public/i18n/*.json`:**
   - Update `rm.x5.d` to remove stale certificate-funding wording and mark Windows 11 Microsoft Store support shipped across all 35 `public/i18n/*.json` files.
4. **`privacy/en.html` & 34 `privacy/<tag>.html` (+ generated `public/privacy.html`, `public/privacy/<tag>.html`):**
   - Bump `privacy/en.html` from `version 7` to `version 8` (updating the date stamp).
   - Add Windows local storage paths (`Downloads\TotalDrop` for received files and `%LOCALAPPDATA%\TotalDrop\settings.json` for local-only settings) and state clearly that Microsoft Store collects installation and usage telemetry under Microsoft's own data-controller responsibility.
   - Update all 34 `privacy/<tag>.html` translations with the matching 12-hex SHA-256 stamp (`<!-- Translated from en.html <hash>. -->`), preserving `code`/`em`/number structural parity enforced by `tools/privacy.mjs`.
5. **Run all `totaldrop-site` validators before opening the PR:**
   ```bash
   node tools/privacy.mjs --write
   node tools/privacy.mjs
   node tools/static-locales.mjs --write
   node tools/static-locales.mjs --check
   node tools/check-i18n.mjs
   ```

### 6.2 `totaldrop` (Threat Model, Design Doc & 35-Language READMEs)
1. **`docs/tehdit-modeli.md` (`T12` and trust boundaries):**
   - Add Microsoft Store to `T12` alongside Google Play, GitHub Releases, and `totaldrop.app`.
   - Document the Store re-signing provenance caveat (GitHub Actions Sigstore OIDC attestations verify the pre-submission `.msixupload`/`.msixbundle` but cannot be verified directly against the Store-re-signed installed binary; Partner Center account custody is the single point of trust).
   - Add an explicit Windows `rescap:runFullTrust` entry stating that the MSIX runs at Medium Integrity Level without an AppContainer filesystem/process sandbox (contrasted with Linux Flatpak isolation in `T15`).
2. **`docs/tasarim.md`:**
   - Add the Windows 11 platform row (WinUI 3 Fluent 2, `MicaBackdrop` -> `DesktopAcrylicBackdrop` -> solid surface fallback, `ExtendsContentIntoTitleBar`, `UISettings`/`AccessibilitySettings`/`ThemeSettings`).
   - Add Windows `ui-winui3-fluent2/Views/SendPage.xaml(.cs)`, `ui-winui3-fluent2/Views/ReceivePage.xaml(.cs)`, and `ui-winui3-fluent2/MainWindow.xaml.cs` (`UISettings.AnimationsEnabled` reduced-motion gate) to the Motion section.
3. **`README.md` & 34 `docs/readme/README.<tag>.md`:**
   - Promote Windows out of `"Coming"` with the live Microsoft Store link (`x64` & `ARM64`) and `winget install --source msstore <9N...>`, translate all 34 READMEs, and validate with zero errors and zero warnings:
     ```bash
     node site/tools/check-readmes.mjs --write <updated-tags...>
     node site/tools/check-readmes.mjs
     ```

### 6.3 `totaldrop-core` (English Architectural Mirrors)
1. **`docs/threat-model.md`:** Mirror the `T12` Microsoft Store channel, Store re-signing provenance caveat, Partner Center single-point-of-trust note, and Windows `rescap:runFullTrust` no-AppContainer note.
2. **`docs/design.md`:** Mirror the Windows 11 platform row and `UISettings.AnimationsEnabled` Motion entry.

### 6.4 `totaldrop-windows` (Post-Certification Metadata Polish)
- Confirm `README.md` and reference manifests in `target-{x86_64,arm64}/winget/app.totaldrop.TotalDrop.{x64,arm64}.yaml` document the live `winget install --source msstore <9N...>` command and real `PackageFamilyName` (while keeping the ADR 0016 decision not to publish a community `microsoft/winget-pkgs` `TotalDrop.TotalDrop` manifest).
