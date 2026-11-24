<!-- SPDX-FileCopyrightText: 2026 The TotalDrop Contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Microsoft Store Certification Notes (Ready to Paste into Partner Center)

Paste the sections below directly into **Partner Center -> Submission -> Submission options -> Notes for certification**.

Related documentation:
- Master release & ADR 0016 Step 6 runbook: [docs/microsoft-store-release.md](microsoft-store-release.md)
- Pre-submission Partner Center governance checklist: [docs/partner-center-checklist.md](partner-center-checklist.md)

---

## 1. Restricted Capability Justification: `rescap:runFullTrust` (Microsoft Store Policy 10.6)

TotalDrop is a free, open-source (`GPL-3.0-or-later`), end-to-end encrypted peer-to-peer file and plain-text transfer application for Windows 11 (`x64` and `ARM64`), built with WinUI 3 (`.NET 10` Native AOT) and a native Rust transfer and cryptography engine (`totaldrop_windows_ffi.dll`, where all cryptographic, protocol, and core transfer crates enforce `#![forbid(unsafe_code)]`).

TotalDrop declares `<rescap:Capability Name="runFullTrust" />` strictly because of four required desktop integration capabilities that are unavailable inside an AppContainer sandbox:

1. **Direct user-selected file/folder streaming and atomic BLAKE3-verified writes:** Users pick arbitrary files and nested directories via native Windows pickers, drag-and-drop, Share Target, or File Explorer, including extended-length paths exceeding `260` UTF-16 code units (`\\?\` and `\\?\UNC\` paths). Received files are streamed directly into the user's chosen destination folder (defaulting to `Downloads\TotalDrop` via `SHGetKnownFolderPath(FOLDERID_Downloads)`) using temporary files verified with BLAKE3 before atomic rename without overwriting existing files.
2. **Packaged File Explorer top-level context menu (`IExplorerCommand` COM Surrogate):** TotalDrop ships an in-package native Rust COM shell extension (`totaldrop_explorer_ext.dll`, CLSID `{8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0}`, registered via `<com:SurrogateServer>` and `<desktop4:FileExplorerContextMenus>` for `*` and `Directory`) providing the Windows 11 top-level **"Send with TotalDrop"** verb. Selections are handed off to the running single-instance window over a session-local `PipeOptions.CurrentUserOnly` Named Pipe (`\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.<SessionId>`) parsed strictly in Rust.
3. **Prerequisite for `desktop2:FirewallRules`:** Windows MSIX packaging requires `runFullTrust` to register a package-scoped inbound UDP firewall rule for direct local-network QUIC peer connectivity.
4. **Transparent privilege boundary:** TotalDrop runs exclusively at standard user **Medium Integrity Level (`asInvoker`)** — it never requests administrator elevation (UAC), never installs kernel drivers or Windows services, never modifies system files or registry startup keys, and terminates completely with zero background persistence when closed. Because it uses `runFullTrust`, it runs outside an AppContainer sandbox.

---

## 2. Scoped Windows Firewall Rule Disclosure: `desktop2:FirewallRules`

To allow direct peer-to-peer QUIC transfers over the user's local Wi-Fi or Ethernet network without falling back to an encrypted relay server, TotalDrop declares a single minimally scoped package-level firewall rule in `AppxManifest.xml`:

```xml
<desktop2:Extension Category="windows.firewallRules">
  <desktop2:FirewallRules Executable="totaldrop-winui.exe">
    <desktop2:Rule
      Direction="in"
      IPProtocol="UDP"
      Profile="private" />
  </desktop2:FirewallRules>
</desktop2:Extension>
```

- **Minimal attack surface:** Permits **inbound UDP only** to `totaldrop-winui.exe` on **Private networks only** (`Profile="private"`). Zero Public-network rules, zero Domain-network rules, and zero TCP listening rules are declared.
- **Automatic lifecycle management:** Windows installs the rule atomically with the MSIX package and removes it completely upon uninstall.
- **End-to-end encryption:** Every transfer performs a PAKE (`CPace`) + post-quantum hybrid (`Noise XXpsk3` + `ML-KEM-768`) handshake verified by 4 human-readable English words before any file metadata or payload is sent.

---

## 3. Zero-Account Reviewer Test Walkthrough (Microsoft Store Policy 10.3)

TotalDrop requires **no account, no login, no credentials, no phone number, no email address, no subscription, and no in-app purchase**.

### Option A — Full Two-Device End-to-End Transfer Test
1. Install TotalDrop on the Windows 11 test PC and install TotalDrop (Windows, Linux, Android, or CLI) on a second device on the same network or over the internet.
2. **Send files:** On the Windows 11 PC, open **Send**, choose any test file or folder (or drag and drop it onto the Send card), and click **Create code**. Note the generated transfer code (e.g., `7-harbor-rocket`).
3. **Receive files:** On the second device, open **Receive**, enter the transfer code, and connect. Confirm that both devices display the **same 4 English verification words**, then click **Accept** on the receiver. Confirm the file arrives intact in `Downloads\TotalDrop` (or the chosen destination folder).
4. **Plain-text transfer:** Switch to **Text** mode on **Send**, type a short message, create a code, connect from the receiver, verify the 4 matching English words, and accept. Confirm the text appears in memory with a **Copy** button and is never written to disk automatically.
5. **Decline / Cancel:** Start another transfer and verify **Decline** (on receiver) or **Cancel** (with confirmation dialog on sender) cleanly aborts the session and returns both devices to idle.

### Option B — Single-PC Functional Inspection (No Second Device Required)
1. **Launch & theming:** Launch TotalDrop from the Start menu and verify Fluent 2 layout in Light, Dark, and High Contrast themes.
2. **File Explorer context menu:** Right-click any file or folder in Windows 11 File Explorer and click **"Send with TotalDrop"** directly in the top-level menu. Confirm TotalDrop opens (or focuses its single window) on the **Send** view with the selected items queued.
3. **Protocol URI handling:** Open `totaldrop://r/7-harbor-rocket` from `Win+R` or a browser. Confirm TotalDrop focuses the **Receive** view with the validated code pre-filled without auto-dialing the network until the user clicks **Connect**.
4. **Settings & Privacy Mode:** Open **Settings** from the navigation footer. Verify the default rendezvous server (`wss://rendezvous.totaldrop.app`), inspect the **Privacy mode** toggle confirmation dialog, and confirm settings persist locally in `%LOCALAPPDATA%\TotalDrop\settings.json`.

---

## 4. Explicit No-Self-Updater Statement (Microsoft Store Policy 10.2.1 & ADR 0016)

TotalDrop contains **zero self-updating logic**:
- It has no built-in auto-updater, no background update-check task, and no code path that downloads or executes external binaries, installers, or scripts.
- All application updates and `Microsoft.WindowsAppRuntime.1.8` framework updates are delivered exclusively through the Microsoft Store.

---

## 5. Privacy & Contact Summary (Microsoft Store Policy 10.5)

- **Privacy Policy URL:** `https://totaldrop.app/privacy/` (available in 35 languages)
- **Support Contact:** `hello@totaldrop.app`
- **Local storage only:** Received files are written only to the user-selected destination folder (`Downloads\TotalDrop` by default); user settings are stored strictly locally in `%LOCALAPPDATA%\TotalDrop\settings.json` and are never cloud-synced.
- **Zero tracking:** TotalDrop collects zero analytics, zero crash telemetry, zero advertising identifiers, and zero account data.
