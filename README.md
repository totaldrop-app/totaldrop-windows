# TotalDrop for Windows 11 (`06-windows`)

<!-- SPDX-FileCopyrightText: 2026 The TotalDrop Contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

Native Windows 11 desktop client, File Explorer `IExplorerCommand` shell integration, and isolated `x86_64` / `ARM64` MSIX packaging targets for **TotalDrop**, implementing **ADR 0016** (*Windows App Built with WinUI 3 and Distributed via Microsoft Store*), **ADR 0008** (*35 Languages & Regional Formatting*), and **ADR 0019** (*English by Default*).

---

## Architecture Overview

TotalDrop's invariant across every platform is strict: **protocol state machines, CPace PAKE, XChaCha20-Poly1305 authenticated channels, QUIC/relay transport, path safety, and ICU localization live exclusively in shared pure-Rust crates (`crates/*`)**. The Windows shell performs zero cryptography and never blocks the UI thread on transfer I/O.

```text
06-windows/
├── Cargo.toml                           # Rust 2024 (1.99, resolver = "3") workspace with strict safety lints
├── crates/
│   ├── totaldrop-crypto/                # CPace Ristretto255 PAKE, Ed25519 identity, XChaCha20-Poly1305
│   ├── totaldrop-proto/                 # Wire messages, 2048-word TransferCode & totaldrop:// link grammar
│   ├── totaldrop-core/                  # QUIC + relay transport, framing, pairing, path traversal guards
│   ├── totaldrop-l10n/                  # Compile-time ARB -> ICU4X message & regional number/percent engine
│   ├── totaldrop-windows-bridge/        # Pure-Rust Windows 11 bridge: URI validation, Explorer IPC, 35-lang UI
│   ├── totaldrop-windows-ffi/           # Thin C ABI cdylib boundary (totaldrop_windows_ffi.dll)
│   └── totaldrop-explorer-ext/          # Pure-Rust IExplorerCommand COM server (totaldrop_explorer_ext.dll)
├── ui-winui3-fluent2/                   # 100% native WinUI 3 (Windows App SDK 1.8+) + C# 14 (.NET 10 Native AOT)
│   ├── TotalDrop.WinUI.csproj           # net10.0-windows10.0.26100.0, PublishAot=true, CsWinRT, x64;ARM64
│   ├── App.xaml(.cs)                    # Single-instance Named Pipe IPC, totaldrop:// URI & Share Target activation
│   ├── MainWindow.xaml(.cs)             # MicaBackdrop + DesktopAcrylic fallback, live Accent & High Contrast
│   ├── Views/SendPage.xaml(.cs)         # Fluent 2 drag-and-drop card, wormhole code, Narrator UIA semantics
│   ├── Views/ReceivePage.xaml(.cs)      # Code input, verification words, regional floor-rounded progress bar
│   ├── ViewModels/TransferViewModels.cs # Reflection-free x:Bind observable view models
│   ├── Interop/NativeBridge.cs          # LibraryImport source-generated C ABI P/Invoke bindings (zero Marshal)
│   └── ExplorerExtension/               # Windows 11 File Explorer COM registration & handoff architecture notes
├── target-x86_64/                       # Isolated Intel/AMD x64 target unit (x86_64-pc-windows-msvc)
│   ├── cargo-config.toml                # +crt-static notes, AVX2 / PCLMUL crypto acceleration profile
│   ├── Package.x64.appxmanifest         # ProcessorArchitecture="x64", totaldrop://, FileExplorerContextMenus
│   ├── build-x64.ps1                    # Rust release + .NET Native AOT win-x64 + MakeAppx x64 MSIX pipeline
│   └── winget/app.totaldrop.TotalDrop.x64.yaml
└── target-arm64/                        # Isolated Snapdragon X / Copilot+ ARM64 target unit (aarch64-pc-windows-msvc)
    ├── cargo-config.toml                # ARMv8-A NEON + PMULL crypto profile for Windows 11 on ARM
    ├── Package.arm64.appxmanifest       # ProcessorArchitecture="arm64" native ARM64 Explorer COM registration
    ├── build-arm64.ps1                  # Rust release + .NET Native AOT win-arm64 + dual-arch .msixbundle
    └── winget/app.totaldrop.TotalDrop.arm64.yaml
```

---

## Key Engineering Decisions (ADR 0016)

### 1. WinUI 3 + C# 14 `.NET 10 Native AOT` (`PublishAot=true`)

- **Why WinUI 3 instead of Qt or Flutter:** Per TotalDrop's platform design rules, desktop apps use the operating system's own toolkit so system theme behavior is exact rather than emulated. WinUI 3 (Windows App SDK 1.8+) provides authentic Windows 11 `MicaBackdrop` (with `DesktopAcrylicBackdrop` fallback when Mica is unavailable), custom `TitleBar` integration (`ExtendsContentIntoTitleBar`), live Windows system Accent Color tracking, `AccessibilitySettings.HighContrast` adaptation, `Segoe UI Variable` typography, and native UI Automation trees for Windows Narrator and NVDA.
- **Zero JIT, zero reflection:** `TotalDrop.WinUI.csproj` compiles directly to native machine code (`PublishAot=true`, `CsWinRT`, `LibraryImport` source generation, and compile-time `x:Bind` bindings—no reflection `{Binding}`), avoiding a separate `.NET` runtime dependency and delivering instant cold startup from File Explorer right-click invocations.
- **Reduced motion (`UISettings.AnimationsEnabled`):** `totaldrop_windows_bridge::should_animate_mark` binds the TotalDrop corner mark (`Kose`) animation directly to Windows *Settings -> Accessibility -> Visual effects -> Animation effects*. When disabled—or when no active transfer is in flight—the mark rests cleanly with zero animation frames.

### 2. Why `x64` and `ARM64` `explorer.exe` Require Native COM Isolation

Windows 11's modern top-level right-click menu (**"Send with TotalDrop"**) is powered by an `IExplorerCommand` COM server (`CLSID {8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0}`) declared through `desktop4:FileExplorerContextMenus` and `com:Extension` inside the MSIX package identity:

1. **No cross-architecture in-proc DLL loading:** On Intel/AMD PCs, `explorer.exe` is an `x86_64` process; on Snapdragon X / Copilot+ ARM64 PCs, `explorer.exe` is a native `ARM64` process. Windows cannot load an `x64` in-proc COM DLL into an `ARM64` `explorer.exe` (or vice versa)—doing so fails with `REGDB_E_CLASSNOTREG` and silently drops the context-menu verb on Windows on ARM.
2. **No managed runtime inside `explorer.exe`:** Loading a managed CLR or heavy UI runtime in-process inside the user's shell risks DLL version conflicts, GC pauses on right-click, and shell crashes.
3. **Minimal native COM binary per architecture:** Each target (`target-x86_64/` and `target-arm64/`) compiles a tiny, dependency-free native `totaldrop_explorer_ext.dll` matching the host ABI (`x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`). Its sole job is reading `IShellItemArray` (`SIGDN_FILESYSPATH`) and handing the selection off out-of-process to `totaldrop-winui.exe`.

### 3. Safe Multi-File Explorer Handoff & Extended-Length `\\?\` Paths

`crates/totaldrop-windows-bridge/src/activation.rs` eliminates three classic Windows shell vulnerabilities and limits:

- **Zero `cmd.exe` / `ShellExecute` string concatenation:** Command-line arguments are encoded strictly with `CommandLineToArgvW`-exact escaping (`quote_win32_arg` / `split_win32_command_line`), so filenames containing spaces, quotes, `&`, `|`, `%TEMP%`, `$()`, backslashes, or non-BMP Unicode scalars can never trigger shell command injection.
- **No `MAX_PATH` (260 UTF-16 code units) ceiling:** Standard drive (`C:\...`), UNC (`\\server\share\...`), and Win32 extended-length (`\\?\C:\...` and `\\?\UNC\server\share\...`) paths up to 32,767 UTF-16 code units are validated, normalized for display vs. Win32 `CreateFileW` extended access (`to_extended_length_path`), and checked against embedded NULs, ASCII control characters, reserved DOS device names (`CON`, `NUL`, `COM1`, `LPT1`, ...), and Win32 device namespace escapes (`\\.\PhysicalDrive0`).
- **No `CreateProcessW` 32,767-character truncation:** `plan_explorer_invocation` uses direct `--explorer-send` argv below a conservative 30,000 UTF-16 code-unit budget (`MAX_COMMAND_LINE_UTF16`) for small selections, and automatically upgrades large multi-file selections (hundreds or thousands of files) to single-instance Named Pipe IPC (`\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.<SessionId>`) carrying a versioned, 4-byte little-endian length-prefixed JSON `ActivationEnvelope` (capped at 4 MiB).

### 4. 35 Languages, Regional Percent Floor-Rounding (`#483`), and Bidi Safety

`crates/totaldrop-windows-bridge/src/l10n.rs` builds directly on `totaldrop-l10n` (`l10n/app/*.arb`, single source of truth per ADR 0008):

- **35 localized languages + Explorer verbs:** Negotiates Windows `ApplicationLanguages` BCP-47 preference lists across all 35 supported TotalDrop languages (`ar`, `bn`, `cs`, `da`, `de`, `el`, `en`, `es`, `fa`, `fi`, `fr`, `he`, `hi`, `hu`, `id`, `it`, `ja`, `ko`, `ms`, `nb`, `nl`, `pl`, `pt-BR`, `pt-PT`, `ro`, `ru`, `sv`, `sw`, `th`, `tr`, `uk`, `ur`, `vi`, `zh-Hans`, `zh-Hant`) and generates the complete 35-language **"Send with TotalDrop"** (`desktopSendWith`) catalog for `IExplorerCommand::GetTitle` and MSIX PRI resources.
- **Regional formatting decoupled from UI language (`#483`):** Windows allows pairing any display language with an independent regional format (for example, English UI with Türkiye region `en-TR` or Germany region `en-DE`). `WindowsLocalizer` uses ICU4X `LocaleExpander` over `und-<Region>` so percentage placement and decimal separators follow the user's region (`%50` and `1,0 MB` in `tr-TR`, `50 %` in `de-DE`, `50%` in `en-US`). Transfer progress uses integer floor division (`done * 100 / total`) so `999,999 / 1,000,000` bytes reports `99%`—never prematurely displaying `100%` before cryptographic verification finishes.
- **RTL layout & bidirectional spoofing defense:** Right-to-left scripts (`ar`, `fa`, `he`, `ur`) switch the WinUI 3 root to `FlowDirection.RightToLeft`, while transfer codes, `totaldrop://` URIs, and PAKE verification words remain wrapped in Unicode First Strong Isolate (`U+2068 ... U+2069`) left-to-right runs. Peer-supplied filenames strip `U+202E` (`RLO`) and related bidi override controls (`sanitize_peer_filename`) so `invoice\u{202E}gpj.exe` cannot masquerade as `.jpg` in WinUI cards or toast notifications.

---

## Microsoft Store & MSIX Distribution Model (ADR 0016)

- **Store-signed `.msixbundle` (`x64` + `ARM64`):** Both isolated architecture units (`target-x86_64/` and `target-arm64/`) are built on standard GitHub Actions Windows runners (`windows-2025` for `x64`, `windows-11-arm` for `ARM64`) and bundled into a single `.msixbundle` / `.msixupload`. Microsoft Store re-signs the certified MSIX with Microsoft's Store certificate, eliminating recurring OV/EV code-signing fees and SmartScreen reputation warnings; `winget` installs from the `msstore` source using the same signed Store package.
- **Security & capability boundary (`runFullTrust`):** As documented in ADR 0016, packaged WinUI 3 desktop apps declare `rescap:runFullTrust` and execute with the interactive user's standard desktop token rather than an AppContainer sandbox. Build provenance attestations cover the CI-built `.msixupload` and inner binaries prior to Store re-signing.
- **Firewall rule:** Both `Package.x64.appxmanifest` and `Package.arm64.appxmanifest` declare `desktop2:FirewallRules` scoped strictly to `totaldrop-winui.exe` over UDP on the `Private` profile for direct LAN QUIC peer discovery without unnecessary public-network exposure.

---

## Verification

Run the full Rust workspace formatting check, unit test suite, and strict Clippy lints (`unsafe_code = "forbid"`, `-D warnings`):

```bash
RUSTUP_TOOLCHAIN=stable cargo fmt --all -- --check
RUSTUP_TOOLCHAIN=stable cargo test --workspace --locked
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --all-targets --locked -- -D warnings
./tools/check-spdx.sh
```

To build the native Windows `x64` and `ARM64` MSIX packages on Windows 11 / CI runners:

```powershell
# Build isolated x86_64 MSIX (Rust FFI cdylib + .NET 10 Native AOT WinUI 3)
pwsh -NoProfile -File .\target-x86_64\build-x64.ps1

# Build isolated ARM64 MSIX and assemble unified x64+ARM64 .msixbundle
pwsh -NoProfile -File .\target-arm64\build-arm64.ps1 -CreateStoreBundle
```

---

## License

- Shared Rust crates (`crates/totaldrop-*`): `MIT OR Apache-2.0`
- Windows WinUI 3 application, MSIX packaging, and build scripts: `GPL-3.0-or-later`
