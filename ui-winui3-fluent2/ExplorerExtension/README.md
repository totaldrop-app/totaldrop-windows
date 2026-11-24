<!-- SPDX-FileCopyrightText: 2026 The TotalDrop Contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Windows 11 File Explorer Extension (`IExplorerCommand`) Architecture

TotalDrop's Windows 11 top-level right-click context menu integration (**"Send with TotalDrop"**, ADR 0016) is implemented as a pure-Rust native COM server in [`crates/totaldrop-explorer-ext/`](../../crates/totaldrop-explorer-ext/) (`totaldrop_explorer_ext.dll`).

---

## 1. Why Windows 11 Requires `IExplorerCommand` + MSIX Identity

Starting in Windows 11 (Build 22000+), legacy registry-only `IContextMenu` handlers are relegated behind **"Show more options"** (`Shift+F10`). To appear directly in the modern Fluent 2 primary context menu when a user right-clicks one or more files or folders, an application must:

1. Carry **MSIX package identity** (either a full MSIX package from Microsoft Store — TotalDrop's distribution model per ADR 0016 — or a sparse MSIX external-location package during local unpackaged development).
2. Declare `<desktop4:Extension Category="windows.fileExplorerContextMenus">` paired with `<com:Extension Category="windows.comServer">` in `Package.appxmanifest`, binding file/directory item types (`*`, `Directory`) to the registered COM `CLSID` (`{8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0}`).
3. Implement `IExplorerCommand` (`shobjidl_core.idl`) in a native COM binary (`totaldrop_explorer_ext.dll`).

---

## 2. Why `x86_64` and `ARM64` `explorer.exe` Require Isolated Pure-Rust COM Binaries

### 2.1 Why C# Native AOT Is Not Loaded into `explorer.exe`

Per ADR 0016, `totaldrop-winui.exe` uses C# 14 with `.NET 10 Native AOT` calling `totaldrop_windows_ffi.dll`, whereas `totaldrop_explorer_ext.dll` is a tiny, zero-runtime pure-Rust COM `cdylib` (`crates/totaldrop-explorer-ext`, built directly on locked `windows-sys 0.61.2` + explicit `#[repr(C)]` COM vtables + `totaldrop-windows-bridge`, with static CRT `+crt-static` and embedded Köşe icon resource ID `101`):

- An in-proc shell extension is mapped into `explorer.exe` (or its COM surrogate `dllhost.exe`) whenever the user right-clicks a file.
- A managed `.NET Native AOT` DLL embeds its own GC, thread pool, and static runtime state that **cannot safely unload** when `explorer.exe` calls `DllCanUnloadNow()` + `FreeLibrary()`.
- Any unhandled fault inside `explorer.exe` crashes the entire Windows desktop shell and taskbar. Keeping the COM server memory-safe in Rust with `catch_unwind` at every `extern "system"` boundary, `unsafe_op_in_unsafe_fn = "deny"`, and `clippy::undocumented_unsafe_blocks = "deny"` eliminates C++ memory-safety hazards and eliminates runtime startup stalls on right-click.

### 2.2 Strict Per-Architecture (`x64` vs `ARM64`) Process ABI Boundary

Windows enforces strict machine-architecture matching for COM servers loaded by `explorer.exe`:

| Host Machine | `explorer.exe` Image Machine | Required COM Binary | Why Cross-Architecture Fails |
| --- | --- | --- | --- |
| Windows 11 x64 (Intel / AMD) | `IMAGE_FILE_MACHINE_AMD64` (`0x8664`) | `totaldrop_explorer_ext.dll` (`x86_64-pc-windows-msvc`) | A 64-bit `x64` process cannot `LoadLibrary` an `ARM64` or `x86` DLL (`ERROR_BAD_EXE_FORMAT`). |
| Windows 11 on ARM (Snapdragon X Copilot+ PCs) | `IMAGE_FILE_MACHINE_ARM64` (`0xAA64`) | `totaldrop_explorer_ext.dll` (`aarch64-pc-windows-msvc`) | Native `ARM64` `explorer.exe` refuses pure `x64` in-proc COM DLLs (`REGDB_E_CLASSNOTREG`) unless packaged as native `ARM64` or bounced through an emulated out-of-proc surrogate. |

TotalDrop solves both cleanly by building **isolated per-architecture MSIX packages** (`target-x86_64/Package.x64.appxmanifest` with `ProcessorArchitecture="x64"` and `target-arm64/Package.arm64.appxmanifest` with `ProcessorArchitecture="arm64"`) bundled into a single `.msixbundle` for Microsoft Store:

- On Intel/AMD PCs, Windows Store installs ONLY the `x64` slice (`totaldrop-winui.exe` + `totaldrop_windows_ffi.dll` + `totaldrop_explorer_ext.dll`, all pure `x86_64`).
- On Snapdragon X Copilot+ PCs, Windows Store installs ONLY the `arm64` slice (all three binaries compiled natively for `aarch64-pc-windows-msvc`, zero Prism emulation).
- Both manifests register `<com:SurrogateServer>` with XSD-valid **`ThreadingModel="STA"`** (`ComManifestSchema.xsd` `ST_ThreadingModel`), protecting `explorer.exe` stability while remaining strictly valid under `makeappx.exe pack` (without `/nv`).

---

## 3. Sparse / Full MSIX Registration Layout

```xml
<Extensions>
  <!-- 1. Out-of-proc surrogate COM server registration (XSD-valid ThreadingModel="STA") -->
  <com:Extension Category="windows.comServer">
    <com:ComServer>
      <com:SurrogateServer DisplayName="TotalDrop Explorer Verb Host">
        <com:Class
            Id="8f6e3d72-4b9a-4e1c-9d3a-7c2f5a81e4b0"
            Path="totaldrop_explorer_ext.dll"
            ThreadingModel="STA" />
      </com:SurrogateServer>
    </com:ComServer>
  </com:Extension>

  <!-- 2. Windows 11 top-level File Explorer context menu binding -->
  <desktop4:Extension Category="windows.fileExplorerContextMenus">
    <desktop4:FileExplorerContextMenus>
      <desktop5:ItemType Type="*">
        <desktop5:Verb Id="TotalDropSendFiles" Clsid="8f6e3d72-4b9a-4e1c-9d3a-7c2f5a81e4b0" />
      </desktop5:ItemType>
      <desktop5:ItemType Type="Directory">
        <desktop5:Verb Id="TotalDropSendFolder" Clsid="8f6e3d72-4b9a-4e1c-9d3a-7c2f5a81e4b0" />
      </desktop5:ItemType>
    </desktop4:FileExplorerContextMenus>
  </desktop4:Extension>
</Extensions>
```

---

## 4. Safe Multi-File Selection Handoff (`IShellItemArray` -> `totaldrop-winui.exe`)

When `IExplorerCommand::Invoke(IShellItemArray *psiItemArray, IBindCtx *)` fires:

1. Enumerates `psiItemArray->GetCount(&count)` (bounded to `MAX_SELECTION_ITEMS = 10,000`; `10,001` items immediately returns `HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW)` / `0x8007006F`).
2. Extracts each item's filesystem path via `IShellItem::GetDisplayName(SIGDN_FILESYSPATH, &pszPath)` with guaranteed `CoTaskMemFree` and `IShellItem::Release`.
3. Passes the UTF-8 paths to `totaldrop_windows_bridge::activation::ActivationEnvelope::explorer_send`:
   - Normalizes every drive (`C:\...` -> `\\?\C:\...`) and UNC share (`\\server\share\...` -> `\\?\UNC\server\share\...`) path to bypass legacy 260-char `MAX_PATH`.
   - Rejects Win32 raw device namespaces (`\\.\`, `CON`, `LPT1`), NTFS Alternate Data Streams (`file.txt:stream`), and `..` traversal.
   - Deduplicates case-insensitively while preserving Explorer's selection order.
4. Selects transport:
   - **Warm window already listening:** streams a 4-byte little-endian length-prefixed schema-v1 `ActivationEnvelope` frame over `\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.<SessionId>` directly into the primary window's Rust `WinUiWindowRouter`.
   - **Cold start (`plan_explorer_invocation`):** uses direct `CreateProcessW(lpApplicationName = "...\\totaldrop-winui.exe", lpCommandLine = "... --explorer-send -- ...")` with `CommandLineToArgvW`-exact escaping (`<= 30,000` UTF-16 code units, **never** `cmd.exe` or `ShellExecute`), or upgrades oversized selections to `--ipc-await` + Named Pipe IPC.
5. `IExplorerCommand::GetTitle` queries `GetThreadPreferredUILanguages` (with user/system MUI fallback) and resolves **"Send with TotalDrop"** across all **35 supported TotalDrop languages** via `totaldrop_windows_bridge::l10n::explorer_send_verb`.
6. `IExplorerCommand::GetIcon` returns `<totaldrop_explorer_ext.dll>,-101`, referencing the Köşe `TotalDrop.ico` icon embedded as Win32 `RT_GROUP_ICON` resource ID `101` via `crates/totaldrop-explorer-ext/resources/explorer_ext.rc`.
