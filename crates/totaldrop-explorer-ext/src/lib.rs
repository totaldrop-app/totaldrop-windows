// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure-Rust Windows 11 File Explorer `IExplorerCommand` COM server for
//! TotalDrop (`totaldrop_explorer_ext.dll`, ADR 0016).
//!
//! This crate keeps all selection validation, 35-language Explorer verb title
//! resolution, Named Pipe / `CreateProcessW` transport planning, icon resource
//! formatting, and path helpers strictly cross-platform and unit-testable on
//! both Linux and Windows, while isolating Win32 COM vtables and DLL entry
//! points inside the `#[cfg(windows)]` `com` module.

use totaldrop_windows_bridge::activation::{
    ActivationEnvelope, ActivationError, ExplorerLaunchTransport, MAX_SELECTION_ITEMS,
    plan_explorer_invocation,
};
use totaldrop_windows_bridge::l10n::explorer_send_verb;

#[cfg(windows)]
pub mod com;

/// Canonical COM CLSID for TotalDrop's Windows 11 top-level File Explorer
/// `"Send with TotalDrop"` verb (`{8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0}`).
pub const CLSID_TOTALDROP_EXPLORER_COMMAND_STR: &str = "8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0";

/// Big-endian 128-bit UUID representation of
/// [`CLSID_TOTALDROP_EXPLORER_COMMAND_STR`].
pub const CLSID_TOTALDROP_EXPLORER_COMMAND_U128: u128 = 0x8f6e_3d72_4b9a_4e1c_9d3a_7c2f_5a81_e4b0;

/// Win32 `RT_GROUP_ICON` resource ID embedded into `totaldrop_explorer_ext.dll`
/// by `resources/explorer_ext.rc` (`<dll>,-101`).
pub const ICON_RESOURCE_ID: i32 = 101;

/// Maximum number of selected Explorer items accepted in a single invocation
/// (`10,000`, matching [`MAX_SELECTION_ITEMS`]).
pub const MAX_EXPLORER_SELECTION_ITEMS: usize = MAX_SELECTION_ITEMS;

/// Win32 `ERROR_BUFFER_OVERFLOW` (`111`) converted to `HRESULT` (`0x8007006F`),
/// returned when a selection exceeds [`MAX_EXPLORER_SELECTION_ITEMS`].
pub const HRESULT_ERROR_BUFFER_OVERFLOW: i32 = hresult_from_win32(111);

/// Default English fallback label when no MUI preference list is available.
pub const DEFAULT_EXPLORER_VERB_TITLE: &str = "Send with TotalDrop";

/// Converts a Win32 error code into an `HRESULT` matching Win32's
/// `HRESULT_FROM_WIN32` macro (`FACILITY_WIN32 = 7`).
#[must_use]
pub const fn hresult_from_win32(win32: u32) -> i32 {
    if win32 == 0 {
        0
    } else {
        (0x8007_0000_u32 | (win32 & 0x0000_FFFF)) as i32
    }
}

/// Formats the Windows `IExplorerCommand::GetIcon` resource specifier
/// (`"<module_path>,-101"`).
#[must_use]
pub fn format_icon_resource_spec(module_path: &str) -> String {
    format!("{module_path},-{ICON_RESOURCE_ID}")
}

/// Resolves the sibling `totaldrop-winui.exe` path residing in the same MSIX
/// package directory as `totaldrop_explorer_ext.dll`.
///
/// Preserves drive, UNC, and `\\?\` extended-length prefixes, and returns
/// `None` if `module_path` has no directory separator or is empty.
#[must_use]
pub fn sibling_app_exe_path(module_path: &str) -> Option<String> {
    let trimmed = module_path.trim();
    if trimmed.is_empty() {
        return None;
    }
    let sep_idx = trimmed.rfind(['\\', '/'])?;
    let dir_with_sep = trimmed.get(..=sep_idx)?;
    if dir_with_sep.is_empty() {
        return None;
    }
    Some(format!("{dir_with_sep}totaldrop-winui.exe"))
}

/// Parses a Win32 double-NUL-terminated `REG_MULTI_SZ` / MUI language list
/// UTF-16 buffer (as returned by `GetThreadPreferredUILanguages` or
/// `GetUserPreferredUILanguages`) into ordered BCP-47 language tags.
#[must_use]
pub fn parse_mui_multi_sz(utf16_buf: &[u16]) -> Vec<String> {
    let mut tags = Vec::new();
    for segment in utf16_buf.split(|&unit| unit == 0) {
        if segment.is_empty() {
            break;
        }
        let decoded = String::from_utf16_lossy(segment);
        let trimmed = decoded.trim();
        if !trimmed.is_empty() {
            tags.push(trimmed.to_owned());
        }
    }
    tags
}

/// Resolves the localized Explorer context-menu verb title across all 35
/// supported TotalDrop languages (`desktopSendWith`), falling back to
/// [`DEFAULT_EXPLORER_VERB_TITLE`] if empty.
#[must_use]
pub fn resolve_verb_title<I, S>(preferred_tags: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let entry = explorer_send_verb(preferred_tags);
    if entry.title.trim().is_empty() {
        DEFAULT_EXPLORER_VERB_TITLE.to_owned()
    } else {
        entry.title
    }
}

/// Validates raw filesystem paths collected from `IShellItemArray` and builds a
/// schema-v1 [`ActivationEnvelope`] for Explorer Send.
///
/// Enforces [`MAX_EXPLORER_SELECTION_ITEMS`] (`10,000`) immediately before path
/// parsing so oversized selections fail deterministically with
/// [`ActivationError::TooManyItems`].
///
/// # Errors
///
/// Returns [`ActivationError::TooManyItems`] if `raw_paths.len() > 10_000`,
/// [`ActivationError::EmptyExplorerSelection`] if `raw_paths` is empty, or any
/// path validation error from
/// [`totaldrop_windows_bridge::activation::WindowsSelectionPath::parse`].
pub fn prepare_explorer_envelope(
    raw_paths: &[String],
    initiator_pid: Option<u32>,
) -> Result<ActivationEnvelope, ActivationError> {
    if raw_paths.len() > MAX_EXPLORER_SELECTION_ITEMS {
        return Err(ActivationError::TooManyItems {
            count: raw_paths.len(),
        });
    }
    ActivationEnvelope::explorer_send(raw_paths, initiator_pid)
}

/// Validates an Explorer selection and plans the safe transport to
/// `totaldrop-winui.exe` (Named Pipe IPC when a window is open or the command
/// line would exceed `30,000` UTF-16 code units, or direct `CreateProcessW`
/// arguments — never `cmd.exe` or `ShellExecute`).
///
/// # Errors
///
/// Returns [`ActivationError`] if path validation fails, the item count exceeds
/// `10,000`, or the encoded IPC envelope exceeds `4 MiB`.
pub fn plan_invocation(
    exe_path: &str,
    raw_paths: &[String],
    windows_session_id: u32,
    window_already_open: bool,
    initiator_pid: Option<u32>,
) -> Result<ExplorerLaunchTransport, ActivationError> {
    let envelope = prepare_explorer_envelope(raw_paths, initiator_pid)?;
    plan_explorer_invocation(exe_path, &envelope, windows_session_id, window_already_open)
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;

    use totaldrop_windows_bridge::SUPPORTED_LANGUAGES;
    use totaldrop_windows_bridge::activation::{MAX_COMMAND_LINE_UTF16, split_win32_command_line};

    use super::*;

    type TestResult = Result<(), Box<dyn StdError>>;

    #[test]
    fn canonical_clsid_and_hresult_constants_match_contract() {
        assert_eq!(
            CLSID_TOTALDROP_EXPLORER_COMMAND_STR,
            "8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0"
        );
        assert_eq!(
            CLSID_TOTALDROP_EXPLORER_COMMAND_U128,
            0x8f6e_3d72_4b9a_4e1c_9d3a_7c2f_5a81_e4b0
        );
        assert_eq!(ICON_RESOURCE_ID, 101);
        assert_eq!(MAX_EXPLORER_SELECTION_ITEMS, 10_000);
        assert_eq!(HRESULT_ERROR_BUFFER_OVERFLOW as u32, 0x8007_006F);
        assert_eq!(hresult_from_win32(0), 0);
    }

    #[test]
    fn resolves_explorer_verb_across_all_35_languages_and_empty_fallback() {
        assert_eq!(
            resolve_verb_title(std::iter::empty::<&str>()),
            DEFAULT_EXPLORER_VERB_TITLE
        );
        assert_eq!(resolve_verb_title(["en-US"]), "Send with TotalDrop");

        let tr = resolve_verb_title(["tr-TR", "en-US"]);
        assert!(!tr.is_empty());
        assert_ne!(tr, "Send with TotalDrop");

        let ar = resolve_verb_title(["ar-SA"]);
        let ja = resolve_verb_title(["ja-JP"]);
        let zh_hant = resolve_verb_title(["zh-Hant-TW"]);
        assert!(!ar.is_empty());
        assert!(!ja.is_empty());
        assert!(!zh_hant.is_empty());

        for lang in SUPPORTED_LANGUAGES {
            let resolved = resolve_verb_title([lang]);
            assert!(
                !resolved.trim().is_empty(),
                "empty explorer verb title for locale {lang}"
            );
        }
    }

    #[test]
    fn enforces_10000_item_cap_and_rejects_10001_with_too_many_items() -> TestResult {
        let exact_limit: Vec<String> = (0..10_000)
            .map(|i| format!(r"C:\Users\Alice\f{i}.txt"))
            .collect();
        let env = prepare_explorer_envelope(&exact_limit, Some(77))?;
        assert_eq!(env.initiator_pid, Some(77));

        let mut over_limit = exact_limit;
        over_limit.push(r"C:\Users\Alice\f10000.txt".to_owned());
        let err = prepare_explorer_envelope(&over_limit, Some(77));
        assert!(matches!(
            err,
            Err(ActivationError::TooManyItems { count: 10_001 })
        ));
        Ok(())
    }

    #[test]
    fn switches_from_direct_command_line_to_named_pipe_above_30000_utf16() -> TestResult {
        let exe = r"C:\Program Files\WindowsApps\TotalDrop\totaldrop-winui.exe";

        // Small cold-start selection uses direct CreateProcessW arguments.
        let small = vec![r"C:\Users\Alice\report.pdf".to_owned()];
        let direct = plan_invocation(exe, &small, 1, false, Some(100))?;
        assert!(
            matches!(direct, ExplorerLaunchTransport::DirectCommandLine { .. }),
            "expected DirectCommandLine for compact cold start, got {direct:?}"
        );

        // Warm window ALWAYS upgrades to Named Pipe IPC even for 1 file.
        let warm = plan_invocation(exe, &small, 1, true, Some(100))?;
        match warm {
            ExplorerLaunchTransport::NamedPipeIpc {
                pipe_path,
                cold_start_command_line,
                ipc_frame,
            } => {
                assert_eq!(pipe_path, r"\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.1");
                assert!(cold_start_command_line.contains("--ipc-await"));
                assert!(ipc_frame.len() > 4);
            }
            ExplorerLaunchTransport::DirectCommandLine { .. } => {
                return Err("expected NamedPipeIpc for warm window".into());
            }
        }

        // Large cold-start selection exceeding MAX_COMMAND_LINE_UTF16 upgrades to Named Pipe IPC.
        let large: Vec<String> = (0..450)
            .map(|i| format!(r"C:\Users\Alice\Documents\QuarterlyReports\2026\item_{i:04}_payload_archive_data.bin"))
            .collect();
        let total_chars: usize = large.iter().map(String::len).sum();
        assert!(total_chars > MAX_COMMAND_LINE_UTF16);
        let upgraded = plan_invocation(exe, &large, 2, false, Some(101))?;
        match upgraded {
            ExplorerLaunchTransport::NamedPipeIpc {
                pipe_path,
                cold_start_command_line,
                ipc_frame,
            } => {
                assert_eq!(pipe_path, r"\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.2");
                assert!(cold_start_command_line.contains("--ipc-await"));
                assert!(ipc_frame.len() > 4);
            }
            ExplorerLaunchTransport::DirectCommandLine { .. } => {
                return Err("expected NamedPipeIpc above 30,000 UTF-16 code units".into());
            }
        }
        Ok(())
    }

    #[test]
    fn ntfs_shell_metacharacters_quote_safely_without_cmd_exe() -> TestResult {
        let exe = r"C:\Program Files\WindowsApps\TotalDrop\totaldrop-winui.exe";
        let tricky = vec![r"C:\Users\Alice\R&D (Final) ^ %TEMP% !notes!.txt".to_owned()];
        let transport = plan_invocation(exe, &tricky, 1, false, Some(55))?;
        match transport {
            ExplorerLaunchTransport::DirectCommandLine {
                command_line,
                utf16_len,
            } => {
                assert!(utf16_len <= MAX_COMMAND_LINE_UTF16);
                assert!(!command_line.to_ascii_lowercase().contains("cmd.exe"));
                let argv = split_win32_command_line(&command_line, false)?;
                assert_eq!(argv.first().map(String::as_str), Some(exe));
                assert!(argv.iter().any(|arg| arg == "--explorer-send"));
                assert!(
                    argv.iter()
                        .any(|arg| arg == r"\\?\C:\Users\Alice\R&D (Final) ^ %TEMP% !notes!.txt")
                );
            }
            ExplorerLaunchTransport::NamedPipeIpc { .. } => {
                return Err("expected DirectCommandLine for single tricky path".into());
            }
        }
        Ok(())
    }

    #[test]
    fn formats_icon_resource_spec_and_resolves_sibling_exe_path() {
        assert_eq!(
            format_icon_resource_spec(
                r"C:\Program Files\WindowsApps\TD\totaldrop_explorer_ext.dll"
            ),
            r"C:\Program Files\WindowsApps\TD\totaldrop_explorer_ext.dll,-101"
        );
        assert_eq!(
            sibling_app_exe_path(r"C:\Program Files\WindowsApps\TD\totaldrop_explorer_ext.dll")
                .as_deref(),
            Some(r"C:\Program Files\WindowsApps\TD\totaldrop-winui.exe")
        );
        assert_eq!(
            sibling_app_exe_path(r"\\?\C:\App\totaldrop_explorer_ext.dll").as_deref(),
            Some(r"\\?\C:\App\totaldrop-winui.exe")
        );
        assert_eq!(
            sibling_app_exe_path(r"\\nas01\apps\td\totaldrop_explorer_ext.dll").as_deref(),
            Some(r"\\nas01\apps\td\totaldrop-winui.exe")
        );
        assert_eq!(
            sibling_app_exe_path("C:/App/totaldrop_explorer_ext.dll").as_deref(),
            Some("C:/App/totaldrop-winui.exe")
        );
        assert_eq!(sibling_app_exe_path("totaldrop_explorer_ext.dll"), None);
        assert_eq!(sibling_app_exe_path("   "), None);
    }

    #[test]
    fn parses_win32_mui_multi_sz_buffers() {
        let mut buf: Vec<u16> = Vec::new();
        buf.extend("tr-TR".encode_utf16());
        buf.push(0);
        buf.extend("en-US".encode_utf16());
        buf.push(0);
        buf.push(0);
        // Trailing garbage after double-NUL must be ignored.
        buf.extend("fr-FR".encode_utf16());
        buf.push(0);

        assert_eq!(parse_mui_multi_sz(&buf), vec!["tr-TR", "en-US"]);
        assert!(parse_mui_multi_sz(&[0, 0]).is_empty());
        assert!(parse_mui_multi_sz(&[]).is_empty());
    }
}
