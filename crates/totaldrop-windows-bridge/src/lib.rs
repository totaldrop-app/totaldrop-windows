// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure-Rust Windows 11 bridge for TotalDrop (ADR 0016).
//!
//! TotalDrop's Windows client pairs a **WinUI 3 + .NET Native AOT** shell
//! (`ui-winui3-fluent2/`) and architecture-native **`IExplorerCommand` COM
//! handlers** (`x86_64` and `ARM64`) with TotalDrop's shared Rust core:
//!
//! - [`uri`]: Validates `totaldrop://r/<code>` and
//!   `https://totaldrop.app/r#<code>` protocol links, interactive transfer
//!   codes, and pasted share messages via [`totaldrop_proto::TransferCode`].
//! - [`activation`]: Parses and serializes Windows 11 File Explorer
//!   `IExplorerCommand` multi-file selections, extended-length `\\?\` and
//!   `\\?\UNC\` paths beyond `MAX_PATH` (260 UTF-16 code units), shell-safe
//!   `CommandLineToArgvW` arguments, and length-prefixed Named Pipe single-window
//!   IPC frames.
//! - [`l10n`]: Negotiates all 35 supported TotalDrop languages, provides the
//!   35-language **"Send with TotalDrop"** Explorer context-menu verb catalog,
//!   implements regional floor-rounded transfer percentages (`#483`), and
//!   enforces RTL bidirectional isolation and `U+202E` filename sanitization.
//! - [`ipc_router`]: Coordinates single-window `WindowsActivityState` routing,
//!   streaming Named Pipe `IpcFrameDecoder` framing with pre-allocation size
//!   guards, busy-window collision banners, and newline-delimited JSON
//!   (`ndjson`) `WinUiBridgeMessage` snapshots.
//! - [`session`]: Projects [`totaldrop_core`] options, async send/receive
//!   preparation with [`WindowsCancellationToken`], progress events, errors,
//!   and `Kose` mark motion rules (`UISettings.AnimationsEnabled`) for WinUI 3
//!   `x:Bind` view models.

pub mod activation;
pub mod ipc_router;
pub mod l10n;
pub mod session;
pub mod uri;

pub use activation::{
    ActivationEnvelope, ActivationError, ActivationPayload, ExplorerLaunchTransport,
    NormalizedWindowsPath, ScreenTarget, WindowsRootKind, WindowsSelectionPath, parse_launch_args,
    plan_explorer_invocation, quote_win32_arg, session_named_pipe_path, split_win32_command_line,
    validate_windows_paths,
};
pub use ipc_router::{
    IpcFrameDecoder, MAX_IPC_FRAME_BYTES, RouterDecision, WinUiBridgeMessage, WinUiWindowRouter,
    WindowsActivityState, decode_ndjson_stream, encode_ndjson_batch,
};
pub use l10n::{
    ExplorerVerbEntry, RegionalPercent, SUPPORTED_LANGUAGES, SanitizedPeerText, WinUiFlowDirection,
    WindowsLocalizer, WindowsUiBundle, explorer_send_verb, explorer_verb_catalog,
    format_regional_percent, isolate_bidi, sanitize_peer_filename, sanitize_peer_text,
    whole_percent,
};
pub use session::{
    BridgeNetworkConfig, LocalizedTransferError, MARK_CYCLE_MS, MARK_HEX_DARK, MARK_HEX_LIGHT,
    MARK_QUARTER_MS, MARK_SVG_PATH, TransferViewEvent, WindowsCancellationToken,
    check_windows_destination, connect_windows_receive, prepare_windows_send,
    prepare_windows_text_send, should_animate_mark,
};
pub use uri::{UriValidationError, ValidatedCode, code_word_completions};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error as StdError;

    use totaldrop_core::{Error as CoreError, Event};

    use super::*;

    type TestResult = Result<(), Box<dyn StdError>>;

    #[test]
    fn protocol_uris_and_web_links_validate_strictly() -> TestResult {
        for valid_link in [
            "totaldrop://r/7-harbor-rocket",
            "totaldrop:7-harbor-rocket",
            "https://totaldrop.app/r#7-harbor-rocket",
            "http://totaldrop.app/r#7-harbor-rocket",
            "totaldrop://r/7%20harbor%20rocket",
            "\u{2068}totaldrop://r/7-harbor-rocket\u{2069}",
            "  7-harbor-rocket  ",
        ] {
            let parsed = ValidatedCode::from_activation_uri(valid_link)?;
            assert_eq!(parsed.nameplate, 7);
            assert_eq!(parsed.word_count, 2);
            assert_eq!(parsed.display_english, "7-harbor-rocket");
            assert_eq!(parsed.canonical, "7-840-1499");
            assert_eq!(parsed.protocol_uri, "totaldrop://r/7-harbor-rocket");
            assert_eq!(parsed.web_uri, "https://totaldrop.app/r#7-harbor-rocket");
            assert_eq!(parsed.ltr_isolated, "\u{2068}7-harbor-rocket\u{2069}");
            assert!(!parsed.is_strong());
        }

        let strong = ValidatedCode::from_activation_uri("totaldrop://r/42-zoo-zone-able")?;
        assert_eq!(strong.nameplate, 42);
        assert_eq!(strong.word_count, 3);
        assert!(strong.is_strong());
        Ok(())
    }

    #[test]
    fn untrusted_or_malformed_activation_uris_are_rejected() {
        for bad_link in [
            "https://evil.example/r#7-harbor-rocket",
            "https://totaldrop.app.evil.example/r#7-harbor-rocket",
            "totaldrop://r/7-harbor-rocket?track=1",
            "totaldrop://r/7-harbor-rocket/extra",
            "totaldrop://send/7-harbor-rocket",
            // Double percent-encoding (`%2537` -> `%37`) must NOT decode twice.
            "totaldrop://r/%2537-harbor-rocket",
            r"C:\Users\Alice\7-harbor-rocket.pdf",
        ] {
            assert_eq!(
                ValidatedCode::from_activation_uri(bad_link),
                Err(UriValidationError::InvalidActivationLink),
                "should reject {bad_link:?}"
            );
        }

        assert_eq!(
            ValidatedCode::from_activation_uri("   \u{2068}\u{2069} "),
            Err(UriValidationError::Empty)
        );

        let oversized = format!("totaldrop://r/{}", "a".repeat(1100));
        assert!(matches!(
            ValidatedCode::from_activation_uri(&oversized),
            Err(UriValidationError::LinkTooLong { .. })
        ));
    }

    #[test]
    fn user_input_and_clipboard_extraction_handle_arabic_digits_and_share_text() -> TestResult {
        // Arabic-Indic (`\u{0667}`) and Extended Arabic-Indic (`\u{06F7}`) digits.
        let from_arabic = ValidatedCode::from_user_input("\u{0667} Harbor ROCKET")?;
        let from_persian = ValidatedCode::from_user_input("\u{06F7}-840-1499")?;
        assert_eq!(from_arabic.display_english, "7-harbor-rocket");
        assert_eq!(from_arabic, from_persian);

        // Specific error classification for WinUI 3 inline validation hints.
        assert_eq!(
            ValidatedCode::from_user_input("0-harbor-rocket"),
            Err(UriValidationError::BadNameplate)
        );
        assert_eq!(
            ValidatedCode::from_user_input("7-harbor"),
            Err(UriValidationError::WrongWordCount)
        );
        assert_eq!(
            ValidatedCode::from_user_input("7-harbor-notaword"),
            Err(UriValidationError::UnknownWord {
                word: "notaword".to_owned()
            })
        );

        // Localized share sentence round-trip in an RTL language (Arabic).
        let ar = WindowsLocalizer::new(["ar-EG"], Some("ar-EG"));
        let share_sentence = ar.format_share_text("7-harbor-rocket");
        let extracted = ValidatedCode::from_clipboard_text(&share_sentence)?;
        assert_eq!(extracted.display_english, "7-harbor-rocket");

        // Link embedded inside prose.
        let from_prose = ValidatedCode::from_clipboard_text(
            "Open TotalDrop: (https://totaldrop.app/r#7-harbor-rocket).",
        )?;
        assert_eq!(from_prose.display_english, "7-harbor-rocket");
        Ok(())
    }

    #[test]
    fn extended_length_drive_and_unc_paths_bypass_max_path_260() -> TestResult {
        // Build a deep NTFS path well beyond legacy 260-char MAX_PATH (~420 chars).
        let deep_segment = "quarterly_archive_2026_verified_segment";
        let mut raw_long = String::from(r"D:\Engineering");
        for _ in 0..10 {
            raw_long.push('\\');
            raw_long.push_str(deep_segment);
        }
        raw_long.push_str(r"\design-bundle.tar.zst");
        assert!(raw_long.encode_utf16().count() > 400);

        let parsed_drive = WindowsSelectionPath::parse(&raw_long)?;
        assert_eq!(parsed_drive.root_kind(), WindowsRootKind::Drive);
        assert!(parsed_drive.exceeds_legacy_max_path());
        assert!(
            parsed_drive
                .extended_path()
                .starts_with(r"\\?\D:\Engineering\")
        );
        assert_eq!(parsed_drive.unprefixed_path(), raw_long);

        // Already `\\?\`-prefixed input is idempotent (never `\\?\ \\?\`).
        let reparsed = WindowsSelectionPath::parse(parsed_drive.extended_path())?;
        assert_eq!(reparsed, parsed_drive);

        // Long UNC network share path (`\\fileserver\projects\…` -> `\\?\UNC\fileserver\projects\…`).
        let mut raw_unc = String::from(r"\\nas-corp\shared-builds");
        for _ in 0..8 {
            raw_unc.push('\\');
            raw_unc.push_str(deep_segment);
        }
        raw_unc.push_str(r"\TotalDrop_arm64.msix");
        let parsed_unc = WindowsSelectionPath::parse(&raw_unc)?;
        assert_eq!(parsed_unc.root_kind(), WindowsRootKind::Unc);
        assert!(parsed_unc.exceeds_legacy_max_path());
        assert!(
            parsed_unc
                .extended_path()
                .starts_with(r"\\?\UNC\nas-corp\shared-builds\")
        );
        assert_eq!(parsed_unc.unprefixed_path(), raw_unc);
        Ok(())
    }

    #[test]
    fn dangerous_windows_paths_and_device_namespaces_are_rejected() {
        for forbidden in [
            "",
            "relative\\file.txt",
            "C:drive-relative.txt",
            r"\\.\PhysicalDrive0",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\SAM",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\secret.txt",
            r"C:\Users\Alice\..\Bob\secret.txt",
            r"C:\Users\Alice\CON.txt",
            r"C:\Users\Alice\LPT1",
            r"C:\Users\Alice\report.pdf:Zone.Identifier",
            r"C:\Users\Alice\trailing-dot.",
            r"C:\Users\Alice\trailing-space ",
            "C:\\Users\\Alice\\bad\0null.txt",
            r"\\?\C:\Users/forward-slash-in-verbatim.txt",
        ] {
            assert!(
                WindowsSelectionPath::parse(forbidden).is_err(),
                "path must be rejected: {forbidden:?}"
            );
        }

        // Case-insensitive verbatim device namespaces must return exact DeviceNamespaceForbidden.
        for device_path in [
            r"\\?\globalroot\Device\Harddisk0",
            r"\\?\GlobalRoot\Device\Harddisk0",
            r"\\?\volume{01234567-89ab-cdef-0123-456789abcdef}\secret.txt",
            r"\\?\PIPE\app.totaldrop.TotalDrop",
            r"\\?\pipe\foo",
        ] {
            assert_eq!(
                WindowsSelectionPath::parse(device_path),
                Err(ActivationError::DeviceNamespaceForbidden),
                "expected DeviceNamespaceForbidden for {device_path:?}"
            );
        }
    }

    #[test]
    fn win32_command_line_quoting_prevents_shell_injection_and_round_trips() -> TestResult {
        let tricky_args = [
            r"C:\Program Files\TotalDrop\totaldrop-winui.exe",
            "--explorer-send",
            "--",
            r"\\?\C:\Users\Alice\My Documents\Q4 & Q1 | Report (Final) %PATH% ^100%.pdf",
            r#"\\?\D:\Weird "Quoted" Folder\TrailingSlash\"#,
            r"\\?\UNC\fileserver\share\file with   spaces.zip",
        ];

        let mut quoted_parts = Vec::with_capacity(tricky_args.len());
        for arg in tricky_args {
            quoted_parts.push(quote_win32_arg(arg)?);
        }
        let command_line = quoted_parts.join(" ");
        let decoded_all = split_win32_command_line(&command_line, false)?;
        assert_eq!(decoded_all, tricky_args);

        let decoded_without_exe = split_win32_command_line(&command_line, true)?;
        let expected_tail: Vec<String> = tricky_args
            .iter()
            .skip(1)
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(decoded_without_exe, expected_tail);

        // Embedded NUL or newline is refused before reaching Win32 APIs.
        assert_eq!(
            quote_win32_arg("C:\\bad\nline.txt"),
            Err(ActivationError::ControlCharacter)
        );
        assert_eq!(
            split_win32_command_line("\"unclosed quote", false),
            Err(ActivationError::MalformedCommandLine)
        );
        Ok(())
    }

    #[test]
    fn explorer_multi_file_envelope_deduplicates_and_frames_over_named_pipe() -> TestResult {
        let raw_selection = [
            r"c:\Users\Alice\Desktop\Photo 1.jpg",
            r"C:\Users\Alice\Desktop\photo 1.jpg", // case-insensitive duplicate on NTFS
            r"\\?\D:\Projects\TotalDrop\README.md",
            r"\\nas\team\Specs & Notes (2026).docx",
        ];

        let envelope = ActivationEnvelope::explorer_send(raw_selection, Some(4820))?;
        if let ActivationPayload::ExplorerSend { ref paths } = envelope.payload {
            assert_eq!(paths.len(), 3);
            let first = paths.first().ok_or("missing first path")?;
            assert_eq!(
                first.extended_path(),
                r"\\?\C:\Users\Alice\Desktop\Photo 1.jpg"
            );
        } else {
            return Err("expected ExplorerSend payload".into());
        }

        let frame = envelope.encode_ipc_frame()?;
        let decoded = ActivationEnvelope::decode_ipc_frame(&frame)?;
        assert_eq!(decoded, envelope);

        // Truncated or tampered length header fails cleanly without panicking.
        assert_eq!(
            ActivationEnvelope::decode_ipc_frame(&[1, 2]),
            Err(ActivationError::MalformedIpcFrame)
        );
        assert_eq!(
            ActivationEnvelope::decode_ipc_frame(&[10, 0, 0, 0, b'{', b'}']),
            Err(ActivationError::MalformedIpcFrame)
        );
        Ok(())
    }

    #[test]
    fn large_explorer_selection_switches_from_argv_to_named_pipe_ipc() -> TestResult {
        let exe = r"C:\Program Files\WindowsApps\TotalDrop\totaldrop-winui.exe";

        // Small selection while no window is open -> DirectCommandLine.
        let small = ActivationEnvelope::explorer_send([r"C:\Users\Alice\notes.txt"], None)?;
        let small_plan = plan_explorer_invocation(exe, &small, 1, false)?;
        assert!(matches!(
            small_plan,
            ExplorerLaunchTransport::DirectCommandLine { .. }
        ));

        // Same small selection when a window is already open -> NamedPipeIpc
        // (single-window rule, ADR 0016).
        let open_window_plan = plan_explorer_invocation(exe, &small, 1, true)?;
        assert!(matches!(
            open_window_plan,
            ExplorerLaunchTransport::NamedPipeIpc { .. }
        ));

        // 450 long paths (> 30,000 UTF-16 code units) -> switches automatically
        // to NamedPipeIpc even on cold start so CreateProcessW never truncates.
        let many_paths: Vec<String> = (0..450usize)
            .map(|i| {
                format!(
                    r"C:\Users\Developer\Workspaces\ Deeply_Nested_Project_Folder_2026\Submodule_Alpha\Artifact_{i:04}.bin"
                )
            })
            .collect();
        let large = ActivationEnvelope::explorer_send(&many_paths, Some(9001))?;
        let large_plan = plan_explorer_invocation(exe, &large, 2, false)?;
        match large_plan {
            ExplorerLaunchTransport::NamedPipeIpc {
                pipe_path,
                cold_start_command_line,
                ipc_frame,
            } => {
                assert_eq!(pipe_path, r"\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.2");
                assert!(cold_start_command_line.ends_with(" --ipc-await"));
                let round_trip = ActivationEnvelope::decode_ipc_frame(&ipc_frame)?;
                assert_eq!(round_trip, large);
            }
            ExplorerLaunchTransport::DirectCommandLine { .. } => {
                return Err("expected NamedPipeIpc for >30k UTF-16 selection".into());
            }
        }
        Ok(())
    }

    #[test]
    fn launch_args_cover_explorer_uris_screens_and_await_mode() -> TestResult {
        assert_eq!(parse_launch_args(["--ipc-await"])?, None);
        assert_eq!(parse_launch_args(Vec::<&str>::new())?, None);

        let screen_env =
            parse_launch_args(["--screen=clipboard"])?.ok_or("expected OpenScreen envelope")?;
        assert_eq!(
            screen_env.payload,
            ActivationPayload::OpenScreen {
                screen: ScreenTarget::Clipboard
            }
        );

        let uri_env = parse_launch_args(["totaldrop://r/7-harbor-rocket"])?
            .ok_or("expected ProtocolUri envelope")?;
        assert!(matches!(
            uri_env.payload,
            ActivationPayload::ProtocolUri { .. }
        ));

        let explorer_env = parse_launch_args([
            "--explorer-send",
            "--",
            r"\\?\C:\Users\Alice\file1.png",
            r"\\?\C:\Users\Alice\file2.png",
        ])?
        .ok_or("expected ExplorerSend envelope")?;
        if let ActivationPayload::ExplorerSend { paths } = explorer_env.payload {
            assert_eq!(paths.len(), 2);
        } else {
            return Err("expected ExplorerSend payload".into());
        }
        Ok(())
    }

    #[test]
    fn all_35_languages_have_localized_explorer_send_with_verbs() -> TestResult {
        assert_eq!(SUPPORTED_LANGUAGES.len(), 35);
        let unique: BTreeSet<&str> = SUPPORTED_LANGUAGES.iter().copied().collect();
        assert_eq!(unique.len(), 35);

        let catalog = explorer_verb_catalog();
        assert_eq!(catalog.len(), 35);

        for entry in &catalog {
            assert!(
                !entry.title.is_empty(),
                "empty Explorer verb for {}",
                entry.language_tag
            );
            // Every translation of `desktopSendWith` names `TotalDrop` and
            // never falls back to the raw key name `"desktopSendWith"`.
            assert_ne!(entry.title, "desktopSendWith");
            assert!(
                entry.title.contains("TotalDrop"),
                "{} verb {:?} should contain brand name TotalDrop",
                entry.language_tag,
                entry.title
            );
        }

        // Verify English, Windows Chinese script negotiation (`zh-HK` -> `zh-Hant`,
        // `zh-CN` -> `zh` / `zh-Hans`), Norwegian (`nn-NO` -> `nb`), and RTL flags.
        let en = explorer_send_verb(["en-US"]);
        assert_eq!(en.title, "Send with TotalDrop");
        assert_eq!(en.flow_direction, WinUiFlowDirection::LeftToRight);

        let zh_hk = explorer_send_verb(["zh-HK"]);
        let zh_cn = explorer_send_verb(["zh-CN"]);
        assert_eq!(zh_hk.language_tag, "zh-Hant");
        assert_ne!(zh_hk.title, zh_cn.title);

        let nb = explorer_send_verb(["nn-NO"]);
        assert_eq!(nb.language_tag, "nb");

        for rtl_tag in ["ar-SA", "fa-IR", "he-IL", "ur-PK"] {
            let verb = explorer_send_verb([rtl_tag]);
            assert_eq!(
                verb.flow_direction,
                WinUiFlowDirection::RightToLeft,
                "{rtl_tag} must use RightToLeft FlowDirection"
            );
        }
        Ok(())
    }

    #[test]
    fn regional_percent_rounds_down_and_follows_windows_region_issue_483() {
        // Floor rounding (#483): 999,999 / 1,000,000 must read 99%, NEVER 100%,
        // while the final byte is still in transit.
        assert_eq!(whole_percent(0, 0), 0);
        assert_eq!(whole_percent(0, 1_000), 0);
        assert_eq!(whole_percent(999_999, 1_000_000), 99);
        assert_eq!(whole_percent(1_000_000, 1_000_000), 100);
        assert_eq!(whole_percent(1_500_000, 1_000_000), 100);

        // Turkish region places `%` before the digits (`"%50"`), even when the
        // user's Windows display language is English (`en-TR`).
        let tr = format_regional_percent(50, 100, "tr-TR");
        assert_eq!(tr.whole, 50);
        assert_eq!(tr.formatted, "%50");

        let en_tr = WindowsLocalizer::new(["en-US"], Some("en-TR"));
        assert_eq!(en_tr.language_tag(), "en");
        assert_eq!(en_tr.format_percent(999, 1000).formatted, "%99");

        // German region places a space before `%` (`"50 %"`), even with English UI.
        let en_de = WindowsLocalizer::new(["en-US"], Some("de-DE"));
        assert_eq!(en_de.language_tag(), "en");
        assert_eq!(en_de.format_percent(50, 100).formatted, "50 %");
        assert_eq!(en_de.format_bytes(1_500_000), "1,5 MB");

        // US English region writes `"50%"` and `"1.5 MB"`.
        let en_us = WindowsLocalizer::new(["en-US"], Some("en-US"));
        assert_eq!(en_us.format_percent(50, 100).formatted, "50%");
        assert_eq!(en_us.format_bytes(1_500_000), "1.5 MB");
    }

    #[test]
    fn rtl_bidi_isolation_and_spoofed_filename_sanitization() {
        // Right-to-left override attack (`invoice` + U+202E + `fdp.exe`) must be
        // visibly exposed as `<U+202E>` and wrapped in FSI..PDI (`U+2068..U+2069`).
        let spoofed = "invoice\u{202E}fdp.exe";
        let safe = sanitize_peer_filename(spoofed);
        assert_eq!(safe, "\u{2068}invoice<U+202E>fdp.exe\u{2069}");

        let path = WindowsSelectionPath::parse("C:\\Downloads\\invoice\u{202E}fdp.exe");
        assert!(path.is_ok());
        if let Ok(p) = path {
            assert_eq!(
                p.safe_display_path(),
                "C:\\Downloads\\invoice<U+202E>fdp.exe"
            );
        }

        // Pseudo-locales `en-XA` and `ar-XB` (ADR 0008).
        let pseudo_rtl = WindowsLocalizer::new(["ar-XB"], None);
        assert_eq!(pseudo_rtl.flow_direction(), WinUiFlowDirection::RightToLeft);

        let pseudo_accent = WindowsLocalizer::new(["en-XA"], None);
        assert_eq!(
            pseudo_accent.flow_direction(),
            WinUiFlowDirection::LeftToRight
        );
        assert!(pseudo_accent.text("sendTitle").len() > "Send files".len());

        // Safety-critical unreviewed drafts fall back to English (`verificationTitle`),
        // whereas reviewed Turkish (`tr`) shows its reviewed translation.
        let de = WindowsLocalizer::new(["de-DE"], None);
        assert!(de.needs_english("verificationTitle"));
        assert_eq!(
            de.ui_bundle("0.2.0-beta.5").verification_title,
            "Verification words"
        );

        let tr = WindowsLocalizer::new(["tr-TR"], None);
        assert!(!tr.needs_english("verificationTitle"));
        assert!(!tr.has_drafts());
    }

    #[test]
    fn peer_text_sanitization_truncates_and_names_controls() {
        let clean = sanitize_peer_text("line1\r\nline2\tvalue");
        assert_eq!(clean.display_text, "line1\nline2\tvalue");
        assert!(!clean.shortened);
        assert!(!clean.has_hidden_controls);

        let hidden = sanitize_peer_text("hello\u{202E}world");
        assert_eq!(hidden.display_text, "hello<U+202E>world");
        assert!(hidden.has_hidden_controls);

        let huge = "x".repeat(l10n::MAX_SHOWN_TEXT_CHARS.saturating_add(32));
        let capped = sanitize_peer_text(&huge);
        assert!(capped.shortened);
        assert_eq!(
            capped.display_text.chars().count(),
            l10n::MAX_SHOWN_TEXT_CHARS
        );
    }

    #[test]
    fn core_session_projection_and_reduced_motion_rules() {
        let cfg = BridgeNetworkConfig::default();
        assert!(BridgeNetworkConfig::is_valid_rendezvous_url(
            &cfg.rendezvous_server
        ));
        assert!(!BridgeNetworkConfig::is_valid_rendezvous_url(
            "http://insecure.example.com"
        ));
        assert_eq!(cfg.to_send_options().words, 2);

        let mut strong_cfg = cfg.clone();
        strong_cfg.stronger_three_word_code = true;
        assert_eq!(strong_cfg.to_send_options().words, 3);

        let localizer = WindowsLocalizer::new(["en-US"], Some("tr-TR"));
        let progress = TransferViewEvent::from_core_event(
            Event::Progress {
                done: 999_999,
                total: 1_000_000,
            },
            &localizer,
        );
        assert_eq!(
            progress,
            TransferViewEvent::Progress {
                done_bytes: 999_999,
                total_bytes: 1_000_000,
                formatted_done: "1,0 MB".to_owned(),
                formatted_total: "1,0 MB".to_owned(),
                percent: RegionalPercent {
                    whole: 99,
                    formatted: "%99".to_owned(),
                },
            }
        );

        let err = LocalizedTransferError::from_core_error(&CoreError::WrongCode, &localizer, false);
        assert_eq!(err.kind, "wrong_code");
        assert_eq!(err.l10n_key, "errorWrongCode");
        assert!(err.cause.is_empty());
        assert!(err.summary.contains("code did not match"));
        assert!(err.technical_english.contains("code did not match"));

        // `UISettings.AnimationsEnabled` reduced-motion gate (ADR 0016).
        assert!(should_animate_mark(true, true));
        assert!(!should_animate_mark(true, false));
        assert!(!should_animate_mark(false, true));
    }

    #[test]
    fn rendezvous_url_validation_delegates_strictly_to_core_check_url() {
        for valid in [
            "wss://rendezvous.totaldrop.app",
            "  wss://relay.example.org/v0/relay  ",
            "wss://relay.example.org:443/v0/relay",
            "wss://[2001:db8::1]:8443/v0/relay",
            "ws://127.0.0.1:4000",
            "ws://localhost:4000",
            "ws://[::1]:4000",
            "ws://[::1]",
        ] {
            assert!(
                BridgeNetworkConfig::is_valid_rendezvous_url(valid),
                "expected valid URL: {valid:?}"
            );
        }

        for invalid in [
            "",
            "   ",
            "wss://",
            "wss:///",
            "wss://user@rendezvous.totaldrop.app",
            "ws://localhost@evil.example:4000",
            "wss://host /bad",
            "wss://rendezvous.totaldrop.app\n",
            "http://127.0.0.1:4000",
            "https://rendezvous.totaldrop.app",
            "ws://192.168.1.10:4000",
            "ws://127.0.0.1.evil.com:4000",
            "ws://0.0.0.0:4000",
            // Authority, IPv6, port, and RFC 6455 fragment bypass vectors:
            "wss://:443",
            "wss://:",
            "wss://:0",
            "wss://:443/v0/allocate",
            "wss://[]:443",
            "wss://[::1]garbage",
            "wss://example.invalid:",
            "wss://example.invalid:99999",
            "wss://example.invalid:abc",
            "wss://example.invalid:0",
            "wss://example.invalid#frag",
            "ws://127.0.0.1:99999",
            "ws://127.0.0.1:abc",
            "ws://localhost:99999",
            "ws://localhost:abc",
            "ws://localhost#frag",
        ] {
            assert!(
                !BridgeNetworkConfig::is_valid_rendezvous_url(invalid),
                "expected invalid URL: {invalid:?}"
            );
        }

        let cfg = BridgeNetworkConfig {
            rendezvous_server: "  ws://127.0.0.1:4000  ".to_owned(),
            relay_server: "  ws://127.0.0.1:4001/v0/relay ".to_owned(),
            stun_server: "  ".to_owned(),
            privacy_relay_only: true,
            stronger_three_word_code: false,
        };
        assert_eq!(cfg.to_send_options().server, "ws://127.0.0.1:4000");
        assert_eq!(
            cfg.to_receive_options().paths.relay,
            "ws://127.0.0.1:4001/v0/relay"
        );
        assert_eq!(cfg.to_path_options().stun, "");
    }

    #[test]
    fn localized_transfer_error_distinguishes_sender_vs_receiver_bad_server_and_text_errors() {
        let en = WindowsLocalizer::new(["en-US"], Some("en-US"));

        let expired_sender = LocalizedTransferError::from_core_error(
            &CoreError::Rendezvous("mailbox expired".into()),
            &en,
            true,
        );
        assert_eq!(expired_sender.kind, "code_expired");
        assert_eq!(expired_sender.l10n_key, "errorCodeExpired");
        assert!(expired_sender.cause.is_empty());

        let missing_receiver = LocalizedTransferError::from_core_error(
            &CoreError::Rendezvous("unknown nameplate".into()),
            &en,
            false,
        );
        assert_eq!(missing_receiver.kind, "code_not_in_use");
        assert_eq!(missing_receiver.l10n_key, "errorCodeNotInUse");

        let full_receiver = LocalizedTransferError::from_core_error(
            &CoreError::Rendezvous("nameplate full".into()),
            &en,
            false,
        );
        assert_eq!(full_receiver.kind, "code_not_in_use");
        assert_eq!(full_receiver.l10n_key, "errorCodeNotInUse");

        let bad_srv = LocalizedTransferError::from_core_error(
            &CoreError::Rendezvous("the server address must start with wss://".into()),
            &en,
            false,
        );
        assert_eq!(bad_srv.kind, "bad_server");
        assert_eq!(bad_srv.l10n_key, "errorBadServer");

        let generic_srv = LocalizedTransferError::from_core_error(
            &CoreError::Rendezvous("rate limit exceeded".into()),
            &en,
            false,
        );
        assert_eq!(generic_srv.kind, "server");
        assert_eq!(generic_srv.l10n_key, "errorServer");

        let auth_err = LocalizedTransferError::from_core_error(
            &CoreError::Protocol("message failed authentication"),
            &en,
            false,
        );
        assert_eq!(auth_err.kind, "protocol");
        assert_eq!(auth_err.l10n_key, "errorOther");
        assert_eq!(auth_err.cause, "");
        assert_eq!(auth_err.cause_detail, None);

        let damaged = LocalizedTransferError::text_damaged(&en);
        assert_eq!(damaged.kind, "text_damaged");
        assert_eq!(damaged.l10n_key, "errorTextDamaged");
        assert_eq!(damaged.cause, "");
        assert_eq!(damaged.technical_english, "the text failed its check");

        let too_long = LocalizedTransferError::text_too_long(&en);
        assert_eq!(too_long.kind, "text_too_long");
        assert_eq!(too_long.l10n_key, "sendTextTooLong");
        assert!(too_long.technical_english.contains("1048576"));

        // Critical error keys stay English on unreviewed locales (e.g. de).
        let de = WindowsLocalizer::new(["de-DE"], Some("de-DE"));
        let de_wrong = LocalizedTransferError::from_core_error(&CoreError::WrongCode, &de, false);
        assert_eq!(de_wrong.l10n_key, "errorWrongCode");
        assert_eq!(de_wrong.summary, en.text("errorWrongCode"));
    }

    #[test]
    fn code_word_completions_and_path_validation_and_format_message_work() -> TestResult {
        assert_eq!(code_word_completions("harb", 4), vec!["harbor"]);
        assert_eq!(code_word_completions("  HARB ", 4), vec!["harbor"]);
        assert!(code_word_completions("", 4).is_empty());
        assert!(code_word_completions("12", 4).is_empty());
        assert!(code_word_completions("Ä", 4).is_empty());
        assert!(code_word_completions("zz", 4).is_empty());
        assert!(code_word_completions("ab", 0).is_empty());
        assert_eq!(code_word_completions("ab", 2).len(), 2);

        let paths = validate_windows_paths([
            r"\\nas01\team\Spec.docx",
            r"\\NAS01\team\spec.docx",
            r"c:\Users\Alice\report.pdf",
        ])?;
        assert_eq!(paths.len(), 2);
        let first = paths.first().ok_or("missing first path")?;
        assert_eq!(first.extended_path, r"\\?\UNC\nas01\team\Spec.docx");
        assert_eq!(first.unprefixed_path, r"\\nas01\team\Spec.docx");
        assert_eq!(first.root_kind, WindowsRootKind::Unc);

        let en = WindowsLocalizer::new(["en-US"], Some("en-US"));
        assert!(en.has_key("sendDoneBody"));
        assert!(!en.has_key(""));
        assert!(!en.has_key("nonexistentKey123"));
        assert_eq!(en.format_message("nonexistentKey123", &[]), None);
        assert_eq!(
            en.format_message("sendDoneBody", &[("count", totaldrop_l10n::Arg::Count(3))]),
            Some("All 3 files arrived intact.".to_owned())
        );
        Ok(())
    }

    #[test]
    fn share_target_envelope_supports_files_and_plain_text() -> TestResult {
        let env = ActivationEnvelope::share_target(
            [r"C:\Users\Alice\Pictures\screenshot.png"],
            Some("Shared note".to_owned()),
            Some(1200),
        )?;
        let frame = env.encode_ipc_frame()?;
        let decoded = ActivationEnvelope::decode_ipc_frame(&frame)?;
        assert_eq!(decoded, env);
        Ok(())
    }

    #[test]
    fn envelope_json_rejects_unknown_schema_version_and_tampered_canonical_code() {
        let bad_version = br#"{"version":99,"initiator_pid":null,"payload":{"kind":"open_screen","screen":"send"}}"#;
        assert_eq!(
            ActivationEnvelope::from_json_bytes(bad_version),
            Err(ActivationError::UnsupportedSchemaVersion(99))
        );

        let tampered_code = br#"{"version":1,"initiator_pid":null,"payload":{"kind":"protocol_uri","code":{"nameplate":7,"word_count":2,"display_english":"7-harbor-rocket","canonical":"7-0-0","ltr_isolated":"7-harbor-rocket","protocol_uri":"totaldrop://r/7-harbor-rocket","web_uri":"https://totaldrop.app/r#7-harbor-rocket"}}}"#;
        assert!(matches!(
            ActivationEnvelope::from_json_bytes(tampered_code),
            Err(ActivationError::InvalidUri(_))
        ));
    }
}
