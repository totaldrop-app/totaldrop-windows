// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end C ABI contract tests for all 31 M1 + M2 + M3 exports in
//! `totaldrop-windows-ffi`.

use std::error::Error as StdError;
use std::ffi::{CStr, CString, c_char};
use std::ptr;

use serde_json::Value;
use totaldrop_l10n::{Domain, Strings};
use totaldrop_windows_bridge::{
    ActivationEnvelope, MAX_IPC_FRAME_BYTES, SUPPORTED_LANGUAGES, ScreenTarget,
};
use totaldrop_windows_ffi::{
    APP_VERSION, CORE_VERSION, FFI_ERR_INVALID_ARG, FFI_ERR_INVALID_HANDLE, FFI_ERR_INVALID_UTF8,
    FFI_ERR_NULL_POINTER, FFI_OK, MSIX_VERSION, totaldrop_win_code_completions_json,
    totaldrop_win_extract_clipboard_code_json, totaldrop_win_format_bytes_json,
    totaldrop_win_format_message_json, totaldrop_win_format_percent_json,
    totaldrop_win_receive_accept_files, totaldrop_win_receive_accept_text,
    totaldrop_win_receive_connect_start, totaldrop_win_receive_decline,
    totaldrop_win_router_create, totaldrop_win_router_destroy, totaldrop_win_router_drain_ndjson,
    totaldrop_win_router_ingest_ipc_bytes_json, totaldrop_win_router_set_activity_json,
    totaldrop_win_router_set_animations_json, totaldrop_win_router_update_locale_json,
    totaldrop_win_sanitize_filename_json, totaldrop_win_sanitize_text_json,
    totaldrop_win_send_files_start, totaldrop_win_send_text_start, totaldrop_win_session_cancel,
    totaldrop_win_session_destroy, totaldrop_win_session_poll_events_ndjson,
    totaldrop_win_shutdown, totaldrop_win_string_free, totaldrop_win_ui_bundle_json,
    totaldrop_win_validate_input_json, totaldrop_win_validate_paths_json,
    totaldrop_win_validate_server_url_json, totaldrop_win_validate_uri_json,
    totaldrop_win_version_json,
};

type TestResult = Result<(), Box<dyn StdError>>;

fn decode_and_free(ptr: *mut c_char) -> Result<Value, Box<dyn StdError>> {
    if ptr.is_null() {
        return Err("FFI returned unexpected null pointer".into());
    }
    // SAFETY: `ptr` was freshly returned by a `totaldrop_win_*` FFI export.
    let raw = unsafe { CStr::from_ptr(ptr) }.to_str()?.to_owned();
    // SAFETY: `ptr` was allocated by `totaldrop-windows-ffi` and is freed once.
    unsafe { totaldrop_win_string_free(ptr) };
    Ok(serde_json::from_str(&raw)?)
}

fn c_str(text: &str) -> Result<CString, Box<dyn StdError>> {
    Ok(CString::new(text)?)
}

fn assert_strict_four_field_error(
    val: &Value,
    expected_kind: &str,
    expected_l10n_key: Option<&str>,
) -> TestResult {
    assert_eq!(val.get("ok").and_then(Value::as_bool), Some(false));
    let err = val
        .get("error")
        .and_then(Value::as_object)
        .ok_or("missing error object")?;
    for key in err.keys() {
        assert!(
            matches!(key.as_str(), "kind" | "l10n_key" | "cause" | "message"),
            "unexpected extra key {key:?} in 4-field error envelope"
        );
    }
    assert_eq!(err.get("kind").and_then(Value::as_str), Some(expected_kind));
    if let Some(expected_key) = expected_l10n_key {
        assert_eq!(
            err.get("l10n_key").and_then(Value::as_str),
            Some(expected_key)
        );
    }
    assert!(
        err.get("message")
            .and_then(Value::as_str)
            .is_some_and(|m| !m.is_empty()),
        "error.message must be non-empty"
    );
    Ok(())
}

#[test]
fn string_free_accepts_null_pointer_safely() {
    // SAFETY: Null pointer is explicitly documented as a safe no-op.
    unsafe { totaldrop_win_string_free(ptr::null_mut()) };
}

#[test]
fn version_json_matches_canonical_version_buckets() -> TestResult {
    let val = decode_and_free(totaldrop_win_version_json())?;
    assert_eq!(
        val.get("app_version").and_then(Value::as_str),
        Some(APP_VERSION)
    );
    assert_eq!(
        val.get("app_version").and_then(Value::as_str),
        Some("0.1.0-beta.1")
    );
    assert_eq!(
        val.get("core_version").and_then(Value::as_str),
        Some(CORE_VERSION)
    );
    assert_eq!(
        val.get("core_version").and_then(Value::as_str),
        Some("0.2.0-beta.5")
    );
    assert_eq!(
        val.get("msix_version").and_then(Value::as_str),
        Some(MSIX_VERSION)
    );
    assert_eq!(
        val.get("msix_version").and_then(Value::as_str),
        Some("0.1.1.0")
    );
    Ok(())
}

#[test]
fn validate_uri_json_accepts_valid_links_and_rejects_bad_null_and_invalid_utf8() -> TestResult {
    let valid_uri = c_str("totaldrop://r/7-harbor-rocket")?;
    // SAFETY: `valid_uri` is a live NUL-terminated CString.
    let ok = decode_and_free(unsafe { totaldrop_win_validate_uri_json(valid_uri.as_ptr()) })?;
    assert_eq!(ok.get("nameplate").and_then(Value::as_u64), Some(7));
    assert_eq!(ok.get("word_count").and_then(Value::as_u64), Some(2));
    assert_eq!(
        ok.get("display_english").and_then(Value::as_str),
        Some("7-harbor-rocket")
    );
    assert_eq!(
        ok.get("canonical").and_then(Value::as_str),
        Some("7-840-1499")
    );
    assert_eq!(
        ok.get("ltr_isolated").and_then(Value::as_str),
        Some("\u{2068}7-harbor-rocket\u{2069}")
    );
    assert_eq!(
        ok.get("protocol_uri").and_then(Value::as_str),
        Some("totaldrop://r/7-harbor-rocket")
    );
    assert_eq!(
        ok.get("web_uri").and_then(Value::as_str),
        Some("https://totaldrop.app/r#7-harbor-rocket")
    );

    // SAFETY: Null pointer is explicitly handled by `totaldrop_win_validate_uri_json`.
    let null_err = decode_and_free(unsafe { totaldrop_win_validate_uri_json(ptr::null()) })?;
    assert_strict_four_field_error(&null_err, "null_pointer", Some("errorInvalidCode"))?;

    let bad_utf8: [u8; 3] = [0xFF, 0xFE, 0x00];
    // SAFETY: `bad_utf8` is a NUL-terminated byte buffer alive for this call.
    let utf8_err = decode_and_free(unsafe {
        totaldrop_win_validate_uri_json(bad_utf8.as_ptr().cast::<c_char>())
    })?;
    assert_strict_four_field_error(&utf8_err, "invalid_utf8", Some("errorInvalidCode"))?;

    let evil_uri = c_str("https://evil.example/r#7-harbor-rocket")?;
    // SAFETY: `evil_uri` is a live NUL-terminated CString.
    let evil_err = decode_and_free(unsafe { totaldrop_win_validate_uri_json(evil_uri.as_ptr()) })?;
    assert_strict_four_field_error(
        &evil_err,
        "invalid_activation_link",
        Some("errorInvalidCode"),
    )?;

    let oversized = c_str(&format!("totaldrop://r/{}", "a".repeat(1100)))?;
    // SAFETY: `oversized` is a live NUL-terminated CString.
    let long_err = decode_and_free(unsafe { totaldrop_win_validate_uri_json(oversized.as_ptr()) })?;
    assert_strict_four_field_error(&long_err, "link_too_long", Some("errorInvalidCode"))?;
    Ok(())
}

#[test]
fn validate_input_json_handles_arabic_digits_and_error_classification() -> TestResult {
    let arabic_digits = c_str("\u{0667} Harbor ROCKET")?;
    // SAFETY: `arabic_digits` is a live NUL-terminated CString.
    let ok = decode_and_free(unsafe { totaldrop_win_validate_input_json(arabic_digits.as_ptr()) })?;
    assert_eq!(
        ok.get("display_english").and_then(Value::as_str),
        Some("7-harbor-rocket")
    );

    for (raw, expected_kind, expected_key) in [
        ("", "empty", "receiveCodeInvalid"),
        ("0-harbor-rocket", "bad_nameplate", "receiveCodeInvalid"),
        ("7-harbor", "wrong_word_count", "receiveCodeInvalid"),
        ("7-harbor-notaword", "unknown_word", "receiveCodeInvalid"),
        (
            "https://evil.example/r#7-harbor-rocket",
            "invalid_activation_link",
            "errorInvalidCode",
        ),
    ] {
        let input = c_str(raw)?;
        // SAFETY: `input` is a live NUL-terminated CString.
        let err = decode_and_free(unsafe { totaldrop_win_validate_input_json(input.as_ptr()) })?;
        assert_strict_four_field_error(&err, expected_kind, Some(expected_key))?;
    }

    // SAFETY: Null pointer is explicitly handled by `totaldrop_win_validate_input_json`.
    let null_err = decode_and_free(unsafe { totaldrop_win_validate_input_json(ptr::null()) })?;
    assert_strict_four_field_error(&null_err, "null_pointer", Some("receiveCodeInvalid"))?;
    Ok(())
}

#[test]
fn format_percent_json_enforces_issue_483_floor_rounding_and_region_defaults() -> TestResult {
    let tr = c_str("tr-TR")?;
    // SAFETY: `tr` is a live NUL-terminated CString.
    let tr_pct = decode_and_free(unsafe {
        totaldrop_win_format_percent_json(999_999, 1_000_000, tr.as_ptr())
    })?;
    assert_eq!(tr_pct.get("whole").and_then(Value::as_u64), Some(99));
    assert_eq!(tr_pct.get("formatted").and_then(Value::as_str), Some("%99"));

    let de = c_str("de-DE")?;
    // SAFETY: `de` is a live NUL-terminated CString.
    let de_pct = decode_and_free(unsafe { totaldrop_win_format_percent_json(1, 2, de.as_ptr()) })?;
    assert_eq!(de_pct.get("whole").and_then(Value::as_u64), Some(50));
    let de_formatted = de_pct
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing formatted field")?;
    assert!(de_formatted.contains("50") && de_formatted.ends_with('%'));

    // SAFETY: Null pointer is explicitly accepted as default en-US.
    let en_pct = decode_and_free(unsafe {
        totaldrop_win_format_percent_json(u64::MAX - 1, u64::MAX, ptr::null())
    })?;
    assert_eq!(en_pct.get("whole").and_then(Value::as_u64), Some(99));
    assert_eq!(en_pct.get("formatted").and_then(Value::as_str), Some("99%"));

    let bad_utf8: [u8; 2] = [0xC0, 0x00];
    // SAFETY: `bad_utf8` is a NUL-terminated byte buffer alive for this call.
    let utf8_err = decode_and_free(unsafe {
        totaldrop_win_format_percent_json(50, 100, bad_utf8.as_ptr().cast::<c_char>())
    })?;
    assert_strict_four_field_error(&utf8_err, "invalid_utf8", Some("errorOther"))?;
    Ok(())
}

#[test]
fn ui_bundle_json_preserves_m1_29_fields_and_adds_m2_full_l10n_coverage() -> TestResult {
    const M1_FIELDS: [&str; 29] = [
        "language_tag",
        "region_tag",
        "flow_direction",
        "has_draft_translations",
        "explorer_send_with",
        "app_tagline",
        "send_title",
        "send_add_files",
        "send_drop_here",
        "send_drop_hint",
        "send_strong_code",
        "send_strong_code_hint",
        "send_create_code",
        "send_your_code",
        "send_copy",
        "send_share",
        "receive_title",
        "receive_code_label",
        "receive_code_hint",
        "receive_paste",
        "receive_connect",
        "receive_accept",
        "receive_decline",
        "verification_title",
        "verification_hint",
        "settings_title",
        "cancel",
        "keep_awake_reason",
        "version_label",
    ];

    let ar_langs = c_str("ar-SA,en-US")?;
    let ar_region = c_str("ar-EG")?;
    // SAFETY: Both pointers are live NUL-terminated CStrings; null version defaults to APP_VERSION.
    let ar_bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(ar_langs.as_ptr(), ar_region.as_ptr(), ptr::null())
    })?;
    let obj = ar_bundle
        .as_object()
        .ok_or("WindowsUiBundle must serialize as a JSON object")?;
    assert_eq!(
        obj.len(),
        109,
        "WindowsUiBundle must serialize all 29 M1 + 80 M2 DTO fields"
    );
    for field in M1_FIELDS {
        assert!(
            obj.contains_key(field),
            "missing preserved M1 field {field}"
        );
    }
    assert_eq!(
        ar_bundle.get("language_tag").and_then(Value::as_str),
        Some("ar")
    );
    assert_eq!(
        ar_bundle.get("region_tag").and_then(Value::as_str),
        Some("ar-EG")
    );
    assert_eq!(
        ar_bundle.get("flow_direction").and_then(Value::as_str),
        Some("RightToLeft")
    );
    assert_eq!(
        ar_bundle
            .get("has_draft_translations")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        ar_bundle.get("verification_title").and_then(Value::as_str),
        Some("Verification words")
    );
    assert_eq!(
        ar_bundle.get("receive_accept").and_then(Value::as_str),
        Some("Accept")
    );
    assert_eq!(
        ar_bundle.get("receive_decline").and_then(Value::as_str),
        Some("Decline")
    );
    assert!(
        ar_bundle
            .get("version_label")
            .and_then(Value::as_str)
            .is_some_and(|v| v.contains(APP_VERSION))
    );

    let tr_langs = c_str(r#"["tr-TR","en-US"]"#)?;
    let tr_region = c_str("tr-TR")?;
    let explicit_ver = c_str("0.1.0-beta.1")?;
    // SAFETY: All three pointers are live NUL-terminated CStrings.
    let tr_bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(tr_langs.as_ptr(), tr_region.as_ptr(), explicit_ver.as_ptr())
    })?;
    assert_eq!(
        tr_bundle.get("language_tag").and_then(Value::as_str),
        Some("tr")
    );
    assert_eq!(
        tr_bundle.get("flow_direction").and_then(Value::as_str),
        Some("LeftToRight")
    );
    assert_eq!(
        tr_bundle
            .get("has_draft_translations")
            .and_then(Value::as_bool),
        Some(false)
    );

    let zh_langs = c_str("zh-HK,en-US")?;
    // SAFETY: `zh_langs` is live; null region & version use safe defaults.
    let zh_bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(zh_langs.as_ptr(), ptr::null(), ptr::null())
    })?;
    assert_eq!(
        zh_bundle.get("language_tag").and_then(Value::as_str),
        Some("zh-Hant")
    );

    // SAFETY: Null arguments are explicitly accepted.
    let default_bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(ptr::null(), ptr::null(), ptr::null())
    })?;
    assert_eq!(
        default_bundle.get("language_tag").and_then(Value::as_str),
        Some("en")
    );
    Ok(())
}

#[test]
fn clipboard_extraction_and_bip39_completions_enforce_exact_contracts() -> TestResult {
    let share_msg = c_str("Get my files with TotalDrop. Code: 7-harbor-rocket")?;
    // SAFETY: `share_msg` is a live NUL-terminated CString.
    let extracted =
        decode_and_free(unsafe { totaldrop_win_extract_clipboard_code_json(share_msg.as_ptr()) })?;
    assert_eq!(
        extracted.get("display_english").and_then(Value::as_str),
        Some("7-harbor-rocket")
    );

    let empty = c_str("   ")?;
    // SAFETY: `empty` is a live NUL-terminated CString.
    let empty_err =
        decode_and_free(unsafe { totaldrop_win_extract_clipboard_code_json(empty.as_ptr()) })?;
    assert_strict_four_field_error(&empty_err, "empty", Some("receiveCodeInvalid"))?;

    let no_code = c_str("Hello world, no transfer code in this message!")?;
    // SAFETY: `no_code` is a live NUL-terminated CString.
    let miss_err =
        decode_and_free(unsafe { totaldrop_win_extract_clipboard_code_json(no_code.as_ptr()) })?;
    assert_strict_four_field_error(&miss_err, "no_code_found_in_text", Some("errorInvalidCode"))?;

    // SAFETY: Null pointer is explicitly handled.
    let null_clip =
        decode_and_free(unsafe { totaldrop_win_extract_clipboard_code_json(ptr::null()) })?;
    assert_strict_four_field_error(&null_clip, "null_pointer", Some("errorInvalidCode"))?;

    let harb = c_str("HARB")?;
    // SAFETY: `harb` is a live NUL-terminated CString.
    let words = decode_and_free(unsafe { totaldrop_win_code_completions_json(harb.as_ptr(), 4) })?;
    let arr = words.as_array().ok_or("expected JSON array")?;
    assert_eq!(arr, &vec![Value::String("harbor".to_owned())]);

    for (raw, lim) in [("", 4), ("12", 4), ("Ä", 4), ("zz", 4), ("ab", 0)] {
        let p = c_str(raw)?;
        // SAFETY: `p` is a live NUL-terminated CString.
        let out = decode_and_free(unsafe { totaldrop_win_code_completions_json(p.as_ptr(), lim) })?;
        assert_eq!(out.as_array().map(Vec::len), Some(0));
    }

    // SAFETY: Null pointer is explicitly handled.
    let null_comp =
        decode_and_free(unsafe { totaldrop_win_code_completions_json(ptr::null(), 4) })?;
    assert_strict_four_field_error(&null_comp, "null_pointer", Some("errorOther"))?;
    Ok(())
}

#[test]
fn format_bytes_format_message_and_35_locale_11_critical_key_gate() -> TestResult {
    let en = c_str("en-US")?;
    let de = c_str("de-DE")?;
    // SAFETY: Pointers are live NUL-terminated CStrings.
    let bytes_us = decode_and_free(unsafe {
        totaldrop_win_format_bytes_json(1_500_000, en.as_ptr(), en.as_ptr())
    })?;
    assert_eq!(
        bytes_us.get("bytes").and_then(Value::as_u64),
        Some(1_500_000)
    );
    assert_eq!(
        bytes_us.get("formatted").and_then(Value::as_str),
        Some("1.5 MB")
    );

    // SAFETY: Pointers are live NUL-terminated CStrings.
    let bytes_de = decode_and_free(unsafe {
        totaldrop_win_format_bytes_json(1_500_000, en.as_ptr(), de.as_ptr())
    })?;
    assert_eq!(
        bytes_de.get("formatted").and_then(Value::as_str),
        Some("1,5 MB")
    );

    // ICU plural + text placeholder formatting.
    let key = c_str("itemsAndSize")?;
    let args = c_str(r#"{"count":3,"size":"2.5 MB"}"#)?;
    // SAFETY: Pointers are live NUL-terminated CStrings.
    let msg = decode_and_free(unsafe {
        totaldrop_win_format_message_json(key.as_ptr(), args.as_ptr(), en.as_ptr(), en.as_ptr())
    })?;
    assert_eq!(msg.get("key").and_then(Value::as_str), Some("itemsAndSize"));
    assert_eq!(msg.get("language_tag").and_then(Value::as_str), Some("en"));
    assert_eq!(
        msg.get("formatted").and_then(Value::as_str),
        Some("3 items · 2.5 MB")
    );

    // Negative boundary checks: empty key, unknown key, >16_384-byte args_json, malformed/non-object args_json.
    let empty_key = c_str("")?;
    // SAFETY: Pointers are live or null.
    let empty_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(empty_key.as_ptr(), ptr::null(), ptr::null(), ptr::null())
    })?;
    assert_strict_four_field_error(&empty_err, "empty_key", Some("errorOther"))?;

    let unknown_key = c_str("doesNotExistInArb")?;
    // SAFETY: Pointers are live or null.
    let unknown_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            unknown_key.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    })?;
    assert_strict_four_field_error(&unknown_err, "unknown_key", Some("errorOther"))?;

    let huge_args = c_str(&format!("{{\"a\":\"{}\"}}", "x".repeat(17_000)))?;
    // SAFETY: Pointers are live or null.
    let huge_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            key.as_ptr(),
            huge_args.as_ptr(),
            ptr::null(),
            ptr::null(),
        )
    })?;
    assert_strict_four_field_error(&huge_err, "args_too_large", Some("errorOther"))?;

    let bad_json_args = c_str("{not json")?;
    // SAFETY: Pointers are live or null.
    let bad_json_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            key.as_ptr(),
            bad_json_args.as_ptr(),
            ptr::null(),
            ptr::null(),
        )
    })?;
    assert_strict_four_field_error(&bad_json_err, "invalid_json", Some("errorOther"))?;

    let arr_args = c_str("[1, 2, 3]")?;
    // SAFETY: Pointers are live or null.
    let arr_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(key.as_ptr(), arr_args.as_ptr(), ptr::null(), ptr::null())
    })?;
    assert_strict_four_field_error(&arr_err, "invalid_args", Some("errorOther"))?;

    // Verify all 35 locales against the 11-key critical security English gate:
    // 6 App keys through totaldrop_win_format_message_json + 5 CLI keys via totaldrop-l10n.
    const APP_CRITICAL: [&str; 6] = [
        "verificationTitle",
        "verificationHint",
        "errorWrongCode",
        "errorInvalidOffer",
        "receiveAccept",
        "receiveDecline",
    ];
    const CLI_CRITICAL: [&str; 5] = [
        "cliVerification",
        "cliPromptSave",
        "cliYes",
        "cliErrWrongCode",
        "cliErrInvalidOffer",
    ];

    let en_app = Strings::new(Domain::App, &[], None);
    let en_cli = Strings::new(Domain::Cli, &[], None);

    for &tag in &SUPPORTED_LANGUAGES {
        let is_reviewed = tag == "en" || tag == "tr";
        let tag_c = c_str(tag)?;
        for &ckey in &APP_CRITICAL {
            let key_c = c_str(ckey)?;
            // SAFETY: Pointers are live or null.
            let res = decode_and_free(unsafe {
                totaldrop_win_format_message_json(
                    key_c.as_ptr(),
                    ptr::null(),
                    tag_c.as_ptr(),
                    tag_c.as_ptr(),
                )
            })?;
            let formatted = res
                .get("formatted")
                .and_then(Value::as_str)
                .ok_or("missing formatted text")?;
            if !is_reviewed {
                assert_eq!(
                    formatted,
                    en_app.get(ckey, &[]),
                    "unreviewed locale {tag} leaked non-English critical app key {ckey}"
                );
            }
        }

        if !is_reviewed {
            let loc = totaldrop_l10n::locale::parse(tag).ok_or("valid canonical tag")?;
            let cli_strings = Strings::new(Domain::Cli, &[loc], None);
            for &ckey in &CLI_CRITICAL {
                assert_eq!(
                    cli_strings.get(ckey, &[]),
                    en_cli.get(ckey, &[]),
                    "unreviewed locale {tag} leaked non-English critical CLI key {ckey}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn sanitize_helpers_server_url_and_windows_path_validation() -> TestResult {
    let rlo_name = c_str("invoice\u{202E}fdp.exe")?;
    // SAFETY: `rlo_name` is a live NUL-terminated CString.
    let fn_res =
        decode_and_free(unsafe { totaldrop_win_sanitize_filename_json(rlo_name.as_ptr()) })?;
    assert_eq!(
        fn_res.get("sanitized").and_then(Value::as_str),
        Some("\u{2068}invoice<U+202E>fdp.exe\u{2069}")
    );
    assert_eq!(
        fn_res.get("has_hidden_controls").and_then(Value::as_bool),
        Some(true)
    );

    let clean_name = c_str("report.pdf")?;
    // SAFETY: `clean_name` is a live NUL-terminated CString.
    let clean_fn =
        decode_and_free(unsafe { totaldrop_win_sanitize_filename_json(clean_name.as_ptr()) })?;
    assert_eq!(
        clean_fn.get("has_hidden_controls").and_then(Value::as_bool),
        Some(false)
    );

    let peer_txt = c_str("hi\r\n\u{200D}\u{202E}end")?;
    // SAFETY: `peer_txt` is a live NUL-terminated CString.
    let txt_res = decode_and_free(unsafe { totaldrop_win_sanitize_text_json(peer_txt.as_ptr()) })?;
    assert_eq!(
        txt_res.get("display_text").and_then(Value::as_str),
        Some("hi\n\u{200D}<U+202E>end")
    );
    assert_eq!(
        txt_res.get("shortened").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        txt_res.get("has_hidden_controls").and_then(Value::as_bool),
        Some(true)
    );

    // Server URL validation (`{"ok":true}` vs 4-field error envelope).
    for valid_url in [
        "wss://rendezvous.totaldrop.app",
        "ws://127.0.0.1:4000",
        "ws://[::1]:4000",
    ] {
        let u = c_str(valid_url)?;
        // SAFETY: `u` is a live NUL-terminated CString.
        let ok = decode_and_free(unsafe { totaldrop_win_validate_server_url_json(u.as_ptr()) })?;
        assert_eq!(ok.get("ok").and_then(Value::as_bool), Some(true));
        assert!(ok.get("error").is_none());
    }
    for bad_url in [
        "",
        "wss://",
        "wss://user@rendezvous.totaldrop.app",
        "ws://192.168.1.10:4000",
        "ws://127.0.0.1.evil.com:4000",
        "http://127.0.0.1:4000",
        "wss://host /bad",
        "wss://:443",
        "wss://:",
        "wss://:0",
        "wss://:443/v0/allocate",
        "wss://[]:443",
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
        let u = c_str(bad_url)?;
        // SAFETY: `u` is a live NUL-terminated CString.
        let err = decode_and_free(unsafe { totaldrop_win_validate_server_url_json(u.as_ptr()) })?;
        assert_strict_four_field_error(&err, "bad_server", Some("errorBadServer"))?;
    }

    // Windows path validation (drive + UNC + dedup + dangerous rejections).
    let good_paths = c_str(
        r#"["\\\\nas01\\team\\Spec.docx","\\\\NAS01\\team\\spec.docx","c:/Users/Alice/file.txt"]"#,
    )?;
    // SAFETY: `good_paths` is a live NUL-terminated CString.
    let norm = decode_and_free(unsafe { totaldrop_win_validate_paths_json(good_paths.as_ptr()) })?;
    let items = norm.as_array().ok_or("expected JSON array of paths")?;
    assert_eq!(items.len(), 2);
    let first = items.first().ok_or("missing first path")?;
    assert_eq!(
        first.get("extended_path").and_then(Value::as_str),
        Some(r"\\?\UNC\nas01\team\Spec.docx")
    );
    assert_eq!(
        first.get("unprefixed_path").and_then(Value::as_str),
        Some(r"\\nas01\team\Spec.docx")
    );
    assert_eq!(first.get("root_kind").and_then(Value::as_str), Some("unc"));

    let second = items.get(1).ok_or("missing second path")?;
    assert_eq!(
        second.get("extended_path").and_then(Value::as_str),
        Some(r"\\?\C:\Users\Alice\file.txt")
    );
    assert_eq!(
        second.get("root_kind").and_then(Value::as_str),
        Some("drive")
    );

    for (bad_json, expected_kind) in [
        (
            r#"["C:\\Users\\Alice\\CON.txt"]"#,
            "device_namespace_forbidden",
        ),
        (
            r#"["C:\\Users\\Alice\\LPT\u00B9"]"#,
            "device_namespace_forbidden",
        ),
        (
            r#"["C:\\Users\\Alice\\report.pdf:Zone.Identifier"]"#,
            "forbidden_segment_character",
        ),
        (r#"["\\\\.\\PhysicalDrive0"]"#, "device_namespace_forbidden"),
        (
            r#"["\\\\?\\globalroot\\Device\\Harddisk0"]"#,
            "device_namespace_forbidden",
        ),
        (
            r#"["\\\\?\\volume{01234567-89ab-cdef-0123-456789abcdef}\\a.txt"]"#,
            "device_namespace_forbidden",
        ),
        (r#"["\\\\?\\PIPE\\foo"]"#, "device_namespace_forbidden"),
        (
            r#"["C:\\Users\\Alice\\..\\Bob\\a.txt"]"#,
            "dot_traversal_segment",
        ),
        (r#"["relative\\path.txt"]"#, "not_absolute_windows_path"),
    ] {
        let j = c_str(bad_json)?;
        // SAFETY: `j` is a live NUL-terminated CString.
        let err = decode_and_free(unsafe { totaldrop_win_validate_paths_json(j.as_ptr()) })?;
        assert_strict_four_field_error(&err, expected_kind, Some("errorStorage"))?;
    }
    Ok(())
}

#[test]
fn invalid_session_handles_and_status_codes_behave_deterministically() -> TestResult {
    // Null/malformed inputs return handle 0.
    // SAFETY: Null pointers are explicitly handled.
    let h1 = unsafe {
        totaldrop_win_send_files_start(ptr::null(), ptr::null(), ptr::null(), ptr::null())
    };
    assert_eq!(h1, 0);
    // SAFETY: Null pointers are explicitly handled.
    let h2 = unsafe {
        totaldrop_win_send_text_start(ptr::null(), ptr::null(), ptr::null(), ptr::null())
    };
    assert_eq!(h2, 0);
    // SAFETY: Null pointers are explicitly handled.
    let h3 = unsafe {
        totaldrop_win_receive_connect_start(ptr::null(), ptr::null(), ptr::null(), ptr::null())
    };
    assert_eq!(h3, 0);

    // Unknown / 0 handle returns -3 or structured error JSON.
    assert_eq!(totaldrop_win_session_cancel(0), FFI_ERR_INVALID_HANDLE);
    assert_eq!(
        totaldrop_win_session_cancel(999_999),
        FFI_ERR_INVALID_HANDLE
    );
    assert_eq!(totaldrop_win_session_destroy(0), FFI_ERR_INVALID_HANDLE);
    assert_eq!(
        totaldrop_win_session_destroy(999_999),
        FFI_ERR_INVALID_HANDLE
    );
    assert_eq!(totaldrop_win_receive_accept_text(0), FFI_ERR_INVALID_HANDLE);
    assert_eq!(totaldrop_win_receive_decline(0), FFI_ERR_INVALID_HANDLE);

    // SAFETY: Null pointer returns FFI_ERR_NULL_POINTER.
    let r_null = unsafe { totaldrop_win_receive_accept_files(1, ptr::null()) };
    assert_eq!(r_null, FFI_ERR_NULL_POINTER);
    let empty_dir = c_str("   ")?;
    // SAFETY: `empty_dir` is a live NUL-terminated CString.
    let r_empty = unsafe { totaldrop_win_receive_accept_files(1, empty_dir.as_ptr()) };
    assert_eq!(r_empty, FFI_ERR_INVALID_ARG);
    let bad_utf8: [u8; 2] = [0xFF, 0x00];
    // SAFETY: `bad_utf8` is a NUL-terminated buffer.
    let r_utf8 =
        unsafe { totaldrop_win_receive_accept_files(1, bad_utf8.as_ptr().cast::<c_char>()) };
    assert_eq!(r_utf8, FFI_ERR_INVALID_UTF8);

    let poll_err = decode_and_free(totaldrop_win_session_poll_events_ndjson(999_999))?;
    assert_strict_four_field_error(&poll_err, "invalid_handle", Some("errorOther"))?;

    // Idle shutdown is fast and idempotent.
    assert_eq!(totaldrop_win_shutdown(100), FFI_OK);
    assert_eq!(totaldrop_win_shutdown(100), FFI_OK);
    Ok(())
}

fn contains_disallowed_ui_char(text: &str) -> bool {
    text.chars().any(|ch| {
        if ch.is_control() {
            return true;
        }
        let cp = ch as u32;
        matches!(
            cp,
            0x00AD
                | 0x061C
                | 0x180E
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x206F
                | 0xFDD0..=0xFDEF
                | 0xFEFF
                | 0xFFF9..=0xFFFB
                | 0xE0000..=0xE007F
        ) || (cp & 0xFFFE) == 0xFFFE
    })
}

#[test]
fn ui_bundle_json_strips_control_and_bidi_chars_and_falls_back_cleanly() -> TestResult {
    // Direct reproduction of poisoned region_tag and app_version containing
    // ANSI ESC, Bidi RLO, BEL, NEL, and C1 CSI.
    let langs = c_str("en-US")?;
    let poisoned_region = c_str("\x1b[31m\u{202E}en-US\u{0085}")?;
    let poisoned_version = c_str("0.1.0\x1b[31m\u{202E}\x07\u{009B}31m")?;
    // SAFETY: All three pointers are live NUL-terminated CStrings.
    let bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(
            langs.as_ptr(),
            poisoned_region.as_ptr(),
            poisoned_version.as_ptr(),
        )
    })?;
    let region_out = bundle
        .get("region_tag")
        .and_then(Value::as_str)
        .ok_or("missing region_tag")?;
    let version_out = bundle
        .get("version_label")
        .and_then(Value::as_str)
        .ok_or("missing version_label")?;
    assert!(
        !contains_disallowed_ui_char(region_out),
        "region_tag leaked disallowed control/Bidi char: {region_out:?}"
    );
    assert!(
        !contains_disallowed_ui_char(version_out),
        "version_label leaked disallowed control/Bidi char: {version_out:?}"
    );
    assert_eq!(region_out, "[31men-US");
    assert!(version_out.contains("0.1.0[31m31m"));

    // Poisoned lang_tags (both raw CSV and JSON \uXXXX escapes) with NULL region_tag
    // must never echo raw control or Bidi chars via WindowsLocalizer's region fallback.
    for raw_lang in [
        "\x1b[31m\u{202E}en-US\x07",
        r#"["\u001b[31m\u202een-US\u009b31m"]"#,
    ] {
        let poisoned_langs = c_str(raw_lang)?;
        // SAFETY: `poisoned_langs` is a live NUL-terminated CString; nulls are accepted.
        let lang_fallback_bundle = decode_and_free(unsafe {
            totaldrop_win_ui_bundle_json(poisoned_langs.as_ptr(), ptr::null(), ptr::null())
        })?;
        let echoed_region = lang_fallback_bundle
            .get("region_tag")
            .and_then(Value::as_str)
            .ok_or("missing region_tag")?;
        assert!(
            !contains_disallowed_ui_char(echoed_region),
            "lang_tags fallback leaked disallowed char into region_tag: {echoed_region:?}"
        );
    }

    // All-control / all-Bidi region_tag and app_version fall back cleanly to defaults.
    let all_control = c_str("\x1b\u{202E}\x07\u{009B}\u{200B}\u{FEFF}\u{2028}\u{2029}   ")?;
    // SAFETY: Both pointers are live NUL-terminated CStrings.
    let fallback_bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(langs.as_ptr(), all_control.as_ptr(), all_control.as_ptr())
    })?;
    assert_eq!(
        fallback_bundle.get("region_tag").and_then(Value::as_str),
        Some("en-US")
    );
    assert!(
        fallback_bundle
            .get("version_label")
            .and_then(Value::as_str)
            .is_some_and(|v| v.contains(APP_VERSION) && !contains_disallowed_ui_char(v))
    );

    // All-control / all-Bidi across all three parameters falls back cleanly to English defaults.
    // SAFETY: All three pointers are live NUL-terminated CStrings.
    let all_ctrl_bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(
            all_control.as_ptr(),
            all_control.as_ptr(),
            all_control.as_ptr(),
        )
    })?;
    assert_eq!(
        all_ctrl_bundle.get("language_tag").and_then(Value::as_str),
        Some("en")
    );
    assert_eq!(
        all_ctrl_bundle.get("region_tag").and_then(Value::as_str),
        Some("en")
    );
    assert!(
        all_ctrl_bundle
            .get("version_label")
            .and_then(Value::as_str)
            .is_some_and(|v| v.contains(APP_VERSION) && !contains_disallowed_ui_char(v))
    );

    // Clean BCP 47 tags and SemVer strings pass through unchanged.
    for (lang_tag, reg_tag, ver_str) in [
        ("en-US", "en-US", "0.1.0-beta.1"),
        ("tr-TR", "tr-TR", "0.1.0-beta.1"),
        ("zh-Hant-TW", "zh-Hant-TW", "0.1.0-beta.1"),
    ] {
        let l = c_str(lang_tag)?;
        let r = c_str(reg_tag)?;
        let v = c_str(ver_str)?;
        // SAFETY: All three pointers are live NUL-terminated CStrings.
        let clean = decode_and_free(unsafe {
            totaldrop_win_ui_bundle_json(l.as_ptr(), r.as_ptr(), v.as_ptr())
        })?;
        assert_eq!(
            clean.get("region_tag").and_then(Value::as_str),
            Some(reg_tag)
        );
        assert!(
            clean
                .get("version_label")
                .and_then(Value::as_str)
                .is_some_and(|label| label.contains(ver_str))
        );
    }
    Ok(())
}

#[test]
fn validate_input_json_bounds_unknown_word_message_and_preserves_oversized_kind() -> TestResult {
    // 64 KiB unknown word must preserve exact kind/l10n_key while bounding error.message.
    let huge_unknown = c_str(&format!("7-harbor-{}", "x".repeat(65_536)))?;
    // SAFETY: `huge_unknown` is a live NUL-terminated CString.
    let err = decode_and_free(unsafe { totaldrop_win_validate_input_json(huge_unknown.as_ptr()) })?;
    assert_eq!(err.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        err.pointer("/error/kind").and_then(Value::as_str),
        Some("unknown_word")
    );
    assert_eq!(
        err.pointer("/error/l10n_key").and_then(Value::as_str),
        Some("receiveCodeInvalid")
    );
    let msg = err
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("missing error.message")?;
    assert!(
        msg.len() < 256,
        "expected bounded error.message (< 256 bytes), got {} bytes",
        msg.len()
    );
    assert!(
        msg.contains("..."),
        "expected truncated error.message to contain '...', got {msg:?}"
    );
    assert!(
        !msg.chars().any(char::is_control),
        "expected zero raw control characters in error.message: {msg:?}"
    );

    // Exact 64-char unknown word is preserved untruncated; 65 chars truncates with "...".
    let word64 = "a".repeat(64);
    let input64 = c_str(&format!("7-harbor-{word64}"))?;
    // SAFETY: `input64` is a live NUL-terminated CString.
    let err64 = decode_and_free(unsafe { totaldrop_win_validate_input_json(input64.as_ptr()) })?;
    let msg64 = err64
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("missing error.message")?;
    assert!(!msg64.contains("..."));
    assert!(msg64.contains(&word64));

    let input65 = c_str(&format!("7-harbor-{}", "a".repeat(65)))?;
    // SAFETY: `input65` is a live NUL-terminated CString.
    let err65 = decode_and_free(unsafe { totaldrop_win_validate_input_json(input65.as_ptr()) })?;
    let msg65 = err65
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("missing error.message")?;
    assert!(msg65.contains("..."));
    assert!(msg65.len() < 256);

    // Oversized unknown word with embedded ANSI ESC keeps control chars escaped and bounded.
    let escaped_unknown = c_str(&format!("7-harbor-\x1b{}", "y".repeat(200)))?;
    // SAFETY: `escaped_unknown` is a live NUL-terminated CString.
    let esc_err =
        decode_and_free(unsafe { totaldrop_win_validate_input_json(escaped_unknown.as_ptr()) })?;
    let esc_msg = esc_err
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("missing error.message")?;
    assert!(esc_msg.len() < 256);
    assert!(esc_msg.contains("..."));
    assert!(!esc_msg.chars().any(char::is_control));

    // M5 compatibility invariant: 2 MiB single-token input must still classify as
    // `bad_nameplate` with `receiveCodeInvalid`.
    let two_mib = c_str(&"x".repeat(2_097_152))?;
    // SAFETY: `two_mib` is a live NUL-terminated CString.
    let two_mib_err =
        decode_and_free(unsafe { totaldrop_win_validate_input_json(two_mib.as_ptr()) })?;
    assert_eq!(two_mib_err.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        two_mib_err.pointer("/error/kind").and_then(Value::as_str),
        Some("bad_nameplate")
    );
    assert_eq!(
        two_mib_err
            .pointer("/error/l10n_key")
            .and_then(Value::as_str),
        Some("receiveCodeInvalid")
    );
    Ok(())
}

#[test]
fn build_localizer_sanitizes_region_and_lang_metadata_across_exports() -> TestResult {
    let poisoned_langs = c_str("\x1b[31m\u{202E}de-DE\u{FDD0}\u{E0041},en-US")?;
    let poisoned_region = c_str("\u{2066}\u{202E}de-DE\x1b[31m\u{009B}31m\u{FFFF}\u{E0041}")?;
    let poisoned_ver = c_str("\u{202E}0.1.0\u{FDD0}\u{E007F}")?;

    // 1. ui_bundle_json
    // SAFETY: All three pointers are live NUL-terminated CStrings.
    let bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(
            poisoned_langs.as_ptr(),
            poisoned_region.as_ptr(),
            poisoned_ver.as_ptr(),
        )
    })?;
    let region_out = bundle
        .get("region_tag")
        .and_then(Value::as_str)
        .ok_or("missing region_tag")?;
    assert!(!contains_disallowed_ui_char(region_out));
    assert_eq!(
        bundle.get("language_tag").and_then(Value::as_str),
        Some("en")
    );

    // 2. format_bytes_json uses build_localizer (poisoned de-DE still formats cleanly with zero raw hidden chars)
    let clean_en = c_str("en-US")?;
    let dirty_de = c_str("\x1b\u{202E}de-DE\u{009B}\u{FDD0}\u{E0041}")?;
    // SAFETY: Both pointers are live NUL-terminated CStrings.
    let bytes_json = decode_and_free(unsafe {
        totaldrop_win_format_bytes_json(1_500_000, clean_en.as_ptr(), dirty_de.as_ptr())
    })?;
    let formatted_bytes = bytes_json
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing formatted bytes")?;
    assert_eq!(formatted_bytes, "1,5 MB");
    assert!(!contains_disallowed_ui_char(formatted_bytes));

    // 3. format_message_json uses build_localizer with poisoned lang_tags & region_tag
    let key = c_str("sendDoneBody")?;
    let args = c_str(r#"{"count":3}"#)?;
    let dirty_tr = c_str("\u{202E}\x1btr-TR\u{FDD0}\u{E0041}")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let msg_json = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            key.as_ptr(),
            args.as_ptr(),
            dirty_tr.as_ptr(),
            dirty_tr.as_ptr(),
        )
    })?;
    assert_eq!(
        msg_json.get("language_tag").and_then(Value::as_str),
        Some("tr")
    );
    let formatted_msg = msg_json
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing formatted message")?;
    assert!(!contains_disallowed_ui_char(formatted_msg));
    Ok(())
}

#[test]
fn format_message_json_defeats_rtl_pdi_breakout_and_preserves_m5_share_isolate() -> TestResult {
    let ar = c_str("ar-SA")?;
    let ar_reg = c_str("ar-EG")?;

    // 1. Arabic RTL PDI breakout + RLO + ANSI ESC + C1 CSI + noncharacters + Unicode Tag
    // inside `receiveSaveTo` folder argument must be revealed, leaving only outer FSI/PDI balance.
    let save_key = c_str("receiveSaveTo")?;
    let attack_folder = concat!(
        r"C:\Users\",
        "\u{2069}\u{202E}evil\x1b[31m\u{009B}31m\u{FDD0}\u{FFFF}\u{E0041}"
    );
    let save_args = c_str(&serde_json::json!({ "folder": attack_folder }).to_string())?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let save_res = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            save_key.as_ptr(),
            save_args.as_ptr(),
            ar.as_ptr(),
            ar_reg.as_ptr(),
        )
    })?;
    let rendered = save_res
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing formatted")?;
    for expected_escape in [
        "<U+2069>",
        "<U+202E>",
        "<U+001B>",
        "<U+009B>",
        "<U+FDD0>",
        "<U+FFFF>",
        "<U+E0041>",
    ] {
        assert!(
            rendered.contains(expected_escape),
            "expected {expected_escape} in {rendered:?}"
        );
    }
    // Zero raw control/RLO/noncharacter/Tag characters anywhere in rendered output,
    // and exactly one balanced FSI/PDI pair from totaldrop_l10n's RTL wrapper.
    assert!(!rendered.contains('\u{202E}'));
    assert!(!rendered.contains('\x1b'));
    assert!(!rendered.contains('\u{009B}'));
    assert!(!rendered.contains('\u{FDD0}'));
    assert!(!rendered.contains('\u{E0041}'));
    assert_eq!(rendered.matches('\u{2068}').count(), 1);
    assert_eq!(rendered.matches('\u{2069}').count(), 1);

    // 2. M5 contract compatibility: single outer `\u{2068}...\u{2069}` in `sendShareText`
    // is preserved verbatim, while interior PDI breakout inside outer FSI/PDI is neutralized.
    let share_key = c_str("sendShareText")?;
    let m5_args = c_str(r#"{"code":"\u20687-harbor-rocket\u2069"}"#)?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let m5_res = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            share_key.as_ptr(),
            m5_args.as_ptr(),
            ar.as_ptr(),
            ar_reg.as_ptr(),
        )
    })?;
    let m5_sentence = m5_res
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing formatted share sentence")?;
    assert!(
        m5_sentence.contains("\u{2068}7-harbor-rocket\u{2069}"),
        "M5 sendShareText outer isolate must be preserved: {m5_sentence:?}"
    );

    let nested_attack = "\u{2068}7-harbor\u{2069}\u{202E}evil\x1b[31m\u{2069}";
    let nested_args = c_str(&serde_json::json!({ "code": nested_attack }).to_string())?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let nested_res = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            share_key.as_ptr(),
            nested_args.as_ptr(),
            ar.as_ptr(),
            ar_reg.as_ptr(),
        )
    })?;
    let nested_sentence = nested_res
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing nested formatted")?;
    assert!(nested_sentence.contains("<U+2069><U+202E>evil<U+001B>[31m"));
    assert!(!nested_sentence.contains('\u{202E}'));
    assert!(!nested_sentence.contains('\x1b'));
    Ok(())
}

#[test]
fn format_message_json_and_clipboard_extract_bound_oversized_error_reflections() -> TestResult {
    let en = c_str("en-US")?;
    let empty_args = c_str("{}")?;

    // 1. Oversized unknown_key (10 KiB) bounded at 64 Unicode scalars.
    let huge_key = c_str(&"k".repeat(10_240))?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let key_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            huge_key.as_ptr(),
            empty_args.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    })?;
    assert_eq!(key_err.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        key_err.pointer("/error/kind").and_then(Value::as_str),
        Some("unknown_key")
    );
    let key_msg = key_err
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("missing key error message")?;
    assert!(
        key_msg.len() < 256,
        "unbounded unknown_key error: {} bytes",
        key_msg.len()
    );
    assert!(key_msg.contains("..."));
    assert!(!key_msg.chars().any(char::is_control));

    // Exact 64-char unknown_key is untruncated; 65-char multi-byte key truncates cleanly.
    let key64 = c_str(&"m".repeat(64))?;
    // SAFETY: Live CStrings.
    let err64 = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            key64.as_ptr(),
            empty_args.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    })?;
    let msg64 = err64
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("missing msg64")?;
    assert!(!msg64.contains("..."));

    let key65_mb = c_str(&"é".repeat(65))?;
    // SAFETY: Live CStrings.
    let err65 = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            key65_mb.as_ptr(),
            empty_args.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    })?;
    let msg65 = err65
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("missing msg65")?;
    assert!(msg65.contains("..."));
    assert!(msg65.len() < 256);

    // 2. Oversized invalid arg_name (numeric negative AND unsupported bool) bounded at 64 scalars.
    let valid_key = c_str("sendDoneBody")?;
    let huge_arg_name = "a".repeat(12_000);
    let neg_args = c_str(&serde_json::json!({ &huge_arg_name: -1 }).to_string())?;
    // SAFETY: Live CStrings.
    let neg_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            valid_key.as_ptr(),
            neg_args.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    })?;
    assert_eq!(
        neg_err.pointer("/error/kind").and_then(Value::as_str),
        Some("invalid_args")
    );
    let neg_msg = neg_err
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("missing neg_msg")?;
    assert!(
        neg_msg.len() < 256,
        "unbounded numeric arg_name error: {} bytes",
        neg_msg.len()
    );
    assert!(neg_msg.contains("..."));

    let bool_args = c_str(&serde_json::json!({ &huge_arg_name: true }).to_string())?;
    // SAFETY: Live CStrings.
    let bool_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            valid_key.as_ptr(),
            bool_args.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    })?;
    assert_eq!(
        bool_err.pointer("/error/kind").and_then(Value::as_str),
        Some("invalid_args")
    );
    let bool_msg = bool_err
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("missing bool_msg")?;
    assert!(
        bool_msg.len() < 256,
        "unbounded type arg_name error: {} bytes",
        bool_msg.len()
    );
    assert!(bool_msg.contains("..."));

    // 3. extract_clipboard_code_json with huge non-code text stays bounded and control-free.
    let huge_clip = c_str(&format!("7-harbor-\x1b\u{202E}{}", "z".repeat(20_000)))?;
    // SAFETY: Live CString.
    let clip_err =
        decode_and_free(unsafe { totaldrop_win_extract_clipboard_code_json(huge_clip.as_ptr()) })?;
    assert_eq!(clip_err.get("ok").and_then(Value::as_bool), Some(false));
    let clip_msg = clip_err
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("missing clip_msg")?;
    assert!(
        clip_msg.len() < 256,
        "unbounded clipboard error: {} bytes",
        clip_msg.len()
    );
    assert!(!contains_disallowed_ui_char(clip_msg));
    Ok(())
}

fn take_raw_and_free(ptr: *mut c_char) -> Result<String, Box<dyn StdError>> {
    if ptr.is_null() {
        return Err("FFI returned unexpected null pointer".into());
    }
    // SAFETY: `ptr` was freshly returned by a `totaldrop_win_*` FFI export.
    let raw = unsafe { CStr::from_ptr(ptr) }.to_str()?.to_owned();
    // SAFETY: `ptr` was allocated by `totaldrop-windows-ffi` and is freed once.
    unsafe { totaldrop_win_string_free(ptr) };
    Ok(raw)
}

fn frame_raw_json(json: &str) -> Result<Vec<u8>, Box<dyn StdError>> {
    let payload = json.as_bytes();
    let len = u32::try_from(payload.len())?;
    let mut frame = Vec::with_capacity(payload.len().saturating_add(4));
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

#[test]
fn router_lifecycle_chunked_framing_locale_animations_and_ndjson_drain() -> TestResult {
    let en = c_str("en-US")?;
    let tr = c_str("tr-TR")?;
    let ar = c_str("ar-EG")?;
    let ver = c_str("0.1.0-beta.1")?;

    // SAFETY: All CStrings are live NUL-terminated UTF-8 buffers.
    let h1 =
        unsafe { totaldrop_win_router_create(1, en.as_ptr(), en.as_ptr(), ver.as_ptr(), true) };
    // SAFETY: Null optional strings default safely to English and APP_VERSION.
    let h2 =
        unsafe { totaldrop_win_router_create(2, ptr::null(), ptr::null(), ptr::null(), false) };
    assert_ne!(h1, 0);
    assert!(h2 > h1, "router handles must be strictly monotonic");

    // Startup outbox emits UiBundleReady + MarkAnimationState(animate: false).
    let initial_ndjson = take_raw_and_free(totaldrop_win_router_drain_ndjson(h1))?;
    let initial_lines: Vec<Value> = initial_ndjson
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(initial_lines.len(), 2);
    assert_eq!(
        initial_lines
            .first()
            .and_then(|v| v.get("kind"))
            .and_then(Value::as_str),
        Some("ui_bundle_ready")
    );
    assert_eq!(
        initial_lines
            .get(1)
            .and_then(|v| v.get("kind"))
            .and_then(Value::as_str),
        Some("mark_animation_state")
    );
    // Draining again returns empty string.
    assert_eq!(
        take_raw_and_free(totaldrop_win_router_drain_ndjson(h1))?,
        ""
    );

    // Locale update returns WinUiBridgeMessage(ui_bundle_ready) with RTL flow for Arabic.
    // SAFETY: `ar` is a live NUL-terminated CString.
    let locale_msg = decode_and_free(unsafe {
        totaldrop_win_router_update_locale_json(h1, ar.as_ptr(), ar.as_ptr())
    })?;
    assert_eq!(
        locale_msg.get("kind").and_then(Value::as_str),
        Some("ui_bundle_ready")
    );
    assert_eq!(
        locale_msg
            .get("data")
            .and_then(|d| d.get("flow_direction"))
            .and_then(Value::as_str),
        Some("RightToLeft")
    );
    // Switch back to Turkish for later assertions.
    // SAFETY: `tr` is a live NUL-terminated CString.
    let _ = decode_and_free(unsafe {
        totaldrop_win_router_update_locale_json(h1, tr.as_ptr(), tr.as_ptr())
    })?;

    // Activity + animations toggle: transferring && enabled => animate == true.
    let xfer = c_str(r#"{"state":"transferring","done_bytes":512,"total_bytes":4096}"#)?;
    // SAFETY: `xfer` is a live NUL-terminated CString.
    let anim_on =
        decode_and_free(unsafe { totaldrop_win_router_set_activity_json(h1, xfer.as_ptr()) })?;
    assert_eq!(
        anim_on.get("kind").and_then(Value::as_str),
        Some("mark_animation_state")
    );
    assert_eq!(
        anim_on
            .get("data")
            .and_then(|d| d.get("animate"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        anim_on
            .get("data")
            .and_then(|d| d.get("hex_light"))
            .and_then(Value::as_str),
        Some("#6D4AE0")
    );
    assert_eq!(
        anim_on
            .get("data")
            .and_then(|d| d.get("hex_dark"))
            .and_then(Value::as_str),
        Some("#A68BFF")
    );
    assert_eq!(
        anim_on
            .get("data")
            .and_then(|d| d.get("cycle_ms"))
            .and_then(Value::as_u64),
        Some(3200)
    );

    let anim_off = decode_and_free(totaldrop_win_router_set_animations_json(h1, false))?;
    assert_eq!(
        anim_off
            .get("data")
            .and_then(|d| d.get("animate"))
            .and_then(Value::as_bool),
        Some(false)
    );

    // Return to idle and feed two back-to-back framed envelopes 1 byte at a time (T1-F17-01 / T1-F17-02).
    let idle = c_str(r#"{"state":"idle"}"#)?;
    // SAFETY: `idle` is a live NUL-terminated CString.
    let _ = decode_and_free(unsafe { totaldrop_win_router_set_activity_json(h1, idle.as_ptr()) })?;
    let _ = take_raw_and_free(totaldrop_win_router_drain_ndjson(h1))?;

    let env1 = ActivationEnvelope::explorer_send([r"C:\Users\Alice\doc.pdf"], Some(42))?;
    let env2 = ActivationEnvelope::protocol_uri("totaldrop://r/7-harbor-rocket", Some(43))?;
    let mut stream = env1.encode_ipc_frame()?;
    stream.extend_from_slice(&env2.encode_ipc_frame()?);

    let mut collected = Vec::new();
    for byte in &stream {
        // SAFETY: `byte` points to 1 valid readable byte.
        let batch = decode_and_free(unsafe {
            totaldrop_win_router_ingest_ipc_bytes_json(h1, ptr::from_ref(byte), 1)
        })?;
        let arr = batch.as_array().ok_or("expected RouterDecision[]")?;
        collected.extend(arr.iter().cloned());
    }
    assert_eq!(collected.len(), 2);
    assert_eq!(
        collected
            .first()
            .and_then(|d| d.get("decision"))
            .and_then(Value::as_str),
        Some("navigate_send_files")
    );
    assert_eq!(
        collected
            .get(1)
            .and_then(|d| d.get("decision"))
            .and_then(Value::as_str),
        Some("navigate_receive_code")
    );

    // Clean 0-byte EOF flush with NULL pointer is UB-free and returns "[]".
    // SAFETY: `len == 0` never dereferences `ptr`.
    let eof_ok =
        decode_and_free(unsafe { totaldrop_win_router_ingest_ipc_bytes_json(h1, ptr::null(), 0) })?;
    assert_eq!(eof_ok, serde_json::json!([]));

    // Drained NDJSON contains both route_decision snapshots.
    let drained = take_raw_and_free(totaldrop_win_router_drain_ndjson(h1))?;
    let route_count = drained
        .lines()
        .filter(|line| line.contains(r#""kind":"route_decision""#))
        .count();
    assert_eq!(route_count, 2);

    assert_eq!(totaldrop_win_router_destroy(h1), FFI_OK);
    assert_eq!(totaldrop_win_router_destroy(h1), FFI_ERR_INVALID_HANDLE);
    assert_eq!(totaldrop_win_router_destroy(h2), FFI_OK);
    Ok(())
}

#[test]
fn router_ipc_frame_bounds_eof_truncation_and_schema_rejections() -> TestResult {
    let en = c_str("en-US")?;
    // SAFETY: `en` is a live NUL-terminated CString.
    let router =
        unsafe { totaldrop_win_router_create(1, en.as_ptr(), en.as_ptr(), ptr::null(), true) };
    assert_ne!(router, 0);
    let _ = take_raw_and_free(totaldrop_win_router_drain_ndjson(router))?;

    // 1. Zero-length frame (0x00000000) -> malformed_ipc_frame (T2-F17-01).
    let zero_hdr = 0u32.to_le_bytes();
    // SAFETY: `zero_hdr` is 4 readable bytes.
    let err_zero = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, zero_hdr.as_ptr(), zero_hdr.len())
    })?;
    assert_strict_four_field_error(&err_zero, "malformed_ipc_frame", Some("errorOther"))?;

    // 2. Exact MAX_IPC_FRAME_BYTES (4_194_304) padded JSON frame succeeds (T2-F17-02).
    let base_json = r#"{"version":1,"payload":{"kind":"open_screen","screen":"receive"}}"#;
    let pad_len = MAX_IPC_FRAME_BYTES
        .checked_sub(base_json.len())
        .ok_or("base json exceeds MAX_IPC_FRAME_BYTES")?;
    let mut max_frame = Vec::with_capacity(MAX_IPC_FRAME_BYTES.saturating_add(4));
    max_frame.extend_from_slice(&u32::try_from(MAX_IPC_FRAME_BYTES)?.to_le_bytes());
    max_frame.extend_from_slice(base_json.as_bytes());
    max_frame.resize(max_frame.len().saturating_add(pad_len), b' ');
    // SAFETY: `max_frame` is a live byte slice.
    let exact_ok = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, max_frame.as_ptr(), max_frame.len())
    })?;
    let exact_arr = exact_ok.as_array().ok_or("expected RouterDecision[]")?;
    assert_eq!(exact_arr.len(), 1);
    assert_eq!(
        exact_arr
            .first()
            .and_then(|d| d.get("decision"))
            .and_then(Value::as_str),
        Some("switch_screen")
    );
    let _ = take_raw_and_free(totaldrop_win_router_drain_ndjson(router))?;

    // 3. 4_194_305 and u32::MAX headers rejected immediately before allocation + clean recovery (T2-F17-02).
    for oversized in [4_194_305u32, u32::MAX] {
        let hdr = oversized.to_le_bytes();
        // SAFETY: `hdr` is 4 readable bytes.
        let err = decode_and_free(unsafe {
            totaldrop_win_router_ingest_ipc_bytes_json(router, hdr.as_ptr(), hdr.len())
        })?;
        assert_strict_four_field_error(&err, "envelope_too_large", Some("errorOther"))?;
        let msg = err
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .ok_or("missing message")?;
        assert!(msg.contains(&oversized.to_string()));
        assert!(msg.contains("4194304"));
    }

    // 4. Truncated 2-byte header and 40/100-byte payload fail on 0-byte EOF flush and recover (T2-F17-03).
    let two_bytes = [0x20u8, 0x00];
    // SAFETY: `two_bytes` is 2 readable bytes.
    let part_hdr = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, two_bytes.as_ptr(), two_bytes.len())
    })?;
    assert_eq!(part_hdr, serde_json::json!([]));
    // SAFETY: `len == 0` signals EOF flush.
    let eof_hdr_err = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, ptr::null(), 0)
    })?;
    assert_strict_four_field_error(&eof_hdr_err, "malformed_ipc_frame", Some("errorOther"))?;

    let mut partial_payload = Vec::with_capacity(44);
    partial_payload.extend_from_slice(&100u32.to_le_bytes());
    partial_payload.extend_from_slice(&[b' '; 40]);
    // SAFETY: `partial_payload` is 44 readable bytes.
    let part_body = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(
            router,
            partial_payload.as_ptr(),
            partial_payload.len(),
        )
    })?;
    assert_eq!(part_body, serde_json::json!([]));
    // SAFETY: `len == 0` signals EOF flush.
    let eof_body_err = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, ptr::null(), 0)
    })?;
    assert_strict_four_field_error(&eof_body_err, "malformed_ipc_frame", Some("errorOther"))?;

    // 5. Unsupported schema versions (2, 0), path traversal, tampered canonical URI, and 10,001 ShareTarget items (T2-F17-04, T2-F18-03).
    for bad_ver_json in [
        r#"{"version":2,"payload":{"kind":"open_screen","screen":"send"}}"#,
        r#"{"version":0,"payload":{"kind":"open_screen","screen":"send"}}"#,
    ] {
        let f = frame_raw_json(bad_ver_json)?;
        // SAFETY: `f` is a live slice.
        let err = decode_and_free(unsafe {
            totaldrop_win_router_ingest_ipc_bytes_json(router, f.as_ptr(), f.len())
        })?;
        assert_strict_four_field_error(&err, "unsupported_schema_version", Some("errorOther"))?;
    }

    let traversal_frame = frame_raw_json(
        r#"{"version":1,"payload":{"kind":"explorer_send","paths":["C:\\Users\\Alice\\..\\secret.txt"]}}"#,
    )?;
    // SAFETY: `traversal_frame` is a live slice.
    let traversal_err = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(
            router,
            traversal_frame.as_ptr(),
            traversal_frame.len(),
        )
    })?;
    assert_strict_four_field_error(&traversal_err, "invalid_json", Some("errorOther"))?;

    let tampered_uri_frame = frame_raw_json(
        r#"{"version":1,"payload":{"kind":"protocol_uri","code":{"nameplate":7,"word_count":2,"display_english":"7-harbor-rocket","canonical":"7-999-999","ltr_isolated":"\u20687-harbor-rocket\u2069","protocol_uri":"totaldrop://r/7-harbor-rocket","web_uri":"https://totaldrop.app/r#7-harbor-rocket"}}}"#,
    )?;
    // SAFETY: `tampered_uri_frame` is a live slice.
    let tampered_err = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(
            router,
            tampered_uri_frame.as_ptr(),
            tampered_uri_frame.len(),
        )
    })?;
    assert_strict_four_field_error(&tampered_err, "invalid_uri", Some("errorInvalidCode"))?;

    // Valid canonical + nameplate + display_english, but tampered web_uri / ltr_isolated / protocol_uri / word_count.
    let valid_code = totaldrop_windows_bridge::ValidatedCode::from_user_input("7-harbor-rocket")?;
    let mut tampered_web = valid_code.clone();
    tampered_web.web_uri = "https://evil.example/r#7-harbor-rocket".to_owned();
    let mut tampered_ltr = valid_code.clone();
    tampered_ltr.ltr_isolated = "spoofed".to_owned();
    let mut tampered_proto = valid_code.clone();
    tampered_proto.protocol_uri = "https://evil.example/r#7-harbor-rocket".to_owned();
    let mut tampered_wc = valid_code;
    tampered_wc.word_count = 3;

    for tampered in [tampered_web, tampered_ltr, tampered_proto, tampered_wc] {
        let tampered_json = serde_json::json!({
            "version": 1,
            "payload": {
                "kind": "protocol_uri",
                "code": tampered,
            }
        })
        .to_string();
        let frame = frame_raw_json(&tampered_json)?;
        // SAFETY: `frame` is a live slice.
        let err = decode_and_free(unsafe {
            totaldrop_win_router_ingest_ipc_bytes_json(router, frame.as_ptr(), frame.len())
        })?;
        assert_strict_four_field_error(&err, "invalid_uri", Some("errorInvalidCode"))?;
    }

    let too_many_paths: Vec<String> = (0..10_001)
        .map(|i| format!(r"C:\Users\Alice\f{i}.txt"))
        .collect();
    let too_many_json = serde_json::json!({
        "version": 1,
        "payload": {
            "kind": "share_target",
            "paths": too_many_paths,
            "text": Value::Null,
        }
    })
    .to_string();
    let too_many_frame = frame_raw_json(&too_many_json)?;
    // SAFETY: `too_many_frame` is a live slice.
    let too_many_err = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(
            router,
            too_many_frame.as_ptr(),
            too_many_frame.len(),
        )
    })?;
    assert_strict_four_field_error(&too_many_err, "too_many_items", Some("errorStorage"))?;
    assert!(
        too_many_err
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("10001") && m.contains("10000"))
    );

    // Zero route_decision messages were queued across all rejected frames, and recovery works.
    assert_eq!(
        take_raw_and_free(totaldrop_win_router_drain_ndjson(router))?,
        ""
    );
    let ok_frame =
        ActivationEnvelope::open_screen(ScreenTarget::Settings, None).encode_ipc_frame()?;
    // SAFETY: `ok_frame` is a live slice.
    let ok_dec = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, ok_frame.as_ptr(), ok_frame.len())
    })?;
    assert_eq!(
        ok_dec
            .as_array()
            .and_then(|a| a.first())
            .and_then(|d| d.get("screen"))
            .and_then(Value::as_str),
        Some("settings")
    );

    assert_eq!(totaldrop_win_router_destroy(router), FFI_OK);
    Ok(())
}

#[test]
fn router_busy_states_share_target_unc_text_bidi_and_error_safety() -> TestResult {
    let en = c_str("en-US")?;
    // SAFETY: `en` is a live NUL-terminated CString.
    let router =
        unsafe { totaldrop_win_router_create(1, en.as_ptr(), en.as_ptr(), ptr::null(), true) };
    assert_ne!(router, 0);

    // 1. ShareTarget UNC normalization (T1-F18-02).
    let unc_frame = frame_raw_json(
        r#"{"version":1,"payload":{"kind":"share_target","paths":["\\\\nas01\\share\\brief.pdf","C:\\Users\\Alice\\a.txt"],"text":null}}"#,
    )?;
    // SAFETY: `unc_frame` is a live slice.
    let unc_res = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, unc_frame.as_ptr(), unc_frame.len())
    })?;
    let unc_dec = unc_res
        .as_array()
        .and_then(|a| a.first())
        .ok_or("missing unc decision")?;
    assert_eq!(
        unc_dec.get("decision").and_then(Value::as_str),
        Some("navigate_send_files")
    );
    assert_eq!(
        unc_dec.get("paths"),
        Some(&serde_json::json!([
            r"\\?\UNC\nas01\share\brief.pdf",
            r"\\?\C:\Users\Alice\a.txt"
        ]))
    );

    // 2. ShareTarget plain text -> navigate_send_text with Bidi reveal (T1-F18-03, T2-F18-04).
    let bidi_text_json = serde_json::json!({
        "version": 1,
        "payload": {
            "kind": "share_target",
            "paths": [],
            "text": "hello \u{202E}txt.exe"
        }
    })
    .to_string();
    let bidi_frame = frame_raw_json(&bidi_text_json)?;
    // SAFETY: `bidi_frame` is a live slice.
    let bidi_res = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, bidi_frame.as_ptr(), bidi_frame.len())
    })?;
    let bidi_dec = bidi_res
        .as_array()
        .and_then(|a| a.first())
        .ok_or("missing bidi decision")?;
    assert_eq!(
        bidi_dec.get("decision").and_then(Value::as_str),
        Some("navigate_send_text")
    );
    assert_eq!(
        bidi_dec.get("raw_text").and_then(Value::as_str),
        Some("hello \u{202E}txt.exe")
    );
    assert_eq!(
        bidi_dec
            .get("sanitized_preview")
            .and_then(|p| p.get("display_text"))
            .and_then(Value::as_str),
        Some("hello <U+202E>txt.exe")
    );
    assert_eq!(
        bidi_dec
            .get("sanitized_preview")
            .and_then(|p| p.get("has_hidden_controls"))
            .and_then(Value::as_bool),
        Some(true)
    );

    // 3. Empty ShareTarget -> switch_screen("send").
    let empty_share_frame = frame_raw_json(
        r#"{"version":1,"payload":{"kind":"share_target","paths":[],"text":null}}"#,
    )?;
    // SAFETY: `empty_share_frame` is a live slice.
    let empty_res = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(
            router,
            empty_share_frame.as_ptr(),
            empty_share_frame.len(),
        )
    })?;
    assert_eq!(
        empty_res
            .as_array()
            .and_then(|a| a.first())
            .and_then(|d| d.get("decision"))
            .and_then(Value::as_str),
        Some("switch_screen")
    );
    assert_eq!(
        empty_res
            .as_array()
            .and_then(|a| a.first())
            .and_then(|d| d.get("screen"))
            .and_then(Value::as_str),
        Some("send")
    );

    // 4. All 6 busy states reject explorer_send, share_target, and protocol_uri with reject_busy
    //    (shareBusy vs linkBusy) without mutating activity state (T2-F17-05, T3-07, T3-11).
    // SAFETY: `en` is a live NUL-terminated CString.
    let bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(en.as_ptr(), en.as_ptr(), ptr::null())
    })?;
    let share_busy = bundle
        .get("share_busy")
        .and_then(Value::as_str)
        .ok_or("missing share_busy")?;
    let link_busy = bundle
        .get("link_busy")
        .and_then(Value::as_str)
        .ok_or("missing link_busy")?;
    assert_ne!(share_busy, link_busy);

    let explorer_frame = ActivationEnvelope::explorer_send([r"C:\Users\Alice\busy.bin"], Some(10))?
        .encode_ipc_frame()?;
    let proto_frame = ActivationEnvelope::protocol_uri("totaldrop://r/7-harbor-rocket", Some(11))?
        .encode_ipc_frame()?;

    // Verify both full and minimal JSON forms work for busy states.
    for state_json in [
        r#"{"state":"preparing_send"}"#,
        r#"{"state":"waiting_for_peer"}"#,
        r#"{"state":"connecting_receive"}"#,
        r#"{"state":"offer_prompt_pending"}"#,
        r#"{"state":"transferring","done_bytes":512,"total_bytes":4096}"#,
        r#"{"state":"showing_text_note"}"#,
    ] {
        let state_c = c_str(state_json)?;
        // SAFETY: `state_c` is a live NUL-terminated CString.
        let mark = decode_and_free(unsafe {
            totaldrop_win_router_set_activity_json(router, state_c.as_ptr())
        })?;
        assert_eq!(
            mark.get("kind").and_then(Value::as_str),
            Some("mark_animation_state")
        );

        for (frame, expected_banner) in [
            (&explorer_frame, share_busy),
            (&unc_frame, share_busy),
            (&proto_frame, link_busy),
        ] {
            // SAFETY: `frame` is a live slice.
            let decs = decode_and_free(unsafe {
                totaldrop_win_router_ingest_ipc_bytes_json(router, frame.as_ptr(), frame.len())
            })?;
            let first = decs
                .as_array()
                .and_then(|a| a.first())
                .ok_or("missing busy decision")?;
            assert_eq!(
                first.get("decision").and_then(Value::as_str),
                Some("reject_busy")
            );
            assert_eq!(
                first.get("localized_banner").and_then(Value::as_str),
                Some(expected_banner)
            );
        }
    }

    // 5. Invalid/null/UTF-8/destroyed router handle guards.
    let bad_utf8: [u8; 2] = [0xFF, 0x00];
    let bad_utf8_ptr = bad_utf8.as_ptr().cast::<c_char>();
    // SAFETY: `bad_utf8_ptr` is NUL-terminated invalid UTF-8.
    let bad_utf8_router =
        unsafe { totaldrop_win_router_create(1, bad_utf8_ptr, ptr::null(), ptr::null(), true) };
    assert_eq!(bad_utf8_router, 0);

    // SAFETY: `ptr::null()` with `len > 0` returns null_pointer without dereference.
    let null_buf_err = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, ptr::null(), 4)
    })?;
    assert_strict_four_field_error(&null_buf_err, "null_pointer", Some("errorOther"))?;

    // SAFETY: `len > isize::MAX` returns envelope_too_large without dereference.
    let huge_len_err = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, explorer_frame.as_ptr(), usize::MAX)
    })?;
    assert_strict_four_field_error(&huge_len_err, "envelope_too_large", Some("errorOther"))?;

    // SAFETY: Null activity JSON returns null_pointer; unknown state returns invalid_json.
    let null_act_err =
        decode_and_free(unsafe { totaldrop_win_router_set_activity_json(router, ptr::null()) })?;
    assert_strict_four_field_error(&null_act_err, "null_pointer", Some("errorOther"))?;

    let unknown_state = c_str(r#"{"state":"nonexistent_state"}"#)?;
    // SAFETY: `unknown_state` is a live CString.
    let bad_state_err = decode_and_free(unsafe {
        totaldrop_win_router_set_activity_json(router, unknown_state.as_ptr())
    })?;
    assert_strict_four_field_error(&bad_state_err, "invalid_json", Some("errorOther"))?;

    // SAFETY: `bad_utf8_ptr` is NUL-terminated invalid UTF-8.
    let bad_locale_err = decode_and_free(unsafe {
        totaldrop_win_router_update_locale_json(router, bad_utf8_ptr, ptr::null())
    })?;
    assert_strict_four_field_error(&bad_locale_err, "invalid_utf8", Some("errorOther"))?;

    assert_eq!(totaldrop_win_router_destroy(router), FFI_OK);
    assert_eq!(totaldrop_win_router_destroy(0), FFI_ERR_INVALID_HANDLE);
    assert_eq!(totaldrop_win_router_destroy(router), FFI_ERR_INVALID_HANDLE);

    // Destroyed router returns invalid_handle across all calls.
    // SAFETY: `len == 0` is safe even on destroyed handle.
    let dead_eof = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, ptr::null(), 0)
    })?;
    assert_strict_four_field_error(&dead_eof, "invalid_handle", Some("errorOther"))?;
    let dead_anim = decode_and_free(totaldrop_win_router_set_animations_json(router, true))?;
    assert_strict_four_field_error(&dead_anim, "invalid_handle", Some("errorOther"))?;
    let dead_drain = decode_and_free(totaldrop_win_router_drain_ndjson(router))?;
    assert_strict_four_field_error(&dead_drain, "invalid_handle", Some("errorOther"))?;
    // SAFETY: `en` is a live CString.
    let dead_loc = decode_and_free(unsafe {
        totaldrop_win_router_update_locale_json(router, en.as_ptr(), en.as_ptr())
    })?;
    assert_strict_four_field_error(&dead_loc, "invalid_handle", Some("errorOther"))?;

    Ok(())
}

#[test]
fn router_create_sanitizes_app_version_across_initial_bundle_and_locale_updates() -> TestResult {
    let en = c_str("en-US")?;
    let tr = c_str("tr-TR")?;
    let ar = c_str("ar-SA")?;
    let hostile_version = c_str("0.1.0\u{2069}\u{202E}\x1b[31m\u{009B}\u{FDD0}\u{E0041}\u{2028}")?;

    // SAFETY: All pointers are live NUL-terminated CStrings.
    let router = unsafe {
        totaldrop_win_router_create(7, en.as_ptr(), en.as_ptr(), hostile_version.as_ptr(), true)
    };
    assert_ne!(router, 0);

    let ndjson = take_raw_and_free(totaldrop_win_router_drain_ndjson(router))?;
    let first_line = ndjson
        .lines()
        .next()
        .ok_or("missing initial ui_bundle_ready line")?;
    let initial: Value = serde_json::from_str(first_line)?;
    assert_eq!(
        initial.get("kind").and_then(Value::as_str),
        Some("ui_bundle_ready")
    );
    let initial_version = initial
        .get("data")
        .and_then(|d| d.get("version_label"))
        .and_then(Value::as_str)
        .ok_or("missing initial version_label")?;
    assert!(initial_version.contains("0.1.0[31m"));
    assert!(
        !contains_disallowed_ui_char(initial_version),
        "initial router ui_bundle_ready leaked disallowed char: {initial_version:?}"
    );

    // SAFETY: `tr` is a live NUL-terminated CString.
    let updated_tr = decode_and_free(unsafe {
        totaldrop_win_router_update_locale_json(router, tr.as_ptr(), tr.as_ptr())
    })?;
    let tr_version = updated_tr
        .get("data")
        .and_then(|d| d.get("version_label"))
        .and_then(Value::as_str)
        .ok_or("missing tr version_label")?;
    assert!(tr_version.contains("0.1.0[31m"));
    assert!(
        !contains_disallowed_ui_char(tr_version),
        "router_update_locale_json (tr) leaked disallowed char: {tr_version:?}"
    );

    // Arabic RTL version label must not allow injected PDI (\u2069) breakout or raw RLO/ESC/Tag.
    // SAFETY: `ar` is a live NUL-terminated CString.
    let updated_ar = decode_and_free(unsafe {
        totaldrop_win_router_update_locale_json(router, ar.as_ptr(), ar.as_ptr())
    })?;
    let ar_version = updated_ar
        .get("data")
        .and_then(|d| d.get("version_label"))
        .and_then(Value::as_str)
        .ok_or("missing ar version_label")?;
    assert!(ar_version.contains("0.1.0[31m"));
    let ar_without_legit_isolates: String = ar_version
        .chars()
        .filter(|&c| c != '\u{2068}' && c != '\u{2069}')
        .collect();
    assert!(
        !contains_disallowed_ui_char(&ar_without_legit_isolates),
        "router_update_locale_json (ar) leaked disallowed char: {ar_version:?}"
    );
    assert!(
        ar_version.matches('\u{2069}').count() <= 1,
        "injected PDI broke out of Arabic FSI/PDI isolation: {ar_version:?}"
    );
    assert_eq!(totaldrop_win_router_destroy(router), FFI_OK);

    // All-disallowed app_version must fall back cleanly to APP_VERSION.
    let all_disallowed = c_str("\u{202E}\x1b\u{009B}\u{FDD0}\u{E0041}\u{2069}   ")?;
    // SAFETY: All pointers are live NUL-terminated CStrings.
    let fallback_router = unsafe {
        totaldrop_win_router_create(8, en.as_ptr(), en.as_ptr(), all_disallowed.as_ptr(), false)
    };
    assert_ne!(fallback_router, 0);
    let fb_ndjson = take_raw_and_free(totaldrop_win_router_drain_ndjson(fallback_router))?;
    let fb_line = fb_ndjson
        .lines()
        .next()
        .ok_or("missing fallback ui_bundle_ready")?;
    let fb_msg: Value = serde_json::from_str(fb_line)?;
    let fb_version = fb_msg
        .get("data")
        .and_then(|d| d.get("version_label"))
        .and_then(Value::as_str)
        .ok_or("missing fallback version_label")?;
    assert!(fb_version.contains(totaldrop_windows_ffi::APP_VERSION));
    assert!(!contains_disallowed_ui_char(fb_version));
    assert_eq!(totaldrop_win_router_destroy(fallback_router), FFI_OK);

    Ok(())
}

#[test]
fn router_ingest_ipc_bytes_sanitizes_and_bounds_invalid_json_and_unknown_word_errors() -> TestResult
{
    let en = c_str("en-US")?;
    // SAFETY: `en` is a live NUL-terminated CString.
    let router =
        unsafe { totaldrop_win_router_create(9, en.as_ptr(), en.as_ptr(), ptr::null(), true) };
    assert_ne!(router, 0);

    // 1. Oversized hostile ActivationError::InvalidJson (5,000-char unknown variant with RLO/ESC/CSI/Nonchar/Tag).
    let huge_hostile = format!(
        "evil_\u{202E}\x1b[31m\u{009B}\u{FDD0}\u{E0041}_{}",
        "z".repeat(5_000)
    );
    let bad_variant_json = serde_json::json!({
        "version": 1,
        "payload": { "kind": huge_hostile }
    })
    .to_string();
    let bad_variant_frame = frame_raw_json(&bad_variant_json)?;
    // SAFETY: `bad_variant_frame` is a live readable byte slice.
    let bad_json_err = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(
            router,
            bad_variant_frame.as_ptr(),
            bad_variant_frame.len(),
        )
    })?;
    assert_strict_four_field_error(&bad_json_err, "invalid_json", Some("errorOther"))?;
    let bad_json_msg = bad_json_err
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .ok_or("missing invalid_json error.message")?;
    assert!(
        bad_json_msg.len() < 1_024,
        "unbounded router InvalidJson reflection: {} bytes",
        bad_json_msg.len()
    );
    assert!(bad_json_msg.ends_with("..."));
    assert!(
        !contains_disallowed_ui_char(bad_json_msg),
        "router InvalidJson leaked disallowed Unicode char: {bad_json_msg:?}"
    );

    // 2. Oversized hostile ActivationError::InvalidUri(UnknownWord) over ProtocolUri frame.
    let huge_word = format!("notaword_\u{202E}\x1b\u{E0041}_{}", "q".repeat(5_000));
    let bad_uri_json = serde_json::json!({
        "version": 1,
        "payload": {
            "kind": "protocol_uri",
            "code": {
                "nameplate": 7,
                "word_count": 2,
                "display_english": format!("7-{huge_word}-apple"),
                "canonical": "7-0-0",
                "ltr_isolated": format!("\u{2068}7-{huge_word}-apple\u{2069}"),
                "protocol_uri": format!("totaldrop://r/7-{huge_word}-apple"),
                "web_uri": format!("https://totaldrop.app/r#7-{huge_word}-apple")
            }
        }
    })
    .to_string();
    let bad_uri_frame = frame_raw_json(&bad_uri_json)?;
    // SAFETY: `bad_uri_frame` is a live readable byte slice.
    let bad_uri_err = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(
            router,
            bad_uri_frame.as_ptr(),
            bad_uri_frame.len(),
        )
    })?;
    assert_strict_four_field_error(&bad_uri_err, "invalid_uri", Some("receiveCodeInvalid"))?;
    let bad_uri_msg = bad_uri_err
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .ok_or("missing invalid_uri error.message")?;
    assert!(
        bad_uri_msg.len() < 512,
        "unbounded router InvalidUri reflection: {} bytes",
        bad_uri_msg.len()
    );
    assert!(bad_uri_msg.contains("is not a valid TotalDrop code word"));
    assert!(bad_uri_msg.contains("..."));
    assert!(
        !contains_disallowed_ui_char(bad_uri_msg),
        "router InvalidUri leaked disallowed Unicode char: {bad_uri_msg:?}"
    );

    assert_eq!(totaldrop_win_router_destroy(router), FFI_OK);
    Ok(())
}

#[test]
fn serde_json_errors_in_router_activity_format_message_and_validate_paths_are_bounded_and_sanitized()
-> TestResult {
    let en = c_str("en-US")?;
    // SAFETY: `en` is a live NUL-terminated CString.
    let router =
        unsafe { totaldrop_win_router_create(10, en.as_ptr(), en.as_ptr(), ptr::null(), true) };
    assert_ne!(router, 0);

    let huge_hostile = format!(
        "bad_\u{202E}\x1b[31m\u{009B}\u{FDD0}\u{E0041}_{}",
        "a".repeat(5_000)
    );

    // 1. totaldrop_win_router_set_activity_json unknown state variant (raw Display reflection)
    let bad_activity = c_str(&serde_json::json!({ "state": huge_hostile }).to_string())?;
    // SAFETY: `bad_activity` is a live NUL-terminated CString.
    let act_err = decode_and_free(unsafe {
        totaldrop_win_router_set_activity_json(router, bad_activity.as_ptr())
    })?;
    assert_strict_four_field_error(&act_err, "invalid_json", Some("errorOther"))?;
    let act_msg = act_err
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .ok_or("missing set_activity error.message")?;
    assert!(
        act_msg.starts_with("invalid router activity JSON: unknown variant `bad_"),
        "expected reflected unknown variant in set_activity_json error: {act_msg:?}"
    );
    for marker in ["<U+202E>", "<U+001B>", "<U+009B>", "<U+FDD0>", "<U+E0041>"] {
        assert!(
            act_msg.contains(marker),
            "expected revealed {marker} in set_activity_json error: {act_msg:?}"
        );
    }
    assert!(
        act_msg.ends_with("..."),
        "expected 256-scalar truncation in set_activity_json error: {act_msg:?}"
    );
    assert!(
        !act_msg.contains("expected one of"),
        "set_activity_json truncation must cut off before the 5 KiB payload completes: {act_msg:?}"
    );
    assert!(
        act_msg.chars().count() < 600,
        "unbounded set_activity_json error: {} chars",
        act_msg.chars().count()
    );
    assert!(
        !contains_disallowed_ui_char(act_msg),
        "set_activity_json leaked disallowed Unicode char: {act_msg:?}"
    );

    let escaped_hostile = serde_json::to_string(&huge_hostile)?;

    // 2. totaldrop_win_format_message_json (C ABI order: key, args_json, lang_tags, region_tag)
    let key = c_str("sendDoneBody")?;

    // 2a. Malformed args_json containing raw control character inside string literal
    let raw_ctrl_args = c_str(&format!("{{\"{huge_hostile}\""))?;
    // SAFETY: All pointers are live NUL-terminated CStrings.
    let fmt_ctrl_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            key.as_ptr(),
            raw_ctrl_args.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    })?;
    assert_strict_four_field_error(&fmt_ctrl_err, "invalid_json", Some("errorOther"))?;
    let fmt_ctrl_msg = fmt_ctrl_err
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .ok_or("missing format_message control-char error.message")?;
    assert!(
        fmt_ctrl_msg.starts_with("invalid args_json: control character"),
        "expected args_json control-char parse error (not swapped arg error): {fmt_ctrl_msg:?}"
    );
    assert!(
        fmt_ctrl_msg.chars().count() < 600,
        "unbounded format_message_json control-char error: {} chars",
        fmt_ctrl_msg.chars().count()
    );
    assert!(
        !contains_disallowed_ui_char(fmt_ctrl_msg),
        "format_message_json leaked disallowed Unicode char: {fmt_ctrl_msg:?}"
    );

    // 2b. Unterminated >5 KiB JSON-escaped args_json string (proves serde_json scanned full payload)
    let truncated_args = c_str(&format!("{{{}", escaped_hostile.trim_end_matches('"')))?;
    // SAFETY: All pointers are live NUL-terminated CStrings.
    let fmt_eof_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            key.as_ptr(),
            truncated_args.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    })?;
    assert_strict_four_field_error(&fmt_eof_err, "invalid_json", Some("errorOther"))?;
    let fmt_eof_msg = fmt_eof_err
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .ok_or("missing format_message EOF error.message")?;
    let eof_col: usize = fmt_eof_msg
        .strip_prefix("invalid args_json: EOF while parsing a string at line 1 column ")
        .ok_or_else(|| format!("unexpected format_message_json EOF error: {fmt_eof_msg:?}"))?
        .parse()?;
    assert!(
        eof_col > 5_000,
        "expected serde_json to scan >5,000-byte hostile args_json, got column {eof_col}"
    );
    assert!(
        fmt_eof_msg.chars().count() < 600,
        "unbounded format_message_json EOF error: {} chars",
        fmt_eof_msg.chars().count()
    );
    assert!(
        !contains_disallowed_ui_char(fmt_eof_msg),
        "format_message_json EOF error leaked disallowed Unicode char: {fmt_eof_msg:?}"
    );

    // 2c. Valid JSON object with >5 KiB hostile arg name and unsupported value type (reflects bounded preview)
    let hostile_arg_args = c_str(&serde_json::json!({ huge_hostile.as_str(): true }).to_string())?;
    // SAFETY: All pointers are live NUL-terminated CStrings.
    let fmt_arg_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            key.as_ptr(),
            hostile_arg_args.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    })?;
    assert_strict_four_field_error(&fmt_arg_err, "invalid_args", Some("errorOther"))?;
    let fmt_arg_msg = fmt_arg_err
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .ok_or("missing format_message invalid_args error.message")?;
    assert!(
        fmt_arg_msg.starts_with("argument \"bad_"),
        "expected reflected hostile arg name in format_message_json error: {fmt_arg_msg:?}"
    );
    for escaped in ["\\u{202e}", "\\u{1b}", "\\u{9b}", "\\u{fdd0}", "\\u{e0041}"] {
        assert!(
            fmt_arg_msg.contains(escaped),
            "expected escaped {escaped} in format_message_json error: {fmt_arg_msg:?}"
        );
    }
    assert!(
        fmt_arg_msg.ends_with("\"... must be a JSON string or unsigned integer"),
        "expected 64-scalar truncation in format_message_json arg error: {fmt_arg_msg:?}"
    );
    assert!(
        fmt_arg_msg.chars().count() < 256,
        "unbounded format_message_json arg error: {} chars",
        fmt_arg_msg.chars().count()
    );
    assert!(
        !contains_disallowed_ui_char(fmt_arg_msg),
        "format_message_json arg error leaked disallowed Unicode char: {fmt_arg_msg:?}"
    );

    // 2d. Non-object >5 KiB hostile JSON string returns static invalid_args without reflection
    let hostile_json_str = c_str(&escaped_hostile)?;
    // SAFETY: All pointers are live NUL-terminated CStrings.
    let fmt_non_obj_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            key.as_ptr(),
            hostile_json_str.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    })?;
    assert_strict_four_field_error(&fmt_non_obj_err, "invalid_args", Some("errorOther"))?;
    let fmt_non_obj_msg = fmt_non_obj_err
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .ok_or("missing format_message non-object error.message")?;
    assert_eq!(fmt_non_obj_msg, "args_json must be a JSON object");

    // 2e. Oversized args_json (> MAX_FORMAT_ARGS_JSON_BYTES = 16_384) returns args_too_large without echo
    let oversized_key = format!("{huge_hostile}{}", "b".repeat(15_000));
    let oversized_args = c_str(&serde_json::json!({ oversized_key: "ok" }).to_string())?;
    // SAFETY: All pointers are live NUL-terminated CStrings.
    let fmt_oversize_err = decode_and_free(unsafe {
        totaldrop_win_format_message_json(
            key.as_ptr(),
            oversized_args.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    })?;
    assert_strict_four_field_error(&fmt_oversize_err, "args_too_large", Some("errorOther"))?;
    let fmt_oversize_msg = fmt_oversize_err
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .ok_or("missing format_message args_too_large error.message")?;
    assert!(
        fmt_oversize_msg.contains("exceeds limit of 16384 bytes"),
        "unexpected args_too_large error: {fmt_oversize_msg:?}"
    );
    assert!(
        !fmt_oversize_msg.contains("bad_"),
        "args_too_large must not echo hostile payload: {fmt_oversize_msg:?}"
    );
    assert!(
        fmt_oversize_msg.chars().count() < 256,
        "unbounded args_too_large error: {} chars",
        fmt_oversize_msg.chars().count()
    );
    assert!(
        !contains_disallowed_ui_char(fmt_oversize_msg),
        "args_too_large error leaked disallowed Unicode char: {fmt_oversize_msg:?}"
    );

    // 3. totaldrop_win_validate_paths_json reflecting >5 KiB JSON string where sequence is expected
    // SAFETY: `hostile_json_str` is a live NUL-terminated CString.
    let paths_err =
        decode_and_free(unsafe { totaldrop_win_validate_paths_json(hostile_json_str.as_ptr()) })?;
    assert_strict_four_field_error(&paths_err, "invalid_json", Some("errorStorage"))?;
    let paths_msg = paths_err
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .ok_or("missing validate_paths error.message")?;
    assert!(
        paths_msg.starts_with("invalid paths_json array: invalid type: string \"bad_"),
        "expected reflected string in validate_paths_json error: {paths_msg:?}"
    );
    for escaped in ["\\u{202e}", "\\u{1b}", "\\u{9b}", "\\u{fdd0}", "\\u{e0041}"] {
        assert!(
            paths_msg.contains(escaped),
            "expected escaped {escaped} in validate_paths_json error: {paths_msg:?}"
        );
    }
    assert!(
        paths_msg.ends_with("..."),
        "expected 256-scalar truncation in validate_paths_json error: {paths_msg:?}"
    );
    assert!(
        !paths_msg.contains("expected a sequence"),
        "validate_paths_json truncation must cut off before the 5 KiB payload completes: {paths_msg:?}"
    );
    assert!(
        paths_msg.chars().count() < 600,
        "unbounded validate_paths_json error: {} chars",
        paths_msg.chars().count()
    );
    assert!(
        !contains_disallowed_ui_char(paths_msg),
        "validate_paths_json leaked disallowed Unicode char: {paths_msg:?}"
    );

    assert_eq!(totaldrop_win_router_destroy(router), FFI_OK);
    Ok(())
}

#[test]
fn tier5_validate_server_url_rejects_bidi_non_ascii_and_router_bounds_400k_ipc_frame() -> TestResult
{
    // C1-F1: FFI validate_server_url_json rejects Bidi / non-ASCII / control URLs.
    let bad_urls = [
        "wss://example.test/\u{202E}evil",
        "wss://example.test/\u{2066}spoof",
        "wss://example.test/\u{FDD0}bad",
        "wss://example.test/\u{E0041}tag",
        "wss://example.test\u{00A0}",
        "wss://example.test/a\u{00A0}b",
    ];
    for raw in bad_urls {
        let c_url = c_str(raw)?;
        // SAFETY: `c_url` is a live NUL-terminated CString.
        let val =
            decode_and_free(unsafe { totaldrop_win_validate_server_url_json(c_url.as_ptr()) })?;
        assert_strict_four_field_error(&val, "bad_server", Some("errorBadServer"))?;
    }

    // C1-F3: < 4 MiB Named Pipe frame with 400k short paths aborts bounded at item 10,001.
    let en = c_str("en-US")?;
    // SAFETY: `en` is a live NUL-terminated CString.
    let router =
        unsafe { totaldrop_win_router_create(19, en.as_ptr(), en.as_ptr(), ptr::null(), true) };
    assert_ne!(router, 0);

    let count = 400_000usize;
    let mut big_json = String::with_capacity(count * 8 + 128);
    big_json.push_str(r#"{"version":1,"payload":{"kind":"explorer_send","paths":["#);
    for idx in 0..count {
        if idx > 0 {
            big_json.push(',');
        }
        big_json.push_str(r#""C:\\a""#);
    }
    big_json.push_str("]}}");
    let frame = frame_raw_json(&big_json)?;

    let started = std::time::Instant::now();
    // SAFETY: `frame` is a live byte slice.
    let res = decode_and_free(unsafe {
        totaldrop_win_router_ingest_ipc_bytes_json(router, frame.as_ptr(), frame.len())
    })?;
    let elapsed = started.elapsed();

    assert_strict_four_field_error(&res, "too_many_items", Some("errorStorage"))?;
    assert!(
        elapsed.as_secs() < 1,
        "router_ingest on 400k-path frame must reject bounded under 1s (took {elapsed:?})"
    );
    assert_eq!(totaldrop_win_router_destroy(router), FFI_OK);
    Ok(())
}
