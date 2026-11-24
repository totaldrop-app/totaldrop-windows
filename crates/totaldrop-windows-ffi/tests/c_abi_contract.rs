// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end C ABI contract tests for all 24 M1 + M2 exports in
//! `totaldrop-windows-ffi`.

use std::error::Error as StdError;
use std::ffi::{CStr, CString, c_char};
use std::ptr;

use serde_json::Value;
use totaldrop_l10n::{Domain, Strings};
use totaldrop_windows_bridge::SUPPORTED_LANGUAGES;
use totaldrop_windows_ffi::{
    APP_VERSION, CORE_VERSION, FFI_ERR_INVALID_ARG, FFI_ERR_INVALID_HANDLE, FFI_ERR_INVALID_UTF8,
    FFI_ERR_NULL_POINTER, FFI_OK, MSIX_VERSION, totaldrop_win_code_completions_json,
    totaldrop_win_extract_clipboard_code_json, totaldrop_win_format_bytes_json,
    totaldrop_win_format_message_json, totaldrop_win_format_percent_json,
    totaldrop_win_receive_accept_files, totaldrop_win_receive_accept_text,
    totaldrop_win_receive_connect_start, totaldrop_win_receive_decline,
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
