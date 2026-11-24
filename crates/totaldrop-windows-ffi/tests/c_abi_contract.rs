// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end C ABI contract tests for `totaldrop-windows-ffi`.

use std::error::Error as StdError;
use std::ffi::{CStr, CString, c_char};
use std::ptr;

use serde_json::Value;
use totaldrop_windows_ffi::{
    APP_VERSION, CORE_VERSION, MSIX_VERSION, totaldrop_win_format_percent_json,
    totaldrop_win_string_free, totaldrop_win_ui_bundle_json, totaldrop_win_validate_input_json,
    totaldrop_win_validate_uri_json, totaldrop_win_version_json,
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

    // Null pointer returns structured error envelope.
    // SAFETY: Null pointer is explicitly handled by `totaldrop_win_validate_uri_json`.
    let null_err = decode_and_free(unsafe { totaldrop_win_validate_uri_json(ptr::null()) })?;
    assert_eq!(null_err.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        null_err.pointer("/error/kind").and_then(Value::as_str),
        Some("null_pointer")
    );
    assert_eq!(
        null_err.pointer("/error/l10n_key").and_then(Value::as_str),
        Some("errorInvalidCode")
    );

    // Invalid UTF-8 bytes return structured `invalid_utf8` envelope.
    let bad_utf8: [u8; 3] = [0xFF, 0xFE, 0x00];
    // SAFETY: `bad_utf8` is a NUL-terminated byte buffer alive for this call.
    let utf8_err = decode_and_free(unsafe {
        totaldrop_win_validate_uri_json(bad_utf8.as_ptr().cast::<c_char>())
    })?;
    assert_eq!(utf8_err.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        utf8_err.pointer("/error/kind").and_then(Value::as_str),
        Some("invalid_utf8")
    );

    // Untrusted host is rejected cleanly.
    let evil_uri = c_str("https://evil.example/r#7-harbor-rocket")?;
    // SAFETY: `evil_uri` is a live NUL-terminated CString.
    let evil_err = decode_and_free(unsafe { totaldrop_win_validate_uri_json(evil_uri.as_ptr()) })?;
    assert_eq!(evil_err.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        evil_err.pointer("/error/kind").and_then(Value::as_str),
        Some("invalid_activation_link")
    );
    assert_eq!(
        evil_err.pointer("/error/l10n_key").and_then(Value::as_str),
        Some("errorInvalidCode")
    );

    // Oversized activation URI (> MAX_LINK_BYTES).
    let oversized = c_str(&format!("totaldrop://r/{}", "a".repeat(1100)))?;
    // SAFETY: `oversized` is a live NUL-terminated CString.
    let long_err = decode_and_free(unsafe { totaldrop_win_validate_uri_json(oversized.as_ptr()) })?;
    assert_eq!(long_err.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        long_err.pointer("/error/kind").and_then(Value::as_str),
        Some("link_too_long")
    );
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
        assert_eq!(err.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(
            err.pointer("/error/kind").and_then(Value::as_str),
            Some(expected_kind),
            "unexpected error kind for {raw:?}"
        );
        assert_eq!(
            err.pointer("/error/l10n_key").and_then(Value::as_str),
            Some(expected_key),
            "unexpected l10n key for {raw:?}"
        );
    }

    // Null pointer returns structured error envelope.
    // SAFETY: Null pointer is explicitly handled by `totaldrop_win_validate_input_json`.
    let null_err = decode_and_free(unsafe { totaldrop_win_validate_input_json(ptr::null()) })?;
    assert_eq!(
        null_err.pointer("/error/kind").and_then(Value::as_str),
        Some("null_pointer")
    );
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

    // Null region falls back to en-US.
    // SAFETY: Null pointer is explicitly accepted as default en-US.
    let en_pct = decode_and_free(unsafe {
        totaldrop_win_format_percent_json(999_999, 1_000_000, ptr::null())
    })?;
    assert_eq!(en_pct.get("whole").and_then(Value::as_u64), Some(99));
    assert_eq!(en_pct.get("formatted").and_then(Value::as_str), Some("99%"));

    // Invalid UTF-8 region tag returns structured error.
    let bad_utf8: [u8; 2] = [0xC0, 0x00];
    // SAFETY: `bad_utf8` is a NUL-terminated byte buffer alive for this call.
    let utf8_err = decode_and_free(unsafe {
        totaldrop_win_format_percent_json(50, 100, bad_utf8.as_ptr().cast::<c_char>())
    })?;
    assert_eq!(utf8_err.get("ok").and_then(Value::as_bool), Some(false));
    assert_eq!(
        utf8_err.pointer("/error/kind").and_then(Value::as_str),
        Some("invalid_utf8")
    );
    Ok(())
}

#[test]
fn ui_bundle_json_preserves_29_fields_rtl_security_gates_and_fallbacks() -> TestResult {
    // Arabic (unreviewed RTL): FlowDirection == RightToLeft, critical verification_title stays English.
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
        29,
        "WindowsUiBundle must serialize all 29 DTO fields"
    );
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
    assert!(
        ar_bundle
            .get("version_label")
            .and_then(Value::as_str)
            .is_some_and(|v| v.contains(APP_VERSION))
    );

    // Turkish (reviewed LTR): has_draft_translations == false.
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

    // Traditional Chinese fallback (`zh-HK` -> `zh-Hant`).
    let zh_langs = c_str("zh-HK,en-US")?;
    // SAFETY: `zh_langs` is live; null region & version use safe defaults.
    let zh_bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(zh_langs.as_ptr(), ptr::null(), ptr::null())
    })?;
    assert_eq!(
        zh_bundle.get("language_tag").and_then(Value::as_str),
        Some("zh-Hant")
    );

    // All-null arguments fall back safely to English.
    // SAFETY: Null arguments are explicitly accepted.
    let default_bundle = decode_and_free(unsafe {
        totaldrop_win_ui_bundle_json(ptr::null(), ptr::null(), ptr::null())
    })?;
    assert_eq!(
        default_bundle.get("language_tag").and_then(Value::as_str),
        Some("en")
    );
    assert_eq!(
        default_bundle.get("flow_direction").and_then(Value::as_str),
        Some("LeftToRight")
    );
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
