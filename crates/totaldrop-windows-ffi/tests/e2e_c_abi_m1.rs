// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opaque-box E2E tests for Milestone M1 (`F01`) C ABI exports of
//! `totaldrop-windows-ffi` (`T1-F01-02`..`T1-F01-05`, `T2-F01-01`..`T2-F01-04`).
//!
//! Strictly targets observable `extern "C"` boundaries, JSON envelopes, and
//! allocator contracts without inspecting private crate internals or opening
//! any network sockets.

use std::error::Error as StdError;
use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::thread;

use serde_json::Value;
use totaldrop_windows_ffi::{
    totaldrop_win_format_percent_json, totaldrop_win_string_free, totaldrop_win_ui_bundle_json,
    totaldrop_win_validate_input_json, totaldrop_win_validate_uri_json, totaldrop_win_version_json,
};

type TestResult = Result<(), Box<dyn StdError>>;

fn c_str(text: &str) -> Result<CString, Box<dyn StdError>> {
    Ok(CString::new(text)?)
}

fn take_raw_and_free(ptr: *mut c_char) -> Result<String, Box<dyn StdError>> {
    if ptr.is_null() {
        return Err("FFI export returned unexpected NULL pointer".into());
    }
    // SAFETY: `ptr` was freshly returned by a `totaldrop_win_*` FFI export as a
    // NUL-terminated UTF-8 C string owned by the caller until `string_free`.
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec();
    // SAFETY: `ptr` was allocated by `totaldrop-windows-ffi` and is freed once.
    unsafe { totaldrop_win_string_free(ptr) };
    if bytes.contains(&0u8) {
        return Err("returned C string payload contained an interior NUL byte".into());
    }
    Ok(String::from_utf8(bytes)?)
}

fn take_json(ptr: *mut c_char) -> Result<Value, Box<dyn StdError>> {
    let raw = take_raw_and_free(ptr)?;
    Ok(serde_json::from_str(&raw)?)
}

fn assert_direct_dto_ok(val: &Value) -> TestResult {
    if val.get("error").is_some() {
        return Err(format!("expected direct DTO without 'error' key, got: {val}").into());
    }
    if val.get("ok") == Some(&Value::Bool(false)) {
        return Err(format!("expected direct DTO with ok != false, got: {val}").into());
    }
    Ok(())
}

fn assert_error_envelope(
    val: &Value,
    expected_kind: &str,
    expected_l10n_key: Option<&str>,
) -> Result<String, Box<dyn StdError>> {
    if val.get("ok").and_then(Value::as_bool) != Some(false) {
        return Err(format!("expected ok == false error envelope, got: {val}").into());
    }
    let err = val
        .get("error")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing error object in envelope: {val}"))?;
    for key in err.keys() {
        if !matches!(key.as_str(), "kind" | "l10n_key" | "cause" | "message") {
            return Err(format!("unexpected extra error key {key:?} in envelope: {val}").into());
        }
    }
    let actual_kind = err
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing error.kind in envelope: {val}"))?;
    if actual_kind != expected_kind {
        return Err(format!(
            "expected error.kind == {expected_kind:?}, got {actual_kind:?} ({val})"
        )
        .into());
    }
    if let Some(expected_key) = expected_l10n_key {
        let actual_key = err.get("l10n_key").and_then(Value::as_str);
        if actual_key != Some(expected_key) {
            return Err(format!(
                "expected error.l10n_key == {expected_key:?}, got {actual_key:?} ({val})"
            )
            .into());
        }
    }
    let message = err
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing error.message in envelope: {val}"))?;
    if message.is_empty() {
        return Err(format!("error.message must be non-empty in envelope: {val}").into());
    }
    Ok(message.to_owned())
}

#[test]
fn t1_f01_02_version_json_and_string_free() -> TestResult {
    let val = take_json(totaldrop_win_version_json())?;
    assert_direct_dto_ok(&val)?;
    assert_eq!(
        val.get("app_version").and_then(Value::as_str),
        Some("0.1.0-beta.1")
    );
    assert_eq!(
        val.get("core_version").and_then(Value::as_str),
        Some("0.2.0-beta.5")
    );
    assert_eq!(
        val.get("msix_version").and_then(Value::as_str),
        Some("0.1.1.0")
    );
    Ok(())
}

#[test]
fn t1_f01_03_validate_uri_and_input_json() -> TestResult {
    let uri_c = c_str("totaldrop://r/7-harbor-rocket")?;
    // SAFETY: `uri_c` is a valid NUL-terminated CString alive for this call.
    let uri_val = take_json(unsafe { totaldrop_win_validate_uri_json(uri_c.as_ptr()) })?;

    let input_c = c_str("7 harbor rocket")?;
    // SAFETY: `input_c` is a valid NUL-terminated CString alive for this call.
    let input_val = take_json(unsafe { totaldrop_win_validate_input_json(input_c.as_ptr()) })?;

    for val in [&uri_val, &input_val] {
        assert_direct_dto_ok(val)?;
        assert_eq!(val.get("nameplate").and_then(Value::as_u64), Some(7));
        assert_eq!(val.get("word_count").and_then(Value::as_u64), Some(2));
        assert_eq!(
            val.get("display_english").and_then(Value::as_str),
            Some("7-harbor-rocket")
        );
        assert_eq!(
            val.get("canonical").and_then(Value::as_str),
            Some("7-840-1499")
        );
        assert_eq!(
            val.get("ltr_isolated").and_then(Value::as_str),
            Some("\u{2068}7-harbor-rocket\u{2069}")
        );
        assert_eq!(
            val.get("protocol_uri").and_then(Value::as_str),
            Some("totaldrop://r/7-harbor-rocket")
        );
        // Offline string validation check only — zero network connection.
        assert_eq!(
            val.get("web_uri").and_then(Value::as_str),
            Some("https://totaldrop.app/r#7-harbor-rocket")
        );
    }
    Ok(())
}

#[test]
fn t1_f01_04_format_percent_en_us_and_tr_tr() -> TestResult {
    let en_us = c_str("en-US")?;
    // SAFETY: `en_us` is a valid NUL-terminated CString alive for this call.
    let en_val =
        take_json(unsafe { totaldrop_win_format_percent_json(500, 1000, en_us.as_ptr()) })?;
    assert_direct_dto_ok(&en_val)?;
    assert_eq!(en_val.get("whole").and_then(Value::as_u64), Some(50));
    assert_eq!(en_val.get("formatted").and_then(Value::as_str), Some("50%"));

    let tr_tr = c_str("tr-TR")?;
    // SAFETY: `tr_tr` is a valid NUL-terminated CString alive for this call.
    let tr_val =
        take_json(unsafe { totaldrop_win_format_percent_json(500, 1000, tr_tr.as_ptr()) })?;
    assert_direct_dto_ok(&tr_val)?;
    assert_eq!(tr_val.get("whole").and_then(Value::as_u64), Some(50));
    assert_eq!(tr_val.get("formatted").and_then(Value::as_str), Some("%50"));
    Ok(())
}

#[test]
fn t1_f01_05_ui_bundle_en_us_and_tr_tr() -> TestResult {
    let app_ver = c_str("0.1.0-beta.1")?;

    let en_tag = c_str("en-US")?;
    // SAFETY: All three pointers are valid NUL-terminated CStrings alive for this call.
    let en_val = take_json(unsafe {
        totaldrop_win_ui_bundle_json(en_tag.as_ptr(), en_tag.as_ptr(), app_ver.as_ptr())
    })?;
    assert_direct_dto_ok(&en_val)?;
    assert_eq!(
        en_val.get("flow_direction").and_then(Value::as_str),
        Some("LeftToRight")
    );
    assert_eq!(
        en_val
            .get("has_draft_translations")
            .and_then(Value::as_bool),
        Some(false)
    );
    let en_ver = en_val
        .get("version_label")
        .and_then(Value::as_str)
        .ok_or("missing version_label in en-US bundle")?;
    assert!(en_ver.contains("0.1.0-beta.1"));
    assert_eq!(
        en_val.get("verification_title").and_then(Value::as_str),
        Some("Verification words")
    );
    for key in [
        "send_title",
        "receive_title",
        "settings_title",
        "receive_accept",
        "receive_decline",
        "explorer_send_with",
    ] {
        assert!(
            en_val
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty()),
            "missing non-empty {key} in en-US bundle"
        );
    }

    let tr_tag = c_str("tr-TR")?;
    // SAFETY: All three pointers are valid NUL-terminated CStrings alive for this call.
    let tr_val = take_json(unsafe {
        totaldrop_win_ui_bundle_json(tr_tag.as_ptr(), tr_tag.as_ptr(), app_ver.as_ptr())
    })?;
    assert_direct_dto_ok(&tr_val)?;
    assert_eq!(
        tr_val.get("flow_direction").and_then(Value::as_str),
        Some("LeftToRight")
    );
    assert_eq!(
        tr_val
            .get("has_draft_translations")
            .and_then(Value::as_bool),
        Some(false)
    );
    let tr_ver = tr_val
        .get("version_label")
        .and_then(Value::as_str)
        .ok_or("missing version_label in tr-TR bundle")?;
    assert!(tr_ver.contains("0.1.0-beta.1"));
    assert_eq!(
        tr_val.get("verification_title").and_then(Value::as_str),
        Some("Doğrulama kelimeleri")
    );
    for key in [
        "send_title",
        "receive_title",
        "settings_title",
        "receive_accept",
        "receive_decline",
        "explorer_send_with",
    ] {
        assert!(
            tr_val
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty()),
            "missing non-empty {key} in tr-TR bundle"
        );
    }
    Ok(())
}

#[test]
fn t2_f01_01_null_pointer_defenses_all_m1_exports() -> TestResult {
    // (1) NULL free must be a safe no-op.
    // SAFETY: Null pointer is explicitly permitted as a no-op by the C ABI contract.
    unsafe { totaldrop_win_string_free(ptr::null_mut()) };

    // (2) validate_uri_json(NULL)
    // SAFETY: Null pointer input is explicitly checked by the FFI boundary.
    let uri_err = take_json(unsafe { totaldrop_win_validate_uri_json(ptr::null()) })?;
    assert_error_envelope(&uri_err, "null_pointer", Some("errorInvalidCode"))?;

    // (3) validate_input_json(NULL)
    // SAFETY: Null pointer input is explicitly checked by the FFI boundary.
    let input_err = take_json(unsafe { totaldrop_win_validate_input_json(ptr::null()) })?;
    assert_error_envelope(&input_err, "null_pointer", Some("receiveCodeInvalid"))?;

    // (4) format_percent_json(50, 100, NULL) defaults region_tag to "en-US".
    // SAFETY: Null region_tag is explicitly permitted as default "en-US".
    let pct = take_json(unsafe { totaldrop_win_format_percent_json(50, 100, ptr::null()) })?;
    assert_direct_dto_ok(&pct)?;
    assert_eq!(pct.get("whole").and_then(Value::as_u64), Some(50));
    assert_eq!(pct.get("formatted").and_then(Value::as_str), Some("50%"));

    // (5) ui_bundle_json(NULL, NULL, NULL) defaults to English + compiled app version.
    // SAFETY: All three arguments are nullable per the C ABI contract.
    let bundle =
        take_json(unsafe { totaldrop_win_ui_bundle_json(ptr::null(), ptr::null(), ptr::null()) })?;
    assert_direct_dto_ok(&bundle)?;
    assert_eq!(
        bundle.get("language_tag").and_then(Value::as_str),
        Some("en")
    );
    assert_eq!(
        bundle.get("flow_direction").and_then(Value::as_str),
        Some("LeftToRight")
    );
    assert_eq!(
        bundle
            .get("has_draft_translations")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        bundle.get("verification_title").and_then(Value::as_str),
        Some("Verification words")
    );
    let ver_label = bundle
        .get("version_label")
        .and_then(Value::as_str)
        .ok_or("missing version_label in default bundle")?;
    assert!(ver_label.contains("0.1.0-beta.1"));
    Ok(())
}

#[test]
fn t2_f01_02_invalid_utf8_c_strings() -> TestResult {
    let bad_utf8: [u8; 4] = [0xFF, 0xFE, 0x80, 0x00];
    let bad_ptr = bad_utf8.as_ptr().cast::<c_char>();

    // SAFETY: `bad_utf8` is a valid NUL-terminated buffer alive for each call.
    let uri_err = take_json(unsafe { totaldrop_win_validate_uri_json(bad_ptr) })?;
    assert_error_envelope(&uri_err, "invalid_utf8", Some("errorInvalidCode"))?;

    // SAFETY: `bad_utf8` is a valid NUL-terminated buffer alive for each call.
    let input_err = take_json(unsafe { totaldrop_win_validate_input_json(bad_ptr) })?;
    assert_error_envelope(&input_err, "invalid_utf8", Some("receiveCodeInvalid"))?;

    // SAFETY: `bad_utf8` is a valid NUL-terminated buffer alive for each call.
    let pct_err = take_json(unsafe { totaldrop_win_format_percent_json(50, 100, bad_ptr) })?;
    assert_error_envelope(&pct_err, "invalid_utf8", Some("errorOther"))?;

    // SAFETY: `bad_utf8` is a valid NUL-terminated buffer alive for each call.
    let bundle_lang_err =
        take_json(unsafe { totaldrop_win_ui_bundle_json(bad_ptr, ptr::null(), ptr::null()) })?;
    assert_error_envelope(&bundle_lang_err, "invalid_utf8", Some("errorOther"))?;

    // SAFETY: `bad_utf8` is a valid NUL-terminated buffer alive for each call.
    let bundle_region_err =
        take_json(unsafe { totaldrop_win_ui_bundle_json(ptr::null(), bad_ptr, ptr::null()) })?;
    assert_error_envelope(&bundle_region_err, "invalid_utf8", Some("errorOther"))?;

    // SAFETY: `bad_utf8` is a valid NUL-terminated buffer alive for each call.
    let bundle_ver_err =
        take_json(unsafe { totaldrop_win_ui_bundle_json(ptr::null(), ptr::null(), bad_ptr) })?;
    assert_error_envelope(&bundle_ver_err, "invalid_utf8", Some("errorOther"))?;
    Ok(())
}

#[test]
fn t2_f01_03_empty_and_oversized_1025_byte_uri() -> TestResult {
    let empty: [u8; 1] = [0x00];
    // SAFETY: `empty` is a valid NUL-terminated C string alive for this call.
    let empty_err =
        take_json(unsafe { totaldrop_win_validate_uri_json(empty.as_ptr().cast::<c_char>()) })?;
    assert_error_envelope(&empty_err, "empty", Some("receiveCodeInvalid"))?;

    let prefix = "totaldrop://r/";
    let oversized_str = format!("{prefix}{}", "a".repeat(1011));
    assert_eq!(oversized_str.len(), 1025);
    let oversized_c = c_str(&oversized_str)?;
    // SAFETY: `oversized_c` is a valid NUL-terminated CString alive for this call.
    let long_err = take_json(unsafe { totaldrop_win_validate_uri_json(oversized_c.as_ptr()) })?;
    let msg = assert_error_envelope(&long_err, "link_too_long", Some("errorInvalidCode"))?;
    assert!(
        msg.contains("1025") && msg.contains("1024"),
        "expected '1025' and '1024' in link_too_long message, got: {msg:?}"
    );
    Ok(())
}

#[test]
fn t2_f01_04_nul_boundary_escaped_nul_2mib_and_8x500_threads() -> TestResult {
    // (a) Raw NUL-truncated C buffers must stop at the first 0x00 without over-reading.
    let trunc_input = b"7-harbor\0-rocket\0";
    // SAFETY: `trunc_input` is NUL-terminated at index 8 and alive for this call.
    let trunc_input_val = take_json(unsafe {
        totaldrop_win_validate_input_json(trunc_input.as_ptr().cast::<c_char>())
    })?;
    assert_error_envelope(
        &trunc_input_val,
        "wrong_word_count",
        Some("receiveCodeInvalid"),
    )?;

    let trunc_uri = b"totaldrop://r/7-harbor\0-rocket\0";
    // SAFETY: `trunc_uri` is NUL-terminated at index 22 and alive for this call.
    let trunc_uri_val =
        take_json(unsafe { totaldrop_win_validate_uri_json(trunc_uri.as_ptr().cast::<c_char>()) })?;
    assert_error_envelope(
        &trunc_uri_val,
        "invalid_activation_link",
        Some("errorInvalidCode"),
    )?;

    // (b) Escaped NUL vectors must reject cleanly with zero raw interior NUL bytes.
    let esc_uri = c_str("totaldrop://r/7-harbor%00rocket")?;
    // SAFETY: `esc_uri` is a live NUL-terminated CString.
    let esc_uri_val = take_json(unsafe { totaldrop_win_validate_uri_json(esc_uri.as_ptr()) })?;
    assert_error_envelope(
        &esc_uri_val,
        "invalid_activation_link",
        Some("errorInvalidCode"),
    )?;

    let esc_input = c_str("7-harbor\\u0000rocket")?;
    // SAFETY: `esc_input` is a live NUL-terminated CString.
    let esc_input_val =
        take_json(unsafe { totaldrop_win_validate_input_json(esc_input.as_ptr()) })?;
    assert_error_envelope(&esc_input_val, "unknown_word", Some("receiveCodeInvalid"))?;

    // (c) 2 MiB malformed ASCII strings must reject cleanly without OOM or abort.
    let two_mib_str = "x".repeat(2_097_152);
    let two_mib_c = c_str(&two_mib_str)?;
    // SAFETY: `two_mib_c` is a live NUL-terminated CString.
    let two_mib_uri_val =
        take_json(unsafe { totaldrop_win_validate_uri_json(two_mib_c.as_ptr()) })?;
    let two_mib_msg =
        assert_error_envelope(&two_mib_uri_val, "link_too_long", Some("errorInvalidCode"))?;
    assert!(
        two_mib_msg.contains("1024"),
        "expected '1024' in 2 MiB link_too_long message, got: {two_mib_msg:?}"
    );

    // SAFETY: `two_mib_c` is a live NUL-terminated CString.
    let two_mib_input_val =
        take_json(unsafe { totaldrop_win_validate_input_json(two_mib_c.as_ptr()) })?;
    assert_error_envelope(
        &two_mib_input_val,
        "bad_nameplate",
        Some("receiveCodeInvalid"),
    )?;

    // (d) 8 concurrent OS threads x 500 mixed valid/invalid/64 KiB calls (4,000 total).
    let mut handles = Vec::with_capacity(8);
    for tid in 0u64..8 {
        handles.push(thread::spawn(move || -> Result<(), String> {
            let valid_uri = CString::new("totaldrop://r/7-harbor-rocket")
                .map_err(|e| format!("thread {tid}: {e}"))?;
            let valid_input =
                CString::new("7-harbor-rocket").map_err(|e| format!("thread {tid}: {e}"))?;
            let big_64k =
                CString::new("z".repeat(65_536)).map_err(|e| format!("thread {tid}: {e}"))?;
            let region = CString::new("tr-TR").map_err(|e| format!("thread {tid}: {e}"))?;
            let lang = CString::new("ar-SA,en-US").map_err(|e| format!("thread {tid}: {e}"))?;
            let ver = CString::new("0.1.0-beta.1").map_err(|e| format!("thread {tid}: {e}"))?;

            for iter in 0u64..500 {
                let kind = iter % 6;
                match kind {
                    0 => {
                        let v = take_json(totaldrop_win_version_json())
                            .map_err(|e| format!("t{tid} i{iter}: {e}"))?;
                        if v.get("app_version").and_then(Value::as_str) != Some("0.1.0-beta.1") {
                            return Err(format!("t{tid} i{iter}: bad version {v}"));
                        }
                    }
                    1 => {
                        // SAFETY: `valid_uri` is a live NUL-terminated CString.
                        let v = take_json(unsafe {
                            totaldrop_win_validate_uri_json(valid_uri.as_ptr())
                        })
                        .map_err(|e| format!("t{tid} i{iter}: {e}"))?;
                        if v.get("nameplate").and_then(Value::as_u64) != Some(7) {
                            return Err(format!("t{tid} i{iter}: bad uri {v}"));
                        }
                    }
                    2 => {
                        // SAFETY: `big_64k` is a live NUL-terminated CString.
                        let v =
                            take_json(unsafe { totaldrop_win_validate_uri_json(big_64k.as_ptr()) })
                                .map_err(|e| format!("t{tid} i{iter}: {e}"))?;
                        if v.get("ok").and_then(Value::as_bool) != Some(false) {
                            return Err(format!("t{tid} i{iter}: expected 64KiB fail {v}"));
                        }
                    }
                    3 => {
                        // SAFETY: `valid_input` is a live NUL-terminated CString.
                        let v = take_json(unsafe {
                            totaldrop_win_validate_input_json(valid_input.as_ptr())
                        })
                        .map_err(|e| format!("t{tid} i{iter}: {e}"))?;
                        if v.get("canonical").and_then(Value::as_str) != Some("7-840-1499") {
                            return Err(format!("t{tid} i{iter}: bad input {v}"));
                        }
                    }
                    4 => {
                        let done = iter.saturating_mul(2);
                        // SAFETY: `region` is a live NUL-terminated CString.
                        let v = take_json(unsafe {
                            totaldrop_win_format_percent_json(done, 1000, region.as_ptr())
                        })
                        .map_err(|e| format!("t{tid} i{iter}: {e}"))?;
                        if v.get("whole").and_then(Value::as_u64).is_none() {
                            return Err(format!("t{tid} i{iter}: bad percent {v}"));
                        }
                    }
                    _ => {
                        // SAFETY: `lang`, `region`, and `ver` are live NUL-terminated CStrings.
                        let v = take_json(unsafe {
                            totaldrop_win_ui_bundle_json(
                                lang.as_ptr(),
                                region.as_ptr(),
                                ver.as_ptr(),
                            )
                        })
                        .map_err(|e| format!("t{tid} i{iter}: {e}"))?;
                        if v.get("flow_direction").and_then(Value::as_str) != Some("RightToLeft") {
                            return Err(format!("t{tid} i{iter}: bad bundle {v}"));
                        }
                    }
                }
            }
            // SAFETY: NULL free must remain thread-safe under contention.
            unsafe { totaldrop_win_string_free(ptr::null_mut()) };
            Ok(())
        }));
    }

    for handle in handles {
        let outcome = handle
            .join()
            .map_err(|_| "worker thread panicked during concurrent M1 C ABI stress test")?;
        outcome.map_err(|msg| -> Box<dyn StdError> { msg.into() })?;
    }
    Ok(())
}
