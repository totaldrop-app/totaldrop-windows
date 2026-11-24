// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Thin C ABI FFI boundary for TotalDrop on Windows 11 (ADR 0016).
//!
//! This crate isolates all `extern "C"` FFI exports into a minimal `cdylib` +
//! `rlib` boundary (`totaldrop_windows_ffi.dll`) so that `totaldrop-crypto`,
//! `totaldrop-proto`, `totaldrop-core`, `totaldrop-l10n`, and
//! `totaldrop-windows-bridge` remain strictly `#![forbid(unsafe_code)]`.
//!
//! # Memory Ownership & Safety Invariants
//!
//! - Every function returning `*mut c_char` allocates a NUL-terminated UTF-8
//!   JSON or NDJSON string using Rust's allocator. Callers MUST free every
//!   non-null pointer via [`totaldrop_win_string_free`].
//! - Every `extern "C"` entry point wraps its body in
//!   [`std::panic::catch_unwind`] so a Rust panic can never unwind across the
//!   C ABI boundary.
//! - Interior NUL bytes are stripped before constructing [`CString`] buffers so
//!   serialization never fails or truncates mid-payload.

mod quit;
mod sessions;

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use serde::Serialize;
use totaldrop_l10n::Arg;
use totaldrop_windows_bridge::{
    ActivationError, BridgeNetworkConfig, UriValidationError, ValidatedCode, WindowsLocalizer,
    code_word_completions, format_regional_percent, sanitize_peer_filename, sanitize_peer_text,
    validate_windows_paths,
};

use crate::sessions::FfiNetworkConfig;

/// Independent SemVer of the TotalDrop for Windows 11 application.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the synced pure-Rust TotalDrop core workspace crates.
pub const CORE_VERSION: &str = "0.2.0-beta.5";

/// Four-part Windows MSIX / PE package version (`Revision == 0`).
pub const MSIX_VERSION: &str = "0.1.1.0";

/// Standardized `i32` status code: operation succeeded.
pub const FFI_OK: i32 = 0;

/// Standardized `i32` status code: required pointer argument was null.
pub const FFI_ERR_NULL_POINTER: i32 = -1;

/// Standardized `i32` status code: C string argument was not valid UTF-8.
pub const FFI_ERR_INVALID_UTF8: i32 = -2;

/// Standardized `i32` status code: session handle was `0`, unknown, or destroyed.
pub const FFI_ERR_INVALID_HANDLE: i32 = -3;

/// Standardized `i32` status code: operation invalid for current session state.
pub const FFI_ERR_INVALID_STATE: i32 = -4;

/// Standardized `i32` status code: argument failed domain validation (e.g. empty path).
pub const FFI_ERR_INVALID_ARG: i32 = -5;

/// Standardized `i32` status code: internal panic or poisoned lock caught at boundary.
pub const FFI_ERR_INTERNAL: i32 = -99;

/// Maximum permitted byte length of `args_json` in [`totaldrop_win_format_message_json`].
const MAX_FORMAT_ARGS_JSON_BYTES: usize = 16_384;

const FALLBACK_PANIC_JSON: &str = r#"{"ok":false,"error":{"kind":"internal","l10n_key":"errorOther","message":"internal FFI panic"}}"#;
const FALLBACK_SERIALIZE_JSON: &str = r#"{"ok":false,"error":{"kind":"internal","l10n_key":"errorOther","message":"internal JSON serialization failure"}}"#;

#[derive(Serialize)]
struct VersionInfo {
    app_version: &'static str,
    core_version: &'static str,
    msix_version: &'static str,
}

#[derive(Serialize)]
struct StatusOk {
    ok: bool,
}

#[derive(Serialize)]
struct FormattedBytesDto {
    bytes: u64,
    formatted: String,
}

#[derive(Serialize)]
struct FormattedMessageDto {
    key: String,
    language_tag: String,
    formatted: String,
}

#[derive(Serialize)]
struct SanitizedFilenameDto {
    sanitized: String,
    has_hidden_controls: bool,
}

#[derive(Serialize)]
struct FfiErrorEnvelope<'a> {
    ok: bool,
    error: FfiErrorBody<'a>,
}

#[derive(Serialize)]
struct FfiErrorBody<'a> {
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    l10n_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<&'a str>,
    message: String,
}

fn into_c_string_ptr(mut text: String) -> *mut c_char {
    if text.as_bytes().contains(&0) {
        text.retain(|ch| ch != '\0');
    }
    match CString::new(text) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

fn serialize_or_error<T: Serialize>(value: &T) -> *mut c_char {
    match serde_json::to_string(value) {
        Ok(json) => into_c_string_ptr(json),
        Err(_) => into_c_string_ptr(FALLBACK_SERIALIZE_JSON.to_owned()),
    }
}

fn error_json(
    kind: &str,
    l10n_key: Option<&str>,
    cause: Option<&str>,
    message: impl Into<String>,
) -> *mut c_char {
    let envelope = FfiErrorEnvelope {
        ok: false,
        error: FfiErrorBody {
            kind,
            l10n_key,
            cause,
            message: message.into(),
        },
    };
    serialize_or_error(&envelope)
}

fn guard_ffi_json<F>(f: F) -> *mut c_char
where
    F: FnOnce() -> *mut c_char,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(ptr) => ptr,
        Err(_) => into_c_string_ptr(FALLBACK_PANIC_JSON.to_owned()),
    }
}

fn guard_ffi_u64<F>(f: F) -> u64
where
    F: FnOnce() -> u64,
{
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(0)
}

fn guard_ffi_i32<F>(f: F) -> i32
where
    F: FnOnce() -> i32,
{
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(FFI_ERR_INTERNAL)
}

/// Reads an optional NUL-terminated UTF-8 C string pointer.
///
/// # Safety
///
/// If `ptr` is non-null, it must point to a valid, readable NUL-terminated C
/// string that remains alive for the duration of `'a`.
unsafe fn read_optional_c_str<'a>(ptr: *const c_char) -> Result<Option<&'a str>, &'static str> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: Caller guarantees non-null `ptr` points to a readable
    // NUL-terminated C string valid for lifetime `'a`.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    match cstr.to_str() {
        Ok(valid) => Ok(Some(valid)),
        Err(_) => Err("input string is not valid UTF-8"),
    }
}

const MAX_ERROR_PREVIEW_CHARS: usize = 64;

fn bounded_debug_preview(s: &str, max_chars: usize) -> String {
    if s.chars().nth(max_chars).is_some() {
        let preview: String = s.chars().take(max_chars).collect();
        format!("{preview:?}...")
    } else {
        format!("{s:?}")
    }
}

fn sanitize_message_text_arg(s: &str) -> String {
    if let Some(inner) = s
        .strip_prefix('\u{2068}')
        .and_then(|rest| rest.strip_suffix('\u{2069}'))
    {
        totaldrop_windows_bridge::isolate_bidi(&totaldrop_l10n::reveal_controls(inner))
    } else {
        totaldrop_l10n::reveal_controls(s)
    }
}

const fn is_disallowed_ui_metadata_char(ch: char) -> bool {
    if ch.is_control() {
        return true;
    }
    let cp = ch as u32;
    matches!(
        cp,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x206F
            | 0xFDD0..=0xFDEF
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0000..=0xE007F
    ) || (cp & 0xFFFE) == 0xFFFE
}

fn sanitize_ui_metadata(raw: &str) -> String {
    raw.chars()
        .filter(|&ch| !is_disallowed_ui_metadata_char(ch))
        .collect::<String>()
        .trim()
        .to_owned()
}

fn parse_lang_tags(raw: &str) -> Vec<String> {
    let trimmed = raw.trim().trim_start_matches('\u{FEFF}').trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('[')
        && let Ok(parsed) = serde_json::from_str::<Vec<String>>(trimmed)
    {
        return parsed
            .into_iter()
            .map(|tag| sanitize_ui_metadata(&tag))
            .filter(|tag| !tag.is_empty())
            .collect();
    }
    trimmed
        .split([',', ';'])
        .map(sanitize_ui_metadata)
        .filter(|tag| !tag.is_empty())
        .collect()
}

fn build_localizer(langs_opt: Option<&str>, region_opt: Option<&str>) -> WindowsLocalizer {
    let tags = langs_opt.map(parse_lang_tags).unwrap_or_default();
    let sanitized_region = region_opt
        .map(sanitize_ui_metadata)
        .filter(|tag| !tag.is_empty());
    WindowsLocalizer::new(tags, sanitized_region.as_deref())
}

const fn uri_error_kind(err: &UriValidationError) -> &'static str {
    match err {
        UriValidationError::Empty => "empty",
        UriValidationError::LinkTooLong { .. } => "link_too_long",
        UriValidationError::InvalidActivationLink => "invalid_activation_link",
        UriValidationError::BadNameplate => "bad_nameplate",
        UriValidationError::WrongWordCount => "wrong_word_count",
        UriValidationError::UnknownWord { .. } => "unknown_word",
        UriValidationError::NoCodeFoundInText => "no_code_found_in_text",
    }
}

fn format_uri_error_message(err: &UriValidationError) -> String {
    if let UriValidationError::UnknownWord { word } = err {
        let preview = bounded_debug_preview(word, MAX_ERROR_PREVIEW_CHARS);
        return format!("{preview} is not a valid TotalDrop code word");
    }
    err.to_string()
}

const fn activation_error_kind(err: &ActivationError) -> &'static str {
    match err {
        ActivationError::EmptyPath => "empty_path",
        ActivationError::ControlCharacter => "control_character",
        ActivationError::PathTooLong { .. } => "path_too_long",
        ActivationError::NotAbsoluteWindowsPath => "not_absolute_windows_path",
        ActivationError::DeviceNamespaceForbidden => "device_namespace_forbidden",
        ActivationError::DotTraversalSegment => "dot_traversal_segment",
        ActivationError::ForbiddenSegmentCharacter(_) => "forbidden_segment_character",
        ActivationError::TrailingDotOrSpace => "trailing_dot_or_space",
        ActivationError::TooManyItems { .. } => "too_many_items",
        ActivationError::EmptyExplorerSelection => "empty_explorer_selection",
        ActivationError::EnvelopeTooLarge { .. } => "envelope_too_large",
        ActivationError::MalformedIpcFrame => "malformed_ipc_frame",
        ActivationError::UnsupportedSchemaVersion(_) => "unsupported_schema_version",
        ActivationError::InvalidJson(_) => "invalid_json",
        ActivationError::InvalidUri(_) => "invalid_uri",
        ActivationError::MalformedCommandLine => "malformed_command_line",
    }
}

// ---------------------------------------------------------------------------
// Phase 1 Exports (6 symbols — preserved verbatim)

/// Frees a UTF-8 JSON string previously returned by any `totaldrop_win_*`
/// function in this library.
///
/// Passing a null pointer is a safe no-op.
///
/// # Safety
///
/// `ptr` must either be null or a pointer previously returned by a
/// `totaldrop_win_*` export from this library that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Caller guarantees `ptr` is a live pointer allocated via
        // `CString::into_raw` by this library and freed at most once.
        let owned = unsafe { CString::from_raw(ptr) };
        drop(owned);
    }));
}

/// Returns the version metadata of the Windows app, synced core workspace, and
/// MSIX package as a JSON object.
///
/// The returned pointer must be released with [`totaldrop_win_string_free`].
#[unsafe(no_mangle)]
pub extern "C" fn totaldrop_win_version_json() -> *mut c_char {
    guard_ffi_json(|| {
        let info = VersionInfo {
            app_version: APP_VERSION,
            core_version: CORE_VERSION,
            msix_version: MSIX_VERSION,
        };
        serialize_or_error(&info)
    })
}

/// Validates a `totaldrop://r/<code>` or `https://totaldrop.app/r#<code>`
/// activation URI via [`ValidatedCode::from_activation_uri`].
///
/// On success, returns the JSON-serialized [`ValidatedCode`] object. On
/// failure, returns a structured error envelope (`{"ok":false,"error":{...}}`).
/// The returned pointer must be released with [`totaldrop_win_string_free`].
///
/// # Safety
///
/// `raw_uri` must either be null (which yields a `null_pointer` error JSON) or
/// point to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_validate_uri_json(raw_uri: *const c_char) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let uri_opt = match unsafe { read_optional_c_str(raw_uri) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorInvalidCode"), None, msg);
            }
        };
        let Some(uri) = uri_opt else {
            return error_json(
                "null_pointer",
                Some("errorInvalidCode"),
                None,
                "raw_uri pointer must not be null",
            );
        };
        match ValidatedCode::from_activation_uri(uri) {
            Ok(validated) => serialize_or_error(&validated),
            Err(err) => error_json(
                uri_error_kind(&err),
                Some(err.l10n_key()),
                None,
                format_uri_error_message(&err),
            ),
        }
    })
}

/// Validates interactive transfer code input from WinUI 3 via
/// [`ValidatedCode::from_user_input`].
///
/// On success, returns the JSON-serialized [`ValidatedCode`] object. On
/// failure, returns a structured error envelope (`{"ok":false,"error":{...}}`).
/// The returned pointer must be released with [`totaldrop_win_string_free`].
///
/// # Safety
///
/// `raw_input` must either be null (which yields a `null_pointer` error JSON)
/// or point to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_validate_input_json(
    raw_input: *const c_char,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let input_opt = match unsafe { read_optional_c_str(raw_input) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("receiveCodeInvalid"), None, msg);
            }
        };
        let Some(input) = input_opt else {
            return error_json(
                "null_pointer",
                Some("receiveCodeInvalid"),
                None,
                "raw_input pointer must not be null",
            );
        };
        match ValidatedCode::from_user_input(input) {
            Ok(validated) => serialize_or_error(&validated),
            Err(err) => error_json(
                uri_error_kind(&err),
                Some(err.l10n_key()),
                None,
                format_uri_error_message(&err),
            ),
        }
    })
}

/// Formats floor-rounded regional transfer progress (`#483`) using
/// [`format_regional_percent`].
///
/// Passing a null or whitespace-only `region_tag` defaults to `"en-US"`.
/// The returned pointer must be released with [`totaldrop_win_string_free`].
///
/// # Safety
///
/// `region_tag` must either be null or point to a valid NUL-terminated C
/// string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_format_percent_json(
    done: u64,
    total: u64,
    region_tag: *const c_char,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let region_opt = match unsafe { read_optional_c_str(region_tag) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorOther"), None, msg);
            }
        };
        let sanitized_region = region_opt
            .map(sanitize_ui_metadata)
            .filter(|tag| !tag.is_empty());
        let region = sanitized_region.as_deref().unwrap_or("en-US");
        let percent = format_regional_percent(done, total, region);
        serialize_or_error(&percent)
    })
}

/// Resolves the localized 35-language [`totaldrop_windows_bridge::WindowsUiBundle`]
/// snapshot for the requested BCP 47 language preference list and regional
/// formatting locale.
///
/// `lang_tags` accepts either a comma/semicolon-separated list
/// (`"tr-TR,en-US"`) or a JSON array of strings (`["tr-TR","en-US"]`). Passing
/// null or empty falls back to English (`"en"`). Passing null or empty
/// `app_version` defaults to [`APP_VERSION`].
/// The returned pointer must be released with [`totaldrop_win_string_free`].
///
/// # Safety
///
/// Each non-null pointer (`lang_tags`, `region_tag`, `app_version`) must point
/// to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_ui_bundle_json(
    lang_tags: *const c_char,
    region_tag: *const c_char,
    app_version: *const c_char,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let langs_opt = match unsafe { read_optional_c_str(lang_tags) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorOther"), None, msg);
            }
        };
        // SAFETY: Forwarded from this function's safety contract.
        let region_opt = match unsafe { read_optional_c_str(region_tag) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorOther"), None, msg);
            }
        };
        // SAFETY: Forwarded from this function's safety contract.
        let version_opt = match unsafe { read_optional_c_str(app_version) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorOther"), None, msg);
            }
        };

        let sanitized_version = version_opt
            .map(sanitize_ui_metadata)
            .filter(|ver| !ver.is_empty());
        let version = sanitized_version.as_deref().unwrap_or(APP_VERSION);

        let localizer = build_localizer(langs_opt, region_opt);
        let bundle = localizer.ui_bundle(version);
        serialize_or_error(&bundle)
    })
}

// ---------------------------------------------------------------------------
// Phase 2 Group A Exports (8 JSON DTO / validation exports)

/// Extracts a TotalDrop transfer code or link from arbitrary clipboard or share
/// text via [`ValidatedCode::from_clipboard_text`].
///
/// On success, returns the direct [`ValidatedCode`] JSON. On failure, returns
/// a 4-field error envelope (`empty` -> `receiveCodeInvalid`,
/// `no_code_found_in_text` -> `errorInvalidCode`).
///
/// # Safety
///
/// `raw_text` must either be null or point to a valid NUL-terminated C string
/// for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_extract_clipboard_code_json(
    raw_text: *const c_char,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let text_opt = match unsafe { read_optional_c_str(raw_text) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorInvalidCode"), None, msg);
            }
        };
        let Some(text) = text_opt else {
            return error_json(
                "null_pointer",
                Some("errorInvalidCode"),
                None,
                "raw_text pointer must not be null",
            );
        };
        match ValidatedCode::from_clipboard_text(text) {
            Ok(validated) => serialize_or_error(&validated),
            Err(err) => error_json(
                uri_error_kind(&err),
                Some(err.l10n_key()),
                None,
                format_uri_error_message(&err),
            ),
        }
    })
}

/// Returns up to `limit` BIP-39 English code-word completions matching
/// `prefix` as a direct JSON string array (`["harbor", ...]`).
///
/// # Safety
///
/// `prefix` must either be null or point to a valid NUL-terminated C string
/// for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_code_completions_json(
    prefix: *const c_char,
    limit: u32,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let prefix_opt = match unsafe { read_optional_c_str(prefix) } {
            Ok(opt) => opt,
            Err(msg) => {
                return error_json("invalid_utf8", Some("errorOther"), None, msg);
            }
        };
        let Some(prefix_str) = prefix_opt else {
            return error_json(
                "null_pointer",
                Some("errorOther"),
                None,
                "prefix pointer must not be null",
            );
        };
        let capped = usize::try_from(limit.min(2048)).unwrap_or(2048);
        let words = code_word_completions(prefix_str, capped);
        serialize_or_error(&words)
    })
}

/// Formats `bytes` using TotalDrop's regional SI unit rules (`"0 B"`,
/// `"1.5 MB"`, `"1,5 MB"`) and returns `{"bytes": u64, "formatted": String}`.
///
/// # Safety
///
/// Each non-null pointer (`lang_tags`, `region_tag`) must point to a valid
/// NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_format_bytes_json(
    bytes: u64,
    lang_tags: *const c_char,
    region_tag: *const c_char,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let langs_opt = match unsafe { read_optional_c_str(lang_tags) } {
            Ok(opt) => opt,
            Err(msg) => return error_json("invalid_utf8", Some("errorOther"), None, msg),
        };
        // SAFETY: Forwarded from this function's safety contract.
        let region_opt = match unsafe { read_optional_c_str(region_tag) } {
            Ok(opt) => opt,
            Err(msg) => return error_json("invalid_utf8", Some("errorOther"), None, msg),
        };
        let localizer = build_localizer(langs_opt, region_opt);
        let dto = FormattedBytesDto {
            bytes,
            formatted: localizer.format_bytes(bytes),
        };
        serialize_or_error(&dto)
    })
}

/// Formats a known `l10n/app` message key with optional JSON object arguments
/// (`{"count": 3, "size": "1.5 MB"}`), honoring ICU pluralization, regional
/// digits, RTL FSI/PDI isolation, and `l10n/status.json`'s 11-key critical
/// security English gate.
///
/// Rejects null/empty/unknown keys, `args_json` longer than `16_384` bytes
/// (before JSON parsing), malformed JSON, and non-object or unsupported arg
/// value types.
///
/// # Safety
///
/// Each non-null pointer (`key`, `args_json`, `lang_tags`, `region_tag`) must
/// point to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_format_message_json(
    key: *const c_char,
    args_json: *const c_char,
    lang_tags: *const c_char,
    region_tag: *const c_char,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let key_opt = match unsafe { read_optional_c_str(key) } {
            Ok(opt) => opt,
            Err(msg) => return error_json("invalid_utf8", Some("errorOther"), None, msg),
        };
        let Some(key_str) = key_opt else {
            return error_json(
                "null_pointer",
                Some("errorOther"),
                None,
                "key pointer must not be null",
            );
        };
        if key_str.is_empty() {
            return error_json(
                "empty_key",
                Some("errorOther"),
                None,
                "localization message key must not be empty",
            );
        }

        // SAFETY: Forwarded from this function's safety contract.
        let args_opt = match unsafe { read_optional_c_str(args_json) } {
            Ok(opt) => opt,
            Err(msg) => return error_json("invalid_utf8", Some("errorOther"), None, msg),
        };
        // SAFETY: Forwarded from this function's safety contract.
        let langs_opt = match unsafe { read_optional_c_str(lang_tags) } {
            Ok(opt) => opt,
            Err(msg) => return error_json("invalid_utf8", Some("errorOther"), None, msg),
        };
        // SAFETY: Forwarded from this function's safety contract.
        let region_opt = match unsafe { read_optional_c_str(region_tag) } {
            Ok(opt) => opt,
            Err(msg) => return error_json("invalid_utf8", Some("errorOther"), None, msg),
        };

        enum OwnedArg {
            Text(String),
            Count(u64),
        }

        let mut owned_args: Vec<(String, OwnedArg)> = Vec::new();
        if let Some(raw_args) = args_opt {
            if raw_args.len() > MAX_FORMAT_ARGS_JSON_BYTES {
                return error_json(
                    "args_too_large",
                    Some("errorOther"),
                    None,
                    format!(
                        "args_json of {} bytes exceeds limit of {MAX_FORMAT_ARGS_JSON_BYTES} bytes",
                        raw_args.len()
                    ),
                );
            }
            let trimmed_args = raw_args.trim();
            if !trimmed_args.is_empty() {
                let parsed: serde_json::Value = match serde_json::from_str(trimmed_args) {
                    Ok(v) => v,
                    Err(err) => {
                        return error_json(
                            "invalid_json",
                            Some("errorOther"),
                            None,
                            format!("invalid args_json: {err}"),
                        );
                    }
                };
                let Some(map) = parsed.as_object() else {
                    return error_json(
                        "invalid_args",
                        Some("errorOther"),
                        None,
                        "args_json must be a JSON object",
                    );
                };
                for (arg_name, arg_val) in map {
                    match arg_val {
                        serde_json::Value::String(s) => {
                            owned_args.push((
                                arg_name.clone(),
                                OwnedArg::Text(sanitize_message_text_arg(s)),
                            ));
                        }
                        serde_json::Value::Number(n) => {
                            let Some(count) = n.as_u64() else {
                                return error_json(
                                    "invalid_args",
                                    Some("errorOther"),
                                    None,
                                    format!(
                                        "numeric argument {} must be a non-negative integer",
                                        bounded_debug_preview(arg_name, MAX_ERROR_PREVIEW_CHARS)
                                    ),
                                );
                            };
                            owned_args.push((arg_name.clone(), OwnedArg::Count(count)));
                        }
                        _ => {
                            return error_json(
                                "invalid_args",
                                Some("errorOther"),
                                None,
                                format!(
                                    "argument {} must be a JSON string or unsigned integer",
                                    bounded_debug_preview(arg_name, MAX_ERROR_PREVIEW_CHARS)
                                ),
                            );
                        }
                    }
                }
            }
        }

        let localizer = build_localizer(langs_opt, region_opt);
        if !localizer.has_key(key_str) {
            return error_json(
                "unknown_key",
                Some("errorOther"),
                None,
                format!(
                    "unknown localization message key {}",
                    bounded_debug_preview(key_str, MAX_ERROR_PREVIEW_CHARS)
                ),
            );
        }

        let borrowed_args: Vec<(&str, Arg<'_>)> = owned_args
            .iter()
            .map(|(name, val)| match val {
                OwnedArg::Text(s) => (name.as_str(), Arg::Text(s.as_str())),
                OwnedArg::Count(n) => (name.as_str(), Arg::Count(*n)),
            })
            .collect();

        let Some(formatted) = localizer.format_message(key_str, &borrowed_args) else {
            return error_json(
                "unknown_key",
                Some("errorOther"),
                None,
                format!(
                    "unknown localization message key {}",
                    bounded_debug_preview(key_str, MAX_ERROR_PREVIEW_CHARS)
                ),
            );
        };

        let dto = FormattedMessageDto {
            key: key_str.to_owned(),
            language_tag: localizer.language_tag().to_owned(),
            formatted,
        };
        serialize_or_error(&dto)
    })
}

/// Sanitizes an untrusted filename or directory name for WinUI 3 display,
/// revealing hidden control/bidi characters (`<U+XXXX>`) and wrapping the
/// result in FSI/PDI (`U+2068..U+2069`).
///
/// # Safety
///
/// `raw` must either be null or point to a valid NUL-terminated C string for
/// the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_sanitize_filename_json(raw: *const c_char) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let raw_opt = match unsafe { read_optional_c_str(raw) } {
            Ok(opt) => opt,
            Err(msg) => return error_json("invalid_utf8", Some("errorOther"), None, msg),
        };
        let Some(raw_str) = raw_opt else {
            return error_json(
                "null_pointer",
                Some("errorOther"),
                None,
                "raw filename pointer must not be null",
            );
        };
        let revealed = totaldrop_l10n::reveal_controls(raw_str);
        let has_hidden_controls = revealed != raw_str;
        let dto = SanitizedFilenameDto {
            sanitized: sanitize_peer_filename(raw_str),
            has_hidden_controls,
        };
        serialize_or_error(&dto)
    })
}

/// Sanitizes an untrusted plain-text payload for WinUI 3 display (revealing
/// hidden control/bidi characters and capping screen output at `16_384` chars).
///
/// # Safety
///
/// `raw` must either be null or point to a valid NUL-terminated C string for
/// the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_sanitize_text_json(raw: *const c_char) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let raw_opt = match unsafe { read_optional_c_str(raw) } {
            Ok(opt) => opt,
            Err(msg) => return error_json("invalid_utf8", Some("errorOther"), None, msg),
        };
        let Some(raw_str) = raw_opt else {
            return error_json(
                "null_pointer",
                Some("errorOther"),
                None,
                "raw text pointer must not be null",
            );
        };
        let sanitized = sanitize_peer_text(raw_str);
        serialize_or_error(&sanitized)
    })
}

/// Validates a rendezvous or relay server URL against
/// [`BridgeNetworkConfig::is_valid_rendezvous_url`] (`totaldrop_core::relay::check_url`).
///
/// Returns `{"ok":true}` on success and a 4-field error envelope
/// (`kind: "bad_server"`, `l10n_key: "errorBadServer"`) on failure without
/// opening any network socket.
///
/// # Safety
///
/// `url` must either be null or point to a valid NUL-terminated C string for
/// the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_validate_server_url_json(url: *const c_char) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let url_opt = match unsafe { read_optional_c_str(url) } {
            Ok(opt) => opt,
            Err(msg) => return error_json("invalid_utf8", Some("errorBadServer"), None, msg),
        };
        let Some(url_str) = url_opt else {
            return error_json(
                "null_pointer",
                Some("errorBadServer"),
                None,
                "url pointer must not be null",
            );
        };
        if BridgeNetworkConfig::is_valid_rendezvous_url(url_str) {
            serialize_or_error(&StatusOk { ok: true })
        } else {
            error_json(
                "bad_server",
                Some("errorBadServer"),
                None,
                "the server address is not valid; it must start with wss://",
            )
        }
    })
}

/// Validates and normalizes a JSON array of raw Windows paths (`["C:\\...", "\\\\nas\\share\\..."]`)
/// via [`validate_windows_paths`], returning a direct JSON array of
/// [`totaldrop_windows_bridge::NormalizedWindowsPath`] objects deduplicated
/// case-insensitively while preserving first-seen order.
///
/// # Safety
///
/// `paths_json` must either be null or point to a valid NUL-terminated C string
/// for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_validate_paths_json(
    paths_json: *const c_char,
) -> *mut c_char {
    guard_ffi_json(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let json_opt = match unsafe { read_optional_c_str(paths_json) } {
            Ok(opt) => opt,
            Err(msg) => return error_json("invalid_utf8", Some("errorStorage"), None, msg),
        };
        let Some(json_str) = json_opt else {
            return error_json(
                "null_pointer",
                Some("errorStorage"),
                None,
                "paths_json pointer must not be null",
            );
        };
        let raw_paths: Vec<String> = match serde_json::from_str(json_str) {
            Ok(paths) => paths,
            Err(err) => {
                return error_json(
                    "invalid_json",
                    Some("errorStorage"),
                    None,
                    format!("invalid paths_json array: {err}"),
                );
            }
        };
        match validate_windows_paths(&raw_paths) {
            Ok(normalized) => serialize_or_error(&normalized),
            Err(err) => error_json(
                activation_error_kind(&err),
                Some("errorStorage"),
                None,
                err.to_string(),
            ),
        }
    })
}

// ---------------------------------------------------------------------------
// Phase 2 Group B Exports (10 async session lifecycle & shutdown exports)

/// Starts an asynchronous file/folder send session on the static 2-thread
/// Tokio runtime and returns a monotonic non-zero session handle (`0` on null,
/// invalid UTF-8, or malformed JSON input).
///
/// # Safety
///
/// Each non-null pointer (`cfg_json`, `paths_json`, `lang_tags`, `region_tag`)
/// must point to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_send_files_start(
    cfg_json: *const c_char,
    paths_json: *const c_char,
    lang_tags: *const c_char,
    region_tag: *const c_char,
) -> u64 {
    guard_ffi_u64(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(Some(cfg_str)) = (unsafe { read_optional_c_str(cfg_json) }) else {
            return 0;
        };
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(Some(paths_str)) = (unsafe { read_optional_c_str(paths_json) }) else {
            return 0;
        };
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(langs_opt) = (unsafe { read_optional_c_str(lang_tags) }) else {
            return 0;
        };
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(region_opt) = (unsafe { read_optional_c_str(region_tag) }) else {
            return 0;
        };

        let Ok(ffi_cfg) = serde_json::from_str::<FfiNetworkConfig>(cfg_str) else {
            return 0;
        };
        let Ok(raw_paths) = serde_json::from_str::<Vec<String>>(paths_str) else {
            return 0;
        };

        let localizer = build_localizer(langs_opt, region_opt);
        sessions::start_send_files(ffi_cfg.into_bridge_config(), raw_paths, localizer)
    })
}

/// Starts an asynchronous plain-text send session (`MAX_TEXT = 1_048_576` UTF-8
/// bytes) and returns a monotonic non-zero session handle (`0` on null, invalid
/// UTF-8, or malformed `cfg_json`).
///
/// # Safety
///
/// Each non-null pointer (`cfg_json`, `text`, `lang_tags`, `region_tag`) must
/// point to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_send_text_start(
    cfg_json: *const c_char,
    text: *const c_char,
    lang_tags: *const c_char,
    region_tag: *const c_char,
) -> u64 {
    guard_ffi_u64(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(Some(cfg_str)) = (unsafe { read_optional_c_str(cfg_json) }) else {
            return 0;
        };
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(Some(text_str)) = (unsafe { read_optional_c_str(text) }) else {
            return 0;
        };
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(langs_opt) = (unsafe { read_optional_c_str(lang_tags) }) else {
            return 0;
        };
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(region_opt) = (unsafe { read_optional_c_str(region_tag) }) else {
            return 0;
        };

        let Ok(ffi_cfg) = serde_json::from_str::<FfiNetworkConfig>(cfg_str) else {
            return 0;
        };

        let localizer = build_localizer(langs_opt, region_opt);
        sessions::start_send_text(ffi_cfg.into_bridge_config(), text_str.to_owned(), localizer)
    })
}

/// Starts an asynchronous receive connection for `code_or_uri` and returns a
/// monotonic non-zero session handle (`0` on null, invalid UTF-8, or malformed
/// `cfg_json`).
///
/// # Safety
///
/// Each non-null pointer (`cfg_json`, `code_or_uri`, `lang_tags`, `region_tag`)
/// must point to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_receive_connect_start(
    cfg_json: *const c_char,
    code_or_uri: *const c_char,
    lang_tags: *const c_char,
    region_tag: *const c_char,
) -> u64 {
    guard_ffi_u64(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(Some(cfg_str)) = (unsafe { read_optional_c_str(cfg_json) }) else {
            return 0;
        };
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(Some(code_str)) = (unsafe { read_optional_c_str(code_or_uri) }) else {
            return 0;
        };
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(langs_opt) = (unsafe { read_optional_c_str(lang_tags) }) else {
            return 0;
        };
        // SAFETY: Forwarded from this function's safety contract.
        let Ok(region_opt) = (unsafe { read_optional_c_str(region_tag) }) else {
            return 0;
        };

        let Ok(ffi_cfg) = serde_json::from_str::<FfiNetworkConfig>(cfg_str) else {
            return 0;
        };

        let localizer = build_localizer(langs_opt, region_opt);
        sessions::start_receive_connect(
            ffi_cfg.into_bridge_config(),
            code_str.to_owned(),
            localizer,
        )
    })
}

/// Accepts a pending file/folder offer on `session_id` and saves verified files
/// into `dest_dir`.
///
/// Returns [`FFI_OK`] (`0`) on acceptance or a negative `FFI_ERR_*` status code.
///
/// # Safety
///
/// `dest_dir` must either be null (yielding [`FFI_ERR_NULL_POINTER`]) or point
/// to a valid NUL-terminated C string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn totaldrop_win_receive_accept_files(
    session_id: u64,
    dest_dir: *const c_char,
) -> i32 {
    guard_ffi_i32(|| {
        // SAFETY: Forwarded from this function's safety contract.
        let dir_opt = match unsafe { read_optional_c_str(dest_dir) } {
            Ok(opt) => opt,
            Err(_) => return FFI_ERR_INVALID_UTF8,
        };
        let Some(dir_str) = dir_opt else {
            return FFI_ERR_NULL_POINTER;
        };
        if dir_str.trim().is_empty() {
            return FFI_ERR_INVALID_ARG;
        }
        sessions::accept_receive_files(session_id, dir_str.to_owned())
    })
}

/// Accepts a pending plain-text offer on `session_id` strictly in memory (zero
/// disk writes).
///
/// Returns [`FFI_OK`] (`0`) on acceptance or a negative `FFI_ERR_*` status code.
#[unsafe(no_mangle)]
pub extern "C" fn totaldrop_win_receive_accept_text(session_id: u64) -> i32 {
    guard_ffi_i32(|| sessions::accept_receive_text(session_id))
}

/// Declines a pending incoming offer on `session_id` and emits a `declined`
/// event.
///
/// Returns [`FFI_OK`] (`0`) on success or a negative `FFI_ERR_*` status code.
#[unsafe(no_mangle)]
pub extern "C" fn totaldrop_win_receive_decline(session_id: u64) -> i32 {
    guard_ffi_i32(|| sessions::decline_receive(session_id))
}

/// Drains queued FIFO session events for `session_id` as `\n`-terminated
/// NDJSON (`""` when empty).
///
/// Returns a 4-field `FfiErrorEnvelope` (`kind: "invalid_handle"`,
/// `l10n_key: "errorOther"`) if `session_id` is `0`, unknown, or destroyed.
/// The returned pointer must be released with [`totaldrop_win_string_free`].
#[unsafe(no_mangle)]
pub extern "C" fn totaldrop_win_session_poll_events_ndjson(session_id: u64) -> *mut c_char {
    guard_ffi_json(|| match sessions::poll_session_events_ndjson(session_id) {
        Some(ndjson) => into_c_string_ptr(ndjson),
        None => error_json(
            "invalid_handle",
            Some("errorOther"),
            None,
            "unknown or destroyed session handle",
        ),
    })
}

/// Cooperatively cancels `session_id`.
///
/// Returns [`FFI_ERR_INVALID_HANDLE`] (`-3`) if `session_id` is unknown or
/// destroyed, and idempotently returns [`FFI_OK`] (`0`) if the session has
/// already reached a terminal state (`Done`, `Declined`, `Failed`).
#[unsafe(no_mangle)]
pub extern "C" fn totaldrop_win_session_cancel(session_id: u64) -> i32 {
    guard_ffi_i32(|| sessions::cancel_session(session_id))
}

/// Destroys `session_id`, cancelling any running transfer, stopping any pending
/// offer, and dropping buffered events.
///
/// Returns [`FFI_OK`] (`0`) the first time and [`FFI_ERR_INVALID_HANDLE`] (`-3`)
/// if unknown or already destroyed.
#[unsafe(no_mangle)]
pub extern "C" fn totaldrop_win_session_destroy(session_id: u64) -> i32 {
    guard_ffi_i32(|| sessions::destroy_session(session_id))
}

/// Stops all active transfer sessions, waits up to `timeout_ms` (`1500 ms`
/// default when `0`), aborts stragglers with a `200 ms` unwind window, and
/// awaits `totaldrop_core::portmap::released()`.
///
/// Safe to call repeatedly (idempotent); leaves the static runtime reusable.
#[unsafe(no_mangle)]
pub extern "C" fn totaldrop_win_shutdown(timeout_ms: u32) -> i32 {
    guard_ffi_i32(|| sessions::shutdown_all(timeout_ms))
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;
    use std::ffi::CStr;

    use super::*;

    type TestResult = Result<(), Box<dyn StdError>>;

    fn take_and_free(ptr: *mut c_char) -> Result<String, Box<dyn StdError>> {
        if ptr.is_null() {
            return Err("unexpected null pointer returned by FFI helper".into());
        }
        // SAFETY: `ptr` was just allocated by `into_c_string_ptr` in this crate.
        let text = unsafe { CStr::from_ptr(ptr) }.to_str()?.to_owned();
        // SAFETY: `ptr` was allocated by this crate and is freed exactly once.
        unsafe { totaldrop_win_string_free(ptr) };
        Ok(text)
    }

    #[test]
    fn interior_nul_bytes_are_stripped_before_c_string_allocation() -> TestResult {
        let ptr = into_c_string_ptr("hello\0world\0!".to_owned());
        let rendered = take_and_free(ptr)?;
        assert_eq!(rendered, "helloworld!");
        Ok(())
    }

    #[test]
    fn guard_ffi_helpers_contain_panics() -> TestResult {
        let ptr = guard_ffi_json(|| -> *mut c_char {
            std::panic::resume_unwind(Box::new("synthetic panic for boundary test"));
        });
        let raw = take_and_free(ptr)?;
        let parsed: serde_json::Value = serde_json::from_str(&raw)?;
        assert_eq!(
            parsed.get("ok").and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            parsed
                .get("error")
                .and_then(|e| e.get("kind"))
                .and_then(serde_json::Value::as_str),
            Some("internal")
        );
        assert_eq!(
            parsed
                .get("error")
                .and_then(|e| e.get("l10n_key"))
                .and_then(serde_json::Value::as_str),
            Some("errorOther")
        );

        let handle = guard_ffi_u64(|| -> u64 {
            std::panic::resume_unwind(Box::new("synthetic panic for u64 boundary"));
        });
        assert_eq!(handle, 0);

        let code = guard_ffi_i32(|| -> i32 {
            std::panic::resume_unwind(Box::new("synthetic panic for i32 boundary"));
        });
        assert_eq!(code, FFI_ERR_INTERNAL);
        Ok(())
    }

    #[test]
    fn parse_lang_tags_handles_csv_semicolon_json_array_and_empty() {
        assert!(parse_lang_tags("").is_empty());
        assert!(parse_lang_tags("   ").is_empty());
        assert_eq!(
            parse_lang_tags("tr-TR, en-US , , de-DE"),
            vec!["tr-TR", "en-US", "de-DE"]
        );
        assert_eq!(parse_lang_tags("zh-HK; en-US"), vec!["zh-HK", "en-US"]);
        assert_eq!(
            parse_lang_tags(r#"["ar-SA", " en-US ", ""]"#),
            vec!["ar-SA", "en-US"]
        );
        assert_eq!(
            parse_lang_tags("\x1b\u{202E}tr-TR\x07, \u{2066}en-US\u{2069}"),
            vec!["tr-TR", "en-US"]
        );
    }

    #[test]
    fn sanitize_ui_metadata_strips_controls_bidi_and_nonchars_preserving_clean_tags() {
        assert_eq!(sanitize_ui_metadata("en-US"), "en-US");
        assert_eq!(sanitize_ui_metadata("zh-Hant-TW"), "zh-Hant-TW");
        assert_eq!(sanitize_ui_metadata("0.1.0-beta.1"), "0.1.0-beta.1");
        assert_eq!(
            sanitize_ui_metadata(
                " \x1b[31m\u{202E}en-US\u{0085}\u{00AD}\u{FEFF}\u{FDD0}\u{FFFF}\u{E0041} "
            ),
            "[31men-US"
        );
        assert_eq!(
            sanitize_ui_metadata("\x1b\u{202E}\x07\u{009B}\u{200B}\u{2028}\u{2029}   "),
            ""
        );
    }

    #[test]
    fn format_uri_error_message_bounds_unknown_word_at_64_chars() {
        let exact = UriValidationError::UnknownWord {
            word: "a".repeat(MAX_ERROR_PREVIEW_CHARS),
        };
        let exact_msg = format_uri_error_message(&exact);
        assert!(!exact_msg.contains("..."));
        assert!(exact_msg.contains(&"a".repeat(MAX_ERROR_PREVIEW_CHARS)));

        let over = UriValidationError::UnknownWord {
            word: "b".repeat(MAX_ERROR_PREVIEW_CHARS + 1),
        };
        let over_msg = format_uri_error_message(&over);
        assert!(over_msg.contains("..."));
        assert!(over_msg.len() < 256);
    }

    #[test]
    fn sanitize_message_text_arg_preserves_outer_isolate_and_defeats_breakout() {
        // M5 sendShareText contract: single outer FSI/PDI around clean code preserved verbatim.
        assert_eq!(
            sanitize_message_text_arg("\u{2068}7-harbor-rocket\u{2069}"),
            "\u{2068}7-harbor-rocket\u{2069}"
        );
        // Interior PDI breakout + RLO + ANSI ESC inside outer isolate are revealed cleanly.
        let nested = sanitize_message_text_arg("\u{2068}ok\u{2069}\u{202E}evil\x1b[31m\u{2069}");
        assert_eq!(nested, "\u{2068}ok<U+2069><U+202E>evil<U+001B>[31m\u{2069}");
        // Unwrapped attacker folder path has all hidden chars revealed (preserving ZWNJ/ZWJ/NBSP).
        let folder = sanitize_message_text_arg(
            "C:\\Users\\\u{2069}\u{202E}evil\x1b[31m\u{009B}m\u{FDD0}\u{E0041}\u{200C}\u{00A0}",
        );
        assert_eq!(
            folder,
            "C:\\Users\\<U+2069><U+202E>evil<U+001B>[31m<U+009B>m<U+FDD0><U+E0041>\u{200C}\u{00A0}"
        );
    }
}
