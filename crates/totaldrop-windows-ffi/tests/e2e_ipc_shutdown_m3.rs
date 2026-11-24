// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opaque-box E2E tests for Milestone M3 (`F16`–`F21`, Tier 3) across
//! `totaldrop-windows-ffi` and `totaldrop-windows-bridge`.
//!
//! - Exercises all 7 Phase 3 C ABI router exports (`totaldrop_win_router_*`),
//!   Explorer invocation planning (`plan_explorer_invocation`), protocol URI /
//!   Share Target routing, Windows path security boundaries, and cooperative +
//!   forced `totaldrop_win_shutdown` over loopback `127.0.0.1:0` with
//!   `privacy_relay_only: true` and `stun_server: ""`.
//! - Zero live production connections are ever opened.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::ffi::{CStr, CString, c_char};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use totaldrop_core::framing::write_frame;
use totaldrop_core::{pairing, relay as core_relay, rendezvous, secure, transport};
use totaldrop_crypto::cpace::Role;
use totaldrop_crypto::identity::DeviceKeys;
use totaldrop_crypto::{ContentKey, EntryCipher};
use totaldrop_proto::TransferCode;
use totaldrop_proto::limits;
use totaldrop_proto::relay as proto_relay;
use totaldrop_proto::wire::{
    ClientMessage, Control, DataHeader, Entry, EntryKind, Hints, Manifest, ServerMessage,
};
use totaldrop_windows_bridge::activation::{
    ExplorerLaunchTransport, MAX_COMMAND_LINE_UTF16, MAX_SELECTION_ITEMS, plan_explorer_invocation,
};
use totaldrop_windows_bridge::{
    ActivationEnvelope, MAX_IPC_FRAME_BYTES, SUPPORTED_LANGUAGES, split_win32_command_line,
};
use totaldrop_windows_ffi::{
    FFI_ERR_INVALID_HANDLE, FFI_OK, totaldrop_win_format_message_json,
    totaldrop_win_receive_accept_files, totaldrop_win_receive_connect_start,
    totaldrop_win_router_create, totaldrop_win_router_destroy, totaldrop_win_router_drain_ndjson,
    totaldrop_win_router_ingest_ipc_bytes_json, totaldrop_win_router_set_activity_json,
    totaldrop_win_router_set_animations_json, totaldrop_win_router_update_locale_json,
    totaldrop_win_send_files_start, totaldrop_win_send_text_start, totaldrop_win_session_cancel,
    totaldrop_win_session_destroy, totaldrop_win_session_poll_events_ndjson,
    totaldrop_win_shutdown, totaldrop_win_string_free, totaldrop_win_validate_input_json,
    totaldrop_win_validate_paths_json, totaldrop_win_validate_uri_json,
};

type TestResult = Result<(), Box<dyn StdError>>;

/// Coordinates global `totaldrop_win_shutdown` tests (write lock) with active
/// loopback transfer tests (read lock) inside the same integration test binary.
static SHUTDOWN_GATE: LazyLock<RwLock<()>> = LazyLock::new(|| RwLock::new(()));

static TEST_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .thread_name("totaldrop-m3-srv")
        .build()
        .unwrap_or_else(|_| std::process::abort())
});

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// RAII Guards & FFI Helpers

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Result<Self, std::io::Error> {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("totaldrop-win-m3-e2e-{prefix}-{pid}-{id}"));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct RouterGuard(u64);

impl RouterGuard {
    fn create(
        session_id: u32,
        lang: &str,
        region: &str,
        app_version: &str,
        animations_enabled: bool,
    ) -> Result<Self, Box<dyn StdError>> {
        let lang_c = c_str(lang)?;
        let region_c = c_str(region)?;
        let ver_c = c_str(app_version)?;
        // SAFETY: All three pointers are live NUL-terminated CStrings.
        let handle = unsafe {
            totaldrop_win_router_create(
                session_id,
                lang_c.as_ptr(),
                region_c.as_ptr(),
                ver_c.as_ptr(),
                animations_enabled,
            )
        };
        if handle == 0 {
            return Err("totaldrop_win_router_create returned 0".into());
        }
        Ok(Self(handle))
    }

    fn id(&self) -> u64 {
        self.0
    }

    fn into_raw(mut self) -> u64 {
        let id = self.0;
        self.0 = 0;
        id
    }
}

impl Drop for RouterGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = totaldrop_win_router_destroy(self.0);
        }
    }
}

struct SessionGuard(u64);

impl SessionGuard {
    fn id(&self) -> u64 {
        self.0
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = totaldrop_win_session_destroy(self.0);
        }
    }
}

fn c_str(s: &str) -> Result<CString, Box<dyn StdError>> {
    Ok(CString::new(s)?)
}

fn take_raw_string(ptr: *mut c_char) -> Result<String, Box<dyn StdError>> {
    if ptr.is_null() {
        return Err("FFI returned NULL pointer".into());
    }
    // SAFETY: `ptr` was returned by a `totaldrop_win_*` FFI export.
    let raw = unsafe { CStr::from_ptr(ptr) }.to_str()?.to_owned();
    // SAFETY: Freed exactly once via `totaldrop_win_string_free`.
    unsafe { totaldrop_win_string_free(ptr) };
    Ok(raw)
}

fn take_json(ptr: *mut c_char) -> Result<Value, Box<dyn StdError>> {
    let raw = take_raw_string(ptr)?;
    Ok(serde_json::from_str(&raw)?)
}

fn assert_direct_dto_ok(val: &Value) -> TestResult {
    if val.get("error").is_some() || val.get("ok") == Some(&Value::Bool(false)) {
        return Err(format!("expected direct DTO success, got: {val}").into());
    }
    Ok(())
}

fn assert_error_envelope(
    val: &Value,
    expected_kind: Option<&str>,
    expected_l10n_key: Option<&str>,
) -> Result<String, Box<dyn StdError>> {
    if val.get("ok").and_then(Value::as_bool) != Some(false) {
        return Err(format!("expected error envelope ok==false, got: {val}").into());
    }
    let err = val
        .get("error")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing error object: {val}"))?;
    for key in err.keys() {
        if !matches!(key.as_str(), "kind" | "l10n_key" | "cause" | "message") {
            return Err(format!("unexpected extra key {key:?} in error envelope: {val}").into());
        }
    }
    if let Some(kind) = expected_kind {
        let actual = err.get("kind").and_then(Value::as_str);
        if actual != Some(kind) {
            return Err(format!("expected error.kind=={kind:?}, got {actual:?} ({val})").into());
        }
    }
    if let Some(l10n_key) = expected_l10n_key {
        let actual = err.get("l10n_key").and_then(Value::as_str);
        if actual != Some(l10n_key) {
            return Err(
                format!("expected error.l10n_key=={l10n_key:?}, got {actual:?} ({val})").into(),
            );
        }
    }
    let message = err
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing error.message in {val}"))?;
    if message.is_empty() {
        return Err(format!("empty error.message in {val}").into());
    }
    Ok(message.to_owned())
}

fn frame_bytes(payload: &[u8]) -> Result<Vec<u8>, Box<dyn StdError>> {
    let len = u32::try_from(payload.len())?;
    let mut out = Vec::with_capacity(payload.len().saturating_add(4));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn router_ingest(router_id: u64, bytes: &[u8]) -> Result<Value, Box<dyn StdError>> {
    let ptr = if bytes.is_empty() {
        ptr::null()
    } else {
        bytes.as_ptr()
    };
    // SAFETY: Either `bytes.len() == 0` (pointer never dereferenced) or `ptr` points to `bytes.len()` live bytes.
    take_json(unsafe { totaldrop_win_router_ingest_ipc_bytes_json(router_id, ptr, bytes.len()) })
}

fn router_set_activity(router_id: u64, activity_json: &str) -> Result<Value, Box<dyn StdError>> {
    let c = c_str(activity_json)?;
    // SAFETY: `c` is a live NUL-terminated CString.
    take_json(unsafe { totaldrop_win_router_set_activity_json(router_id, c.as_ptr()) })
}

fn router_drain_messages(router_id: u64) -> Result<Vec<Value>, Box<dyn StdError>> {
    let raw = take_raw_string(totaldrop_win_router_drain_ndjson(router_id))?;
    let mut msgs = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            msgs.push(serde_json::from_str(trimmed)?);
        }
    }
    Ok(msgs)
}

fn validate_paths_ffi(paths: &[&str]) -> Result<Value, Box<dyn StdError>> {
    let json_s = serde_json::to_string(paths)?;
    let c = c_str(&json_s)?;
    // SAFETY: `c` is a live NUL-terminated CString.
    take_json(unsafe { totaldrop_win_validate_paths_json(c.as_ptr()) })
}

fn validate_uri(uri: &str) -> Result<Value, Box<dyn StdError>> {
    let c = c_str(uri)?;
    // SAFETY: `c` is a live NUL-terminated CString.
    take_json(unsafe { totaldrop_win_validate_uri_json(c.as_ptr()) })
}

fn validate_input_ffi(input: &str) -> Result<Value, Box<dyn StdError>> {
    let c = c_str(input)?;
    // SAFETY: `c` is a live NUL-terminated CString.
    take_json(unsafe { totaldrop_win_validate_input_json(c.as_ptr()) })
}

fn format_message_ffi(key: &str, lang: &str, region: &str) -> Result<Value, Box<dyn StdError>> {
    let key_c = c_str(key)?;
    let args_c = c_str("{}")?;
    let lang_c = c_str(lang)?;
    let reg_c = c_str(region)?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    take_json(unsafe {
        totaldrop_win_format_message_json(
            key_c.as_ptr(),
            args_c.as_ptr(),
            lang_c.as_ptr(),
            reg_c.as_ptr(),
        )
    })
}

fn pseudo_random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    while out.len() < len {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let chunk = z.to_le_bytes();
        let remaining = len.saturating_sub(out.len());
        let take = remaining.min(chunk.len());
        if let Some(slice) = chunk.get(..take) {
            out.extend_from_slice(slice);
        }
    }
    out
}

fn has_part_files(dir: &Path) -> Result<bool, std::io::Error> {
    if !dir.exists() {
        return Ok(false);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(".totaldrop-") && name_str.ends_with(".part") {
            return Ok(true);
        }
        if entry.file_type()?.is_dir() && has_part_files(&entry.path())? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn current_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages.saturating_mul(4096))
}

#[cfg(not(target_os = "linux"))]
fn current_rss_bytes() -> Option<u64> {
    None
}

// ---------------------------------------------------------------------------
// F16–F21 Pure Offline & Router C ABI Tests (Separated cleanly from live loopback
// transfer helpers for static anti-prod-probing clarity)

#[test]
fn t1_f16_03_part_a_plan_explorer_cold_and_warm() -> TestResult {
    let env = ActivationEnvelope::explorer_send(
        [
            r"C:\Users\Alice\a.txt",
            r"C:\Users\Alice\b.pdf",
            r"C:\Users\Alice\c.bin",
        ],
        Some(1),
    )?;
    let cold = plan_explorer_invocation(
        r"C:\Program Files\WindowsApps\TotalDrop\totaldrop-winui.exe",
        &env,
        1,
        false,
    )?;
    match cold {
        ExplorerLaunchTransport::DirectCommandLine {
            command_line,
            utf16_len,
        } => {
            assert!(command_line.contains("--explorer-send"));
            assert!(command_line.contains(" -- "));
            assert!(utf16_len <= MAX_COMMAND_LINE_UTF16);
        }
        other => return Err(format!("expected DirectCommandLine, got {other:?}").into()),
    }

    let warm = plan_explorer_invocation(
        r"C:\Program Files\WindowsApps\TotalDrop\totaldrop-winui.exe",
        &env,
        1,
        true,
    )?;
    match warm {
        ExplorerLaunchTransport::NamedPipeIpc {
            cold_start_command_line,
            ..
        } => {
            assert!(cold_start_command_line.contains("--ipc-await"));
        }
        other => return Err(format!("expected NamedPipeIpc, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn t2_f16_02_plan_explorer_utf16_30000_vs_30001_boundary() -> TestResult {
    let exe = r"C:\App\totaldrop-winui.exe";
    let base_env = ActivationEnvelope::explorer_send([r"C:\d\a"], None)?;
    let base_len = match plan_explorer_invocation(exe, &base_env, 1, false)? {
        ExplorerLaunchTransport::DirectCommandLine { utf16_len, .. } => utf16_len,
        other => return Err(format!("expected DirectCommandLine, got {other:?}").into()),
    };
    assert!(base_len < MAX_COMMAND_LINE_UTF16);

    // Grow single valid NTFS drive path (split into valid <=200-char segments) so
    // `lpCommandLine` hits exact `30_000` vs `30_001` UTF-16 code units.
    let delta_to_30k = MAX_COMMAND_LINE_UTF16.saturating_sub(base_len);
    let mut exact_path = String::from(r"C:\d\a");
    let mut remaining = delta_to_30k;
    while remaining > 0 {
        if remaining >= 201 {
            exact_path.push('\\');
            exact_path.push_str(&"x".repeat(200));
            remaining = remaining.saturating_sub(201);
        } else if remaining >= 2 {
            exact_path.push('\\');
            exact_path.push_str(&"y".repeat(remaining.saturating_sub(1)));
            remaining = 0;
        } else {
            exact_path.push('z');
            remaining = 0;
        }
    }
    let env_30000 = ActivationEnvelope::explorer_send([exact_path.as_str()], None)?;
    match plan_explorer_invocation(exe, &env_30000, 1, false)? {
        ExplorerLaunchTransport::DirectCommandLine { utf16_len, .. } => {
            assert_eq!(utf16_len, MAX_COMMAND_LINE_UTF16);
        }
        other => return Err(format!("expected DirectCommandLine at 30000, got {other:?}").into()),
    }

    let mut over_path = exact_path;
    over_path.push('q');
    let env_30001 = ActivationEnvelope::explorer_send([over_path.as_str()], None)?;
    match plan_explorer_invocation(exe, &env_30001, 1, false)? {
        ExplorerLaunchTransport::NamedPipeIpc {
            cold_start_command_line,
            ..
        } => {
            assert!(cold_start_command_line.contains("--ipc-await"));
        }
        other => return Err(format!("expected NamedPipeIpc at 30001, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn t2_f16_03_shell_metacharacters_and_forbidden_ntfs_chars() -> TestResult {
    // (a) Valid NTFS shell-metacharacter path
    let meta_path = r"C:\Users\A & calc.exe\report (2026) ^ %TEMP%\file.txt";
    let norm = validate_paths_ffi(&[meta_path])?;
    assert_direct_dto_ok(&norm)?;
    let arr = norm.as_array().ok_or("expected JSON array")?;
    assert_eq!(arr.len(), 1);
    let expected_ext = format!(r"\\?\{meta_path}");
    assert_eq!(
        arr.first()
            .and_then(|v| v.get("extended_path"))
            .and_then(Value::as_str),
        Some(expected_ext.as_str())
    );

    let env = ActivationEnvelope::explorer_send([meta_path], None)?;
    let plan = plan_explorer_invocation(r"C:\TotalDrop\totaldrop-winui.exe", &env, 1, false)?;
    let command_line = match plan {
        ExplorerLaunchTransport::DirectCommandLine { command_line, .. } => command_line,
        other => return Err(format!("expected DirectCommandLine, got {other:?}").into()),
    };
    assert!(!command_line.to_ascii_lowercase().contains("cmd.exe"));
    let parsed_argv = split_win32_command_line(&command_line, false)?;
    assert!(
        parsed_argv.contains(&expected_ext),
        "expected verbatim argv token {expected_ext:?}, got {parsed_argv:?}"
    );

    // (b) Forbidden NTFS characters `"` and `|`
    for (bad_path, bad_char) in [
        (r#"C:\Users\A\report "2026"\file.txt"#, '"'),
        (r"C:\Users\A\a|b.txt", '|'),
    ] {
        let res = validate_paths_ffi(&[bad_path])?;
        let msg = assert_error_envelope(
            &res,
            Some("forbidden_segment_character"),
            Some("errorStorage"),
        )?;
        assert!(
            msg.contains(bad_char),
            "expected forbidden char {bad_char:?} in message: {msg}"
        );
    }
    Ok(())
}

#[test]
fn t1_f17_01_router_lifecycle_explorer_locale_animations_drain() -> TestResult {
    let router = RouterGuard::create(1, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let env = ActivationEnvelope::explorer_send(
        vec![r"C:\Users\Alice\report.pdf".to_owned()],
        Some(4242),
    )?;
    let framed = env.encode_ipc_frame()?;
    let decs = router_ingest(router.id(), &framed)?;
    assert_direct_dto_ok(&decs)?;
    let arr = decs.as_array().ok_or("expected decision array")?;
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr.first()
            .and_then(|v| v.get("decision"))
            .and_then(Value::as_str),
        Some("navigate_send_files")
    );
    assert_eq!(
        arr.first()
            .and_then(|v| v.get("paths"))
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str),
        Some(r"\\?\C:\Users\Alice\report.pdf")
    );

    let tr_lang = c_str("tr-TR")?;
    let tr_reg = c_str("tr-TR")?;
    // SAFETY: Live NUL-terminated CStrings.
    let loc_msg = take_json(unsafe {
        totaldrop_win_router_update_locale_json(router.id(), tr_lang.as_ptr(), tr_reg.as_ptr())
    })?;
    assert_eq!(
        loc_msg.get("kind").and_then(Value::as_str),
        Some("ui_bundle_ready")
    );
    let data = loc_msg.get("data").ok_or("missing data")?;
    assert_eq!(data.get("language_tag").and_then(Value::as_str), Some("tr"));
    assert_eq!(
        data.get("flow_direction").and_then(Value::as_str),
        Some("LeftToRight")
    );
    assert_eq!(
        data.get("verification_title").and_then(Value::as_str),
        Some("Doğrulama kelimeleri")
    );

    let anim_msg = take_json(totaldrop_win_router_set_animations_json(router.id(), false))?;
    assert_eq!(
        anim_msg.get("kind").and_then(Value::as_str),
        Some("mark_animation_state")
    );
    let adata = anim_msg.get("data").ok_or("missing animation data")?;
    assert_eq!(adata.get("animate").and_then(Value::as_bool), Some(false));
    assert_eq!(
        adata.get("hex_light").and_then(Value::as_str),
        Some("#6D4AE0")
    );
    assert_eq!(
        adata.get("hex_dark").and_then(Value::as_str),
        Some("#A68BFF")
    );
    assert_eq!(adata.get("cycle_ms").and_then(Value::as_u64), Some(3200));

    let drained = router_drain_messages(router.id())?;
    let kinds: Vec<&str> = drained
        .iter()
        .filter_map(|m| m.get("kind").and_then(Value::as_str))
        .collect();
    assert!(
        kinds.contains(&"route_decision"),
        "missing route_decision: {kinds:?}"
    );
    assert!(
        kinds.contains(&"ui_bundle_ready"),
        "missing ui_bundle_ready: {kinds:?}"
    );
    assert!(
        kinds.contains(&"mark_animation_state"),
        "missing mark_animation_state: {kinds:?}"
    );

    let raw_id = router.into_raw();
    assert_eq!(totaldrop_win_router_destroy(raw_id), FFI_OK);
    assert_eq!(totaldrop_win_router_destroy(raw_id), FFI_ERR_INVALID_HANDLE);
    Ok(())
}

#[test]
fn t1_f17_02_router_byte_by_byte_concatenated_frames_and_eof() -> TestResult {
    let router = RouterGuard::create(2, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let _ = router_drain_messages(router.id())?;

    let env1 = ActivationEnvelope::explorer_send(vec![r"C:\tmp\first.txt".to_owned()], Some(10))?;
    let env2 = ActivationEnvelope::protocol_uri("totaldrop://r/7-harbor-rocket", Some(11))?;
    let f1 = env1.encode_ipc_frame()?;
    let f2 = env2.encode_ipc_frame()?;
    let mut stream = Vec::with_capacity(f1.len().saturating_add(f2.len()));
    stream.extend_from_slice(&f1);
    stream.extend_from_slice(&f2);

    let mut collected: Vec<Value> = Vec::new();
    for (idx, &byte) in stream.iter().enumerate() {
        let out = router_ingest(router.id(), &[byte])?;
        let arr = out.as_array().ok_or("expected array")?;
        if idx.saturating_add(1) == f1.len() || idx.saturating_add(1) == stream.len() {
            assert_eq!(
                arr.len(),
                1,
                "expected decision at frame boundary idx={idx}"
            );
            collected.extend(arr.iter().cloned());
        } else {
            assert!(
                arr.is_empty(),
                "unexpected early decision at idx={idx}: {out}"
            );
        }
    }

    // 0-byte EOF flush at clean boundary returns []
    let eof_out = router_ingest(router.id(), &[])?;
    assert_eq!(eof_out, json!([]));

    assert_eq!(collected.len(), 2);
    assert_eq!(
        collected
            .first()
            .and_then(|v| v.get("decision"))
            .and_then(Value::as_str),
        Some("navigate_send_files")
    );
    assert_eq!(
        collected
            .get(1)
            .and_then(|v| v.get("decision"))
            .and_then(Value::as_str),
        Some("navigate_receive_code")
    );

    let drained = router_drain_messages(router.id())?;
    let route_msgs: Vec<&Value> = drained
        .iter()
        .filter(|m| m.get("kind").and_then(Value::as_str) == Some("route_decision"))
        .collect();
    assert_eq!(route_msgs.len(), 2);
    Ok(())
}

#[test]
fn t2_f17_01_router_zero_length_header_and_clean_recovery() -> TestResult {
    let router = RouterGuard::create(3, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let bad = router_ingest(router.id(), &[0, 0, 0, 0])?;
    let _ = assert_error_envelope(&bad, Some("malformed_ipc_frame"), Some("errorOther"))?;

    // Subsequent valid frame must decode cleanly
    let ok_env =
        ActivationEnvelope::open_screen(totaldrop_windows_bridge::ScreenTarget::Receive, None);
    let ok = router_ingest(router.id(), &ok_env.encode_ipc_frame()?)?;
    assert_eq!(
        ok.as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.get("decision"))
            .and_then(Value::as_str),
        Some("switch_screen")
    );
    Ok(())
}

#[test]
fn t2_f17_02_router_exact_4mib_boundary_and_zero_oom_overflow() -> TestResult {
    let router = RouterGuard::create(4, "en-US", "en-US", "0.1.0-beta.1", true)?;

    // (a) Exact MAX_IPC_FRAME_BYTES (4_194_304) padded JSON frame
    let base_json = br#"{"version":1,"payload":{"kind":"open_screen","screen":"receive"}}"#;
    let mut padded = Vec::with_capacity(MAX_IPC_FRAME_BYTES);
    padded.extend_from_slice(base_json);
    padded.resize(MAX_IPC_FRAME_BYTES, b' ');
    assert_eq!(padded.len(), MAX_IPC_FRAME_BYTES);
    let exact_frame = frame_bytes(&padded)?;
    let ok = router_ingest(router.id(), &exact_frame)?;
    let arr = ok.as_array().ok_or("expected array")?;
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr.first()
            .and_then(|v| v.get("decision"))
            .and_then(Value::as_str),
        Some("switch_screen")
    );
    assert_eq!(
        arr.first()
            .and_then(|v| v.get("screen"))
            .and_then(Value::as_str),
        Some("receive")
    );

    // (b) 4_194_305 (4 MiB + 1) and u32::MAX rejected in < 50 ms with < 1 MiB RSS delta
    for (hdr, expected_num) in [
        (4_194_305u32.to_le_bytes(), "4194305"),
        (u32::MAX.to_le_bytes(), "4294967295"),
    ] {
        let rss_before = current_rss_bytes();
        let t0 = Instant::now();
        let res = router_ingest(router.id(), &hdr)?;
        let elapsed = t0.elapsed();
        let rss_after = current_rss_bytes();
        let msg = assert_error_envelope(&res, Some("envelope_too_large"), Some("errorOther"))?;
        assert!(
            msg.contains(expected_num),
            "expected {expected_num} in error message: {msg}"
        );
        assert!(
            elapsed < Duration::from_millis(50),
            "overflow header rejection took too long: {elapsed:?}"
        );
        if let (Some(b), Some(a)) = (rss_before, rss_after) {
            let delta = a.saturating_sub(b);
            assert!(
                delta < 1_048_576,
                "RSS jumped by {delta} bytes on overflow header {expected_num}"
            );
        }
    }

    // (c) Clean recovery on subsequent valid frame
    let recovery =
        ActivationEnvelope::open_screen(totaldrop_windows_bridge::ScreenTarget::Send, None);
    let rec_out = router_ingest(router.id(), &recovery.encode_ipc_frame()?)?;
    assert_eq!(
        rec_out
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.get("screen"))
            .and_then(Value::as_str),
        Some("send")
    );
    Ok(())
}

#[test]
fn t2_f17_03_router_truncated_streams_eof_and_recovery() -> TestResult {
    let router = RouterGuard::create(5, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let _ = router_drain_messages(router.id())?;

    // (a) 2-byte partial header + 0-byte EOF flush
    assert_eq!(router_ingest(router.id(), &[0x64, 0x00])?, json!([]));
    let eof1 = router_ingest(router.id(), &[])?;
    let _ = assert_error_envelope(&eof1, Some("malformed_ipc_frame"), Some("errorOther"))?;

    // (b) 4-byte header declaring 100 bytes + only 40 payload bytes + 0-byte EOF flush
    let mut partial = Vec::with_capacity(44);
    partial.extend_from_slice(&100u32.to_le_bytes());
    partial.extend_from_slice(&[b' '; 40]);
    assert_eq!(router_ingest(router.id(), &partial)?, json!([]));
    let eof2 = router_ingest(router.id(), &[])?;
    let _ = assert_error_envelope(&eof2, Some("malformed_ipc_frame"), Some("errorOther"))?;

    // Zero route_decision emitted so far
    let drained = router_drain_messages(router.id())?;
    assert!(
        drained
            .iter()
            .all(|m| m.get("kind").and_then(Value::as_str) != Some("route_decision")),
        "truncated streams must not emit route_decision: {drained:?}"
    );

    // (c) Subsequent valid frame decodes cleanly
    let ok_env =
        ActivationEnvelope::open_screen(totaldrop_windows_bridge::ScreenTarget::Settings, None);
    let ok = router_ingest(router.id(), &ok_env.encode_ipc_frame()?)?;
    assert_eq!(
        ok.as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.get("screen"))
            .and_then(Value::as_str),
        Some("settings")
    );
    Ok(())
}

#[test]
fn t2_f17_04_router_schema_and_invariant_bypass_attempts() -> TestResult {
    let router = RouterGuard::create(6, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let _ = router_drain_messages(router.id())?;

    // (a) version: 2
    let v2 = frame_bytes(br#"{"version":2,"payload":{"kind":"open_screen","screen":"send"}}"#)?;
    let _ = assert_error_envelope(
        &router_ingest(router.id(), &v2)?,
        Some("unsupported_schema_version"),
        Some("errorOther"),
    )?;

    // (b) version: 0
    let v0 = frame_bytes(br#"{"version":0,"payload":{"kind":"open_screen","screen":"send"}}"#)?;
    let _ = assert_error_envelope(
        &router_ingest(router.id(), &v0)?,
        Some("unsupported_schema_version"),
        Some("errorOther"),
    )?;

    // (c) explorer_send with dot-traversal path
    let trav = frame_bytes(
        br#"{"version":1,"payload":{"kind":"explorer_send","paths":["C:\\Windows\\..\\secret"]}}"#,
    )?;
    let msg_trav = assert_error_envelope(
        &router_ingest(router.id(), &trav)?,
        Some("invalid_json"),
        Some("errorOther"),
    )?;
    assert!(
        msg_trav.contains("dot and parent-directory traversal segments are forbidden"),
        "unexpected traversal error: {msg_trav}"
    );

    // (d) protocol_uri with tampered canonical == "7-0-0"
    let tampered_uri = frame_bytes(
        br#"{"version":1,"payload":{"kind":"protocol_uri","code":{"display_english":"7-harbor-rocket","canonical":"7-0-0","nameplate":7,"word_count":2,"ltr_isolated":"\u20687-harbor-rocket\u2069","protocol_uri":"totaldrop://r/7-harbor-rocket","web_uri":"https://totaldrop.app/r#7-harbor-rocket"}}}"#,
    )?;
    let _ = assert_error_envelope(
        &router_ingest(router.id(), &tampered_uri)?,
        Some("invalid_uri"),
        Some("errorInvalidCode"),
    )?;

    let drained = router_drain_messages(router.id())?;
    assert!(
        drained
            .iter()
            .all(|m| m.get("kind").and_then(Value::as_str) != Some("route_decision")),
        "invalid frames must emit 0 route_decision messages: {drained:?}"
    );
    Ok(())
}

#[test]
fn t2_f17_05_router_busy_states_reject_all_activations() -> TestResult {
    let router = RouterGuard::create(7, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let busy_states = [
        r#"{"state":"preparing_send"}"#,
        r#"{"state":"waiting_for_peer","code":"7-harbor-rocket"}"#,
        r#"{"state":"connecting_receive","code":"7-harbor-rocket"}"#,
        r#"{"state":"offer_prompt_pending"}"#,
        r#"{"state":"transferring","done_bytes":100,"total_bytes":1000}"#,
        r#"{"state":"showing_text_note"}"#,
    ];

    let exp_frame = ActivationEnvelope::explorer_send(vec![r"C:\tmp\a.txt".to_owned()], None)?
        .encode_ipc_frame()?;
    let share_frame =
        ActivationEnvelope::share_target(Vec::<String>::new(), Some("hello".to_owned()), None)?
            .encode_ipc_frame()?;
    let uri_frame = ActivationEnvelope::protocol_uri("totaldrop://r/7-harbor-rocket", None)?
        .encode_ipc_frame()?;

    let share_busy_expected = {
        let v = format_message_ffi("shareBusy", "en-US", "en-US")?;
        assert_direct_dto_ok(&v)?;
        v.get("formatted")
            .and_then(Value::as_str)
            .ok_or("missing shareBusy formatted")?
            .to_owned()
    };
    let link_busy_expected = {
        let v = format_message_ffi("linkBusy", "en-US", "en-US")?;
        assert_direct_dto_ok(&v)?;
        v.get("formatted")
            .and_then(Value::as_str)
            .ok_or("missing linkBusy formatted")?
            .to_owned()
    };

    for state_json in busy_states {
        let _ = router_set_activity(router.id(), state_json)?;
        for (frame, expected_banner) in [
            (&exp_frame, &share_busy_expected),
            (&share_frame, &share_busy_expected),
            (&uri_frame, &link_busy_expected),
        ] {
            let out = router_ingest(router.id(), frame)?;
            let dec = out
                .as_array()
                .and_then(|a| a.first())
                .ok_or("expected single decision")?;
            assert_eq!(
                dec.get("decision").and_then(Value::as_str),
                Some("reject_busy")
            );
            assert_eq!(
                dec.get("localized_banner").and_then(Value::as_str),
                Some(expected_banner.as_str())
            );
        }
    }
    Ok(())
}

#[test]
fn t1_f18_01_part_a_all_three_accepted_link_forms() -> TestResult {
    for uri in [
        "totaldrop://r/7-harbor-rocket",
        "totaldrop:7-harbor-rocket",
        "https://totaldrop.app/r#7-harbor-rocket",
    ] {
        let v = validate_uri(uri)?;
        assert_direct_dto_ok(&v)?;
        assert_eq!(
            v.get("display_english").and_then(Value::as_str),
            Some("7-harbor-rocket")
        );
    }
    Ok(())
}

#[test]
fn t1_f18_02_share_target_unc_and_drive_paths() -> TestResult {
    let router = RouterGuard::create(8, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let env = ActivationEnvelope::share_target(
        vec![
            r"\\nas01\share\brief.pdf".to_owned(),
            r"C:\Users\Alice\a.txt".to_owned(),
        ],
        None,
        Some(99),
    )?;
    let out = router_ingest(router.id(), &env.encode_ipc_frame()?)?;
    let dec = out
        .as_array()
        .and_then(|a| a.first())
        .ok_or("missing decision")?;
    assert_eq!(
        dec.get("decision").and_then(Value::as_str),
        Some("navigate_send_files")
    );
    let paths: Vec<&str> = dec
        .get("paths")
        .and_then(Value::as_array)
        .ok_or("missing paths")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        paths,
        vec![
            r"\\?\UNC\nas01\share\brief.pdf",
            r"\\?\C:\Users\Alice\a.txt"
        ]
    );
    Ok(())
}

#[test]
fn t1_f18_03_share_target_plain_text_mode() -> TestResult {
    let router = RouterGuard::create(9, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let env = ActivationEnvelope::share_target(
        Vec::<String>::new(),
        Some("Ship package at 14:00".to_owned()),
        Some(100),
    )?;
    let out = router_ingest(router.id(), &env.encode_ipc_frame()?)?;
    let dec = out
        .as_array()
        .and_then(|a| a.first())
        .ok_or("missing decision")?;
    assert_eq!(
        dec.get("decision").and_then(Value::as_str),
        Some("navigate_send_text")
    );
    assert_eq!(
        dec.get("raw_text").and_then(Value::as_str),
        Some("Ship package at 14:00")
    );
    assert_eq!(
        dec.get("sanitized_preview")
            .and_then(|p| p.get("has_hidden_controls"))
            .and_then(Value::as_bool),
        Some(false)
    );
    Ok(())
}

#[test]
fn t2_f18_01_malicious_protocol_uris_rejected() -> TestResult {
    let long_uri = format!("totaldrop://r/{}", "a".repeat(1011));
    assert_eq!(long_uri.len(), 1025);
    let long_res = validate_uri(&long_uri)?;
    let long_msg =
        assert_error_envelope(&long_res, Some("link_too_long"), Some("errorInvalidCode"))?;
    assert!(
        long_msg.contains("1025") && long_msg.contains("1024"),
        "{long_msg}"
    );

    for bad_uri in [
        "totaldrop://r/%2537-harbor-rocket",
        "totaldrop://r/7-harbor-rocket?evil=1",
        "totaldrop://r/7-harbor-rocket/extra",
        "https://totaldrop.app.evil.example/r#7-harbor-rocket",
    ] {
        let res = validate_uri(bad_uri)?;
        let _ = assert_error_envelope(
            &res,
            Some("invalid_activation_link"),
            Some("errorInvalidCode"),
        )?;
    }
    Ok(())
}

#[test]
fn t2_f18_02_malformed_uris_and_bare_invalid_codes() -> TestResult {
    // (a) 6 malformed URIs -> invalid_activation_link / errorInvalidCode
    for bad_uri in [
        "totaldrop://r/0-harbor-rocket",
        "totaldrop://r/7-harbor",
        "totaldrop://r/7-harbor-rocket-harbor-rocket",
        "totaldrop://r/7-notaword-rocket",
        "totaldrop://r/",
        "https://evil.example/r#7-harbor-rocket",
    ] {
        let res = validate_uri(bad_uri)?;
        let _ = assert_error_envelope(
            &res,
            Some("invalid_activation_link"),
            Some("errorInvalidCode"),
        )?;
    }

    // (b) 4 bare invalid codes -> exact snake_case kinds / receiveCodeInvalid
    let _ = assert_error_envelope(
        &validate_input_ffi("0-harbor-rocket")?,
        Some("bad_nameplate"),
        Some("receiveCodeInvalid"),
    )?;
    let _ = assert_error_envelope(
        &validate_input_ffi("7-harbor")?,
        Some("wrong_word_count"),
        Some("receiveCodeInvalid"),
    )?;
    let _ = assert_error_envelope(
        &validate_input_ffi("7-harbor-rocket-harbor-rocket")?,
        Some("wrong_word_count"),
        Some("receiveCodeInvalid"),
    )?;
    let unk_msg = assert_error_envelope(
        &validate_input_ffi("7-notaword-rocket")?,
        Some("unknown_word"),
        Some("receiveCodeInvalid"),
    )?;
    assert!(
        unk_msg.contains("notaword"),
        "expected 'notaword' in {unk_msg}"
    );
    Ok(())
}

#[test]
fn t2_f18_03_part_a_share_target_negative_paths_and_10001_cap() -> TestResult {
    let router = RouterGuard::create(10, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let _ = router_drain_messages(router.id())?;

    // (a)-(c) direct validate_paths_json + framed share_target ingest
    for (bad_path, direct_kind) in [
        (r"\\server", "not_absolute_windows_path"),
        (r"\\server\", "not_absolute_windows_path"),
        (r"\\.\PhysicalDrive0", "device_namespace_forbidden"),
        (r"C:\tmp\a.txt:stream", "forbidden_segment_character"),
    ] {
        let direct = validate_paths_ffi(&[bad_path])?;
        let _ = assert_error_envelope(&direct, Some(direct_kind), Some("errorStorage"))?;

        let raw_json = json!({
            "version": 1,
            "payload": {
                "kind": "share_target",
                "paths": [bad_path],
                "text": null
            }
        })
        .to_string();
        let framed = frame_bytes(raw_json.as_bytes())?;
        let r_res = router_ingest(router.id(), &framed)?;
        let _ = assert_error_envelope(&r_res, Some("invalid_json"), Some("errorOther"))?;
    }

    // (d) 10_001 valid paths framed -> too_many_items citing "10001"
    let paths_10001: Vec<String> = (0..MAX_SELECTION_ITEMS.saturating_add(1))
        .map(|i| format!(r"C:\d\f{i:05}.txt"))
        .collect();
    let big_json = json!({
        "version": 1,
        "payload": {
            "kind": "share_target",
            "paths": paths_10001,
            "text": null
        }
    })
    .to_string();
    let big_frame = frame_bytes(big_json.as_bytes())?;
    let big_res = router_ingest(router.id(), &big_frame)?;
    let msg = assert_error_envelope(&big_res, Some("too_many_items"), Some("errorStorage"))?;
    assert!(msg.contains("10001"), "expected '10001' in {msg}");

    let drained = router_drain_messages(router.id())?;
    assert!(
        drained
            .iter()
            .all(|m| m.get("kind").and_then(Value::as_str) != Some("route_decision")),
        "rejected ShareTarget payloads must emit 0 route_decision messages"
    );
    Ok(())
}

#[test]
fn t2_f18_04_share_target_bidi_text_and_empty_payload() -> TestResult {
    let router = RouterGuard::create(11, "en-US", "en-US", "0.1.0-beta.1", true)?;

    // (a) Plain text with U+202E RLO -> navigate_send_text with <U+202E> revealed
    let raw_text = "Meet at 15:00 \u{202E}secret";
    let env_a =
        ActivationEnvelope::share_target(Vec::<String>::new(), Some(raw_text.to_owned()), None)?;
    let out_a = router_ingest(router.id(), &env_a.encode_ipc_frame()?)?;
    let dec_a = out_a
        .as_array()
        .and_then(|a| a.first())
        .ok_or("missing dec_a")?;
    assert_eq!(
        dec_a.get("decision").and_then(Value::as_str),
        Some("navigate_send_text")
    );
    assert_eq!(
        dec_a.get("raw_text").and_then(Value::as_str),
        Some(raw_text)
    );
    let preview = dec_a.get("sanitized_preview").ok_or("missing preview")?;
    assert_eq!(
        preview.get("has_hidden_controls").and_then(Value::as_bool),
        Some(true)
    );
    let disp = preview
        .get("display_text")
        .and_then(Value::as_str)
        .ok_or("missing display_text")?;
    assert!(disp.contains("<U+202E>"), "expected <U+202E> in {disp:?}");

    // (b) Empty paths=[] and text=null -> switch_screen send
    let env_b = ActivationEnvelope::share_target(Vec::<String>::new(), None, None)?;
    let out_b = router_ingest(router.id(), &env_b.encode_ipc_frame()?)?;
    let dec_b = out_b
        .as_array()
        .and_then(|a| a.first())
        .ok_or("missing dec_b")?;
    assert_eq!(
        dec_b.get("decision").and_then(Value::as_str),
        Some("switch_screen")
    );
    assert_eq!(dec_b.get("screen").and_then(Value::as_str), Some("send"));
    Ok(())
}

#[test]
fn t2_f18_05_totaldrop_link_vs_non_totaldrop_web_url() -> TestResult {
    let router = RouterGuard::create(12, "en-US", "en-US", "0.1.0-beta.1", true)?;

    // TotalDrop link validates and routes to navigate_receive_code
    let td_url = "https://totaldrop.app/r#7-harbor-rocket";
    let valid = validate_uri(td_url)?;
    assert_direct_dto_ok(&valid)?;
    let env_td = ActivationEnvelope::protocol_uri(td_url, None)?;
    let out_td = router_ingest(router.id(), &env_td.encode_ipc_frame()?)?;
    let dec_td = out_td
        .as_array()
        .and_then(|a| a.first())
        .ok_or("missing dec_td")?;
    assert_eq!(
        dec_td.get("decision").and_then(Value::as_str),
        Some("navigate_receive_code")
    );
    assert_eq!(
        dec_td
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str),
        Some("7-harbor-rocket")
    );

    // Non-TotalDrop URL fails validate_uri_json and routes via share_target text -> navigate_send_text
    let other_url = "https://example.test/article";
    let invalid = validate_uri(other_url)?;
    let _ = assert_error_envelope(
        &invalid,
        Some("invalid_activation_link"),
        Some("errorInvalidCode"),
    )?;

    let env_other =
        ActivationEnvelope::share_target(Vec::<String>::new(), Some(other_url.to_owned()), None)?;
    let out_other = router_ingest(router.id(), &env_other.encode_ipc_frame()?)?;
    let dec_other = out_other
        .as_array()
        .and_then(|a| a.first())
        .ok_or("missing dec_other")?;
    assert_eq!(
        dec_other.get("decision").and_then(Value::as_str),
        Some("navigate_send_text")
    );
    assert_eq!(
        dec_other.get("raw_text").and_then(Value::as_str),
        Some(other_url)
    );
    Ok(())
}

#[test]
fn t1_f19_04_part_a_toast_switch_rejected_as_path() -> TestResult {
    let res = validate_paths_ffi(&["----AppNotificationActivated:"])?;
    let _ = assert_error_envelope(
        &res,
        Some("not_absolute_windows_path"),
        Some("errorStorage"),
    )?;
    Ok(())
}

#[test]
fn t1_f20_05_keep_awake_reason_all_35_locales() -> TestResult {
    assert_eq!(SUPPORTED_LANGUAGES.len(), 35);
    for tag in SUPPORTED_LANGUAGES {
        let v = format_message_ffi("keepAwakeReason", tag, tag)?;
        assert_direct_dto_ok(&v)?;
        let txt = v
            .get("formatted")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing formatted keepAwakeReason for {tag}"))?;
        assert!(!txt.trim().is_empty(), "empty keepAwakeReason for {tag}");
        assert!(
            !txt.chars().any(char::is_control),
            "control char in keepAwakeReason for {tag}: {txt:?}"
        );
    }
    Ok(())
}

#[test]
fn t1_f21_05_canonical_safe_drive_unc_and_extended_paths() -> TestResult {
    let res = validate_paths_ffi(&[
        r"C:\Users\Alice\docs\a.txt",
        r"\\nas\pub\b.bin",
        r"\\?\D:\archive\2026\c.zip",
    ])?;
    assert_direct_dto_ok(&res)?;
    let arr = res.as_array().ok_or("expected array")?;
    assert_eq!(arr.len(), 3);
    let expected = [
        (
            r"\\?\C:\Users\Alice\docs\a.txt",
            r"C:\Users\Alice\docs\a.txt",
        ),
        (r"\\?\UNC\nas\pub\b.bin", r"\\nas\pub\b.bin"),
        (r"\\?\D:\archive\2026\c.zip", r"D:\archive\2026\c.zip"),
    ];
    for (idx, (ext, disp)) in expected.iter().enumerate() {
        let item = arr.get(idx).ok_or("missing item")?;
        assert_eq!(
            item.get("extended_path").and_then(Value::as_str),
            Some(*ext)
        );
        assert_eq!(
            item.get("unprefixed_path").and_then(Value::as_str),
            Some(*disp)
        );
        assert_eq!(
            item.get("safe_display_path").and_then(Value::as_str),
            Some(*disp)
        );
    }
    Ok(())
}

#[test]
fn t2_f21_01_utf16_32766_vs_32767_and_surrogate_emoji_boundary() -> TestResult {
    // Prefix `\\?\C:\` is 7 UTF-16 code units; build valid <=200-char segments to exact 32_766 UTF-16.
    let mut base = String::from(r"C:\");
    let mut current_ext_utf16 = 7usize; // `\\?\C:\`
    let target_ok = 32_766usize;
    while current_ext_utf16 < target_ok {
        let rem = target_ok.saturating_sub(current_ext_utf16);
        if rem > 201 {
            base.push_str(&"a".repeat(200));
            base.push('\\');
            current_ext_utf16 = current_ext_utf16.saturating_add(201);
        } else {
            base.push_str(&"b".repeat(rem));
            current_ext_utf16 = target_ok;
        }
    }
    let ok = validate_paths_ffi(&[&base])?;
    assert_direct_dto_ok(&ok)?;

    // +1 ASCII char -> 32_767 UTF-16 -> rejected with path_too_long citing 32767
    let mut over_ascii = base.clone();
    over_ascii.push('x');
    let res_ascii = validate_paths_ffi(&[&over_ascii])?;
    let msg_ascii = assert_error_envelope(&res_ascii, Some("path_too_long"), Some("errorStorage"))?;
    assert!(msg_ascii.contains("32767"), "{msg_ascii}");

    // Replace final 1 ASCII char (`b`, 1 UTF-16 unit) with non-BMP emoji `😀` (2 UTF-16 units)
    // so UTF-16 length jumps from 32_766 -> 32_767 even though scalar count stays equal!
    let mut over_emoji = base;
    let _ = over_emoji.pop();
    over_emoji.push('😀');
    let res_emoji = validate_paths_ffi(&[&over_emoji])?;
    let msg_emoji = assert_error_envelope(&res_emoji, Some("path_too_long"), Some("errorStorage"))?;
    assert!(msg_emoji.contains("32767"), "{msg_emoji}");
    Ok(())
}

#[test]
fn t2_f21_02_all_dos_reserved_names_and_unicode_superscripts() -> TestResult {
    let mut reserved_paths: Vec<String> = Vec::new();
    for stem in [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ] {
        reserved_paths.push(format!(r"C:\tmp\{stem}"));
    }
    // Mixed-case, extensions, UNC, and Unicode superscripts (28+ inputs total)
    for extra in [
        r"C:\tmp\nul.txt",
        r"C:\tmp\Com9.log",
        r"\\nas\share\aux.dat",
        "C:\\tmp\\COM\u{00B9}",
        "C:\\tmp\\COM\u{00B2}",
        "C:\\tmp\\COM\u{00B3}",
        "C:\\tmp\\LPT\u{00B9}",
        "C:\\tmp\\LPT\u{00B2}",
        "C:\\tmp\\LPT\u{00B3}",
    ] {
        reserved_paths.push(extra.to_owned());
    }
    assert!(reserved_paths.len() >= 28);

    for p in &reserved_paths {
        let res = validate_paths_ffi(&[p.as_str()])?;
        let _ = assert_error_envelope(
            &res,
            Some("device_namespace_forbidden"),
            Some("errorStorage"),
        )?;
    }
    Ok(())
}

#[test]
fn t2_f21_03_device_namespaces_ads_trailing_and_relative_paths() -> TestResult {
    let cases = [
        (r"\\.\PhysicalDrive0", "device_namespace_forbidden"),
        (
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\x",
            "device_namespace_forbidden",
        ),
        (
            r"\\?\Volume{11111111-2222-3333-4444-555555555555}\a",
            "device_namespace_forbidden",
        ),
        (
            r"C:\tmp\report.pdf:Zone.Identifier",
            "forbidden_segment_character",
        ),
        (r"C:\tmp\a<b", "forbidden_segment_character"),
        (r"C:\tmp\file.", "trailing_dot_or_space"),
        (r"C:\tmp\dir \a.txt", "trailing_dot_or_space"),
        (r"relative\a.txt", "not_absolute_windows_path"),
        (r"C:drive-relative.txt", "not_absolute_windows_path"),
    ];
    for (bad, expected_kind) in cases {
        let res = validate_paths_ffi(&[bad])?;
        let _ = assert_error_envelope(&res, Some(expected_kind), Some("errorStorage"))?;
    }
    Ok(())
}

#[test]
fn t3_08_explorer_planning_and_router_ingest_across_thresholds() -> TestResult {
    let exe = r"C:\App\totaldrop-winui.exe";
    let router = RouterGuard::create(13, "en-US", "en-US", "0.1.0-beta.1", true)?;

    // 5 files cold -> DirectCommandLine (no cmd.exe)
    let files_5: Vec<String> = (0..5)
        .map(|i| format!(r"C:\Users\Alice\doc_{i}.txt"))
        .collect();
    let env_5 = ActivationEnvelope::explorer_send(files_5, None)?;
    match plan_explorer_invocation(exe, &env_5, 1, false)? {
        ExplorerLaunchTransport::DirectCommandLine { command_line, .. } => {
            assert!(!command_line.to_ascii_lowercase().contains("cmd.exe"));
        }
        other => {
            return Err(format!("expected DirectCommandLine for 5 files, got {other:?}").into());
        }
    }

    // 500 files (> 30_000 UTF-16) cold -> NamedPipeIpc (--ipc-await) + ingests cleanly
    let files_500: Vec<String> = (0..500)
        .map(|i| format!(r"C:\Users\Alice\Documents\ProjectArchive2026\SubFolder\item_{i:04}.bin"))
        .collect();
    let env_500 = ActivationEnvelope::explorer_send(files_500, None)?;
    let frame_500 = match plan_explorer_invocation(exe, &env_500, 1, false)? {
        ExplorerLaunchTransport::NamedPipeIpc {
            cold_start_command_line,
            ipc_frame,
            ..
        } => {
            assert!(cold_start_command_line.contains("--ipc-await"));
            ipc_frame
        }
        other => return Err(format!("expected NamedPipeIpc for 500 files, got {other:?}").into()),
    };
    let out_500 = router_ingest(router.id(), &frame_500)?;
    assert_eq!(
        out_500
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.get("paths"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(500)
    );

    // 10_000 files (exact cap) -> NamedPipeIpc + ingests cleanly (short paths fit << 4 MiB)
    let files_10k: Vec<String> = (0..MAX_SELECTION_ITEMS)
        .map(|i| format!(r"C:\t\f{i:04}.txt"))
        .collect();
    let env_10k = ActivationEnvelope::explorer_send(files_10k, None)?;
    let frame_10k = match plan_explorer_invocation(exe, &env_10k, 1, false)? {
        ExplorerLaunchTransport::NamedPipeIpc { ipc_frame, .. } => ipc_frame,
        other => return Err(format!("expected NamedPipeIpc for 10k files, got {other:?}").into()),
    };
    assert!(frame_10k.len() <= MAX_IPC_FRAME_BYTES);
    let out_10k = router_ingest(router.id(), &frame_10k)?;
    assert_eq!(
        out_10k
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.get("paths"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(MAX_SELECTION_ITEMS)
    );

    // 10_001 files -> rejected with TooManyItems { count: 10001 }
    let files_10001: Vec<String> = (0..MAX_SELECTION_ITEMS.saturating_add(1))
        .map(|i| format!(r"C:\t\f{i:05}.txt"))
        .collect();
    assert!(ActivationEnvelope::explorer_send(&files_10001, None).is_err());
    let raw_10001 = json!({
        "version": 1,
        "payload": {
            "kind": "explorer_send",
            "paths": files_10001
        }
    })
    .to_string();
    let f_10001 = frame_bytes(raw_10001.as_bytes())?;
    let res_10001 = router_ingest(router.id(), &f_10001)?;
    let msg_10001 =
        assert_error_envelope(&res_10001, Some("too_many_items"), Some("errorStorage"))?;
    assert!(msg_10001.contains("10001"), "{msg_10001}");
    Ok(())
}

#[test]
fn t3_11_router_busy_and_idle_malformed_protocol_uri() -> TestResult {
    let router = RouterGuard::create(14, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let uri_frame = ActivationEnvelope::protocol_uri("totaldrop://r/7-harbor-rocket", None)?
        .encode_ipc_frame()?;

    let link_busy = {
        let v = format_message_ffi("linkBusy", "en-US", "en-US")?;
        assert_direct_dto_ok(&v)?;
        v.get("formatted")
            .and_then(Value::as_str)
            .ok_or("missing linkBusy")?
            .to_owned()
    };

    for busy in [
        r#"{"state":"showing_text_note"}"#,
        r#"{"state":"offer_prompt_pending"}"#,
    ] {
        let _ = router_set_activity(router.id(), busy)?;
        let out = router_ingest(router.id(), &uri_frame)?;
        let dec = out
            .as_array()
            .and_then(|a| a.first())
            .ok_or("missing dec")?;
        assert_eq!(
            dec.get("decision").and_then(Value::as_str),
            Some("reject_busy")
        );
        assert_eq!(
            dec.get("localized_banner").and_then(Value::as_str),
            Some(link_busy.as_str())
        );
    }

    // Idle state + malformed URIs rejected cleanly with zero router corruption
    let _ = router_set_activity(router.id(), r#"{"state":"idle"}"#)?;
    for bad_uri in [
        "totaldrop://r/%2537-harbor-rocket",
        "https://evil.example/r#7-harbor-rocket",
    ] {
        let res = validate_uri(bad_uri)?;
        let _ = assert_error_envelope(
            &res,
            Some("invalid_activation_link"),
            Some("errorInvalidCode"),
        )?;
    }

    // Router still routes valid protocol URI cleanly while Idle
    let ok = router_ingest(router.id(), &uri_frame)?;
    assert_eq!(
        ok.as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.get("decision"))
            .and_then(Value::as_str),
        Some("navigate_receive_code")
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Architecture B Loopback Rendezvous & Controllable Relay (for T1-F20-03,
// T2-F20-02, T2-F20-03, and T3-07)

struct MailboxSlot {
    token: [u8; 16],
    mailbox_id: [u8; 16],
    peers: Vec<mpsc::UnboundedSender<ServerMessage>>,
    buffered_for_second: Vec<ServerMessage>,
}

struct RendezvousState {
    next_nameplate: AtomicU32,
    boxes: Mutex<HashMap<u32, MailboxSlot>>,
}

struct MockRendezvous {
    url: String,
    abort: tokio::task::AbortHandle,
}

impl Drop for MockRendezvous {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl MockRendezvous {
    fn start() -> Result<Self, Box<dyn StdError>> {
        let (url, abort) = TEST_RUNTIME.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let local: SocketAddr = listener.local_addr()?;
            let url = format!("ws://{local}");
            let state = Arc::new(RendezvousState {
                next_nameplate: AtomicU32::new(7),
                boxes: Mutex::new(HashMap::new()),
            });
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let _ = stream.set_nodelay(true);
                    let st = Arc::clone(&state);
                    tokio::spawn(async move {
                        let _ = handle_rdv_conn(stream, st).await;
                    });
                }
            });
            Ok::<_, std::io::Error>((url, task.abort_handle()))
        })?;
        Ok(Self { url, abort })
    }
}

async fn handle_rdv_conn(
    stream: tokio::net::TcpStream,
    state: Arc<RendezvousState>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let mut ws = tokio_tungstenite::accept_async(stream).await?;
    let first = match ws.next().await {
        Some(Ok(Message::Binary(b))) => ClientMessage::decode(&b)?,
        _ => return Ok(()),
    };
    match first {
        ClientMessage::Allocate => {
            let nameplate = state.next_nameplate.fetch_add(1, Ordering::Relaxed);
            let mut token = [0u8; 16];
            let mut mailbox_id = [0u8; 16];
            let np = nameplate.to_le_bytes();
            for i in 0..16 {
                if let (Some(t), Some(m), Some(&b)) =
                    (token.get_mut(i), mailbox_id.get_mut(i), np.get(i % 4))
                {
                    *t = b ^ 0xA5;
                    *m = b ^ 0x3C;
                }
            }
            {
                let mut boxes = state.boxes.lock().await;
                boxes.insert(
                    nameplate,
                    MailboxSlot {
                        token,
                        mailbox_id,
                        peers: Vec::new(),
                        buffered_for_second: Vec::new(),
                    },
                );
            }
            let reply = ServerMessage::Allocated { nameplate, token };
            ws.send(Message::Binary(reply.encode().into())).await?;
        }
        ClientMessage::Claim { nameplate, token } => {
            let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
            let (mailbox_id, peer_index, replay) = {
                let mut boxes = state.boxes.lock().await;
                let Some(slot) = boxes.get_mut(&nameplate) else {
                    let _ = ws
                        .send(Message::Binary(
                            ServerMessage::Error {
                                reason: "unknown nameplate".to_owned(),
                            }
                            .encode()
                            .into(),
                        ))
                        .await;
                    return Ok(());
                };
                if let Some(tok) = token
                    && tok != slot.token
                {
                    let _ = ws
                        .send(Message::Binary(
                            ServerMessage::Error {
                                reason: "bad token".to_owned(),
                            }
                            .encode()
                            .into(),
                        ))
                        .await;
                    return Ok(());
                }
                let peer_index = slot.peers.len();
                slot.peers.push(tx);
                let replay = if peer_index == 1 {
                    std::mem::take(&mut slot.buffered_for_second)
                } else {
                    Vec::new()
                };
                (slot.mailbox_id, peer_index, replay)
            };

            ws.send(Message::Binary(
                ServerMessage::Claimed {
                    mailbox: mailbox_id,
                }
                .encode()
                .into(),
            ))
            .await?;
            for msg in replay {
                ws.send(Message::Binary(msg.encode().into())).await?;
            }

            loop {
                tokio::select! {
                    outgoing = rx.recv() => {
                        let Some(msg) = outgoing else { break; };
                        if ws.send(Message::Binary(msg.encode().into())).await.is_err() {
                            break;
                        }
                    }
                    incoming = ws.next() => {
                        match incoming {
                            Some(Ok(Message::Binary(b))) => {
                                let Ok(cmd) = ClientMessage::decode(&b) else { break; };
                                match cmd {
                                    ClientMessage::Add { phase, body } => {
                                        let forwarded = ServerMessage::Message { phase, body };
                                        let mut boxes = state.boxes.lock().await;
                                        if let Some(slot) = boxes.get_mut(&nameplate) {
                                            let other_idx = 1usize.saturating_sub(peer_index);
                                            if let Some(other) = slot.peers.get(other_idx) {
                                                let _ = other.send(forwarded);
                                            } else if peer_index == 0 {
                                                slot.buffered_for_second.push(forwarded);
                                            }
                                        }
                                    }
                                    ClientMessage::Close { mood } => {
                                        let mut boxes = state.boxes.lock().await;
                                        if let Some(slot) = boxes.get_mut(&nameplate) {
                                            let other_idx = 1usize.saturating_sub(peer_index);
                                            if let Some(other) = slot.peers.get(other_idx) {
                                                let _ = other.send(ServerMessage::PeerClosed { mood });
                                            }
                                        }
                                        let _ = ws.close(None).await;
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            Some(Ok(Message::Ping(p))) => {
                                let _ = ws.send(Message::Pong(p)).await;
                            }
                            Some(Ok(Message::Close(_))) | None => break,
                            _ => {}
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RelayMode {
    Normal,
    /// Delays only large bulk datagrams (> 512 B) so small QUIC ACKs,
    /// `Control::Cancel`, and `CONNECTION_CLOSE` packets flush immediately.
    ThrottledBulkOnly(Duration),
}

#[derive(Clone)]
struct PeerTx {
    ctrl: mpsc::UnboundedSender<Vec<u8>>,
    bulk: mpsc::Sender<Vec<u8>>,
}

type RelayPeerMap = HashMap<[u8; 32], PeerTx>;
type RelayPairTable = HashMap<([u8; 32], [u8; 32]), RelayPeerMap>;
type RelayPendingTable = HashMap<(([u8; 32], [u8; 32]), [u8; 32]), Vec<Vec<u8>>>;

struct RelayState {
    mode: RelayMode,
    freeze_forwarding: Arc<AtomicBool>,
    eof_count: Arc<AtomicU32>,
    pairs: Mutex<RelayPairTable>,
    pending: Mutex<RelayPendingTable>,
}

struct MockRelay {
    url: String,
    freeze_forwarding: Arc<AtomicBool>,
    eof_count: Arc<AtomicU32>,
    abort: tokio::task::AbortHandle,
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl MockRelay {
    fn start(mode: RelayMode) -> Result<Self, Box<dyn StdError>> {
        let freeze_forwarding = Arc::new(AtomicBool::new(false));
        let eof_count = Arc::new(AtomicU32::new(0));
        let ff_clone = Arc::clone(&freeze_forwarding);
        let eof_clone = Arc::clone(&eof_count);

        let (url, abort) = TEST_RUNTIME.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let local = listener.local_addr()?;
            let url = format!("ws://{local}/v0/relay");
            let state = Arc::new(RelayState {
                mode,
                freeze_forwarding: ff_clone,
                eof_count: eof_clone,
                pairs: Mutex::new(HashMap::new()),
                pending: Mutex::new(HashMap::new()),
            });
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let _ = stream.set_nodelay(true);
                    let st = Arc::clone(&state);
                    tokio::spawn(async move {
                        let _ = handle_relay_conn(stream, st).await;
                    });
                }
            });
            Ok::<_, std::io::Error>((url, task.abort_handle()))
        })?;
        Ok(Self {
            url,
            freeze_forwarding,
            eof_count,
            abort,
        })
    }
}

#[allow(clippy::result_large_err)]
async fn handle_relay_conn(
    stream: tokio::net::TcpStream,
    state: Arc<RelayState>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let mut captured_path = String::new();
    let mut ws = tokio_tungstenite::accept_hdr_async(stream, |req: &Request, resp: Response| {
        captured_path = req.uri().path().to_owned();
        Ok(resp)
    })
    .await?;

    let Some(pair_segment) = captured_path.rsplit('/').next() else {
        return Ok(());
    };
    let Some(pair) = proto_relay::parse_pair_name(pair_segment) else {
        return Ok(());
    };

    let nonce = [0x5Au8; 32];
    ws.send(Message::Binary(proto_relay::challenge(&nonce).into()))
        .await?;

    let hello_bytes = match ws.next().await {
        Some(Ok(Message::Binary(b))) => b,
        _ => return Ok(()),
    };
    let Some((key, sig)) = proto_relay::parse_hello(&hello_bytes) else {
        return Ok(());
    };
    if key != pair.0 && key != pair.1 {
        return Ok(());
    }
    let signed = proto_relay::signed_bytes(&nonce);
    if UnparsedPublicKey::new(&ED25519, &key)
        .verify(&signed, &sig)
        .is_err()
    {
        return Ok(());
    }

    ws.send(Message::Binary(proto_relay::ok().into())).await?;

    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let bulk_cap = match state.mode {
        RelayMode::Normal => 2048,
        RelayMode::ThrottledBulkOnly(_) => 16,
    };
    let (bulk_tx, mut bulk_rx) = mpsc::channel::<Vec<u8>>(bulk_cap);
    {
        let mut pairs = state.pairs.lock().await;
        pairs.entry(pair).or_default().insert(
            key,
            PeerTx {
                ctrl: ctrl_tx.clone(),
                bulk: bulk_tx,
            },
        );
    }
    // Flush any QUIC Initial datagrams sent by the peer before this side finished auth.
    let queued_initial = {
        let mut pend = state.pending.lock().await;
        pend.remove(&(pair, key)).unwrap_or_default()
    };
    for frame in queued_initial {
        let _ = ctrl_tx.send(frame);
    }

    let (mut ws_tx, mut ws_rx) = ws.split();
    let write_state = Arc::clone(&state);
    let writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                outbound_ctrl = ctrl_rx.recv() => {
                    let Some(frame) = outbound_ctrl else { break; };
                    if write_state.freeze_forwarding.load(Ordering::SeqCst) {
                        continue;
                    }
                    if ws_tx.send(Message::Binary(frame.into())).await.is_err() {
                        break;
                    }
                }
                outbound_bulk = bulk_rx.recv() => {
                    let Some(frame) = outbound_bulk else { break; };
                    if write_state.freeze_forwarding.load(Ordering::SeqCst) {
                        continue;
                    }
                    if let RelayMode::ThrottledBulkOnly(delay) = write_state.mode {
                        tokio::time::sleep(delay).await;
                    }
                    if ws_tx.send(Message::Binary(frame.into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    while let Some(inbound) = ws_rx.next().await {
        match inbound {
            Ok(Message::Binary(b)) => {
                if state.freeze_forwarding.load(Ordering::SeqCst) {
                    continue;
                }
                if proto_relay::is_probe(&b) || b.len() < 35 {
                    continue;
                }
                let Some((dst_slice, rest)) = b.split_at_checked(32) else {
                    continue;
                };
                let Ok(dst): Result<[u8; 32], _> = dst_slice.try_into() else {
                    continue;
                };
                let mut delivered = Vec::with_capacity(b.len());
                delivered.extend_from_slice(&key);
                delivered.extend_from_slice(rest);
                let peer_tx_opt = {
                    let pairs = state.pairs.lock().await;
                    pairs.get(&pair).and_then(|m| m.get(&dst)).cloned()
                };
                if let Some(peer_tx) = peer_tx_opt {
                    if delivered.len() <= 512 {
                        let _ = peer_tx.ctrl.send(delivered);
                    } else {
                        let _ = peer_tx.bulk.send(delivered).await;
                    }
                } else {
                    let mut pend = state.pending.lock().await;
                    let slot = pend.entry((pair, dst)).or_default();
                    if slot.len() < 16 {
                        slot.push(delivered);
                    }
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    writer.abort();
    state.eof_count.fetch_add(1, Ordering::SeqCst);
    let mut pairs = state.pairs.lock().await;
    if let Some(map) = pairs.get_mut(&pair) {
        map.remove(&key);
    }
    Ok(())
}

/// Cooperative relay-only remote sender for `T1-F20-03`: sends `DataHeader` +
/// chunk 0 of a `4 MiB` file (triggering receiver `progress` + `.totaldrop-*.part`),
/// then paces subsequent chunks while concurrently reading `Control::Cancel` so
/// cooperative shutdown completes deterministically in `< 100 ms`.
async fn run_paced_cooperative_relay_sender(
    rendezvous_url: String,
    relay_url: String,
    code_tx: oneshot::Sender<String>,
) -> Result<String, Box<dyn StdError + Send + Sync>> {
    let keys = DeviceKeys::generate()?;
    let alloc = rendezvous::allocate(&rendezvous_url).await?;
    let code = TransferCode::generate(alloc.nameplate, 2)?;
    let mailbox =
        rendezvous::Mailbox::claim(&rendezvous_url, alloc.nameplate, Some(&alloc)).await?;
    let mailbox_id = mailbox.id;
    let _ = code_tx.send(code.to_english());

    let socket = transport::bind_socket()?;
    let endpoint_key = Arc::new(transport::EndpointKey::generate()?);
    let hints = Hints {
        versions: pairing::VERSIONS.to_vec(),
        endpoint_key: endpoint_key.public(),
        public: Vec::new(),
        local: Vec::new(),
        relay: Some(relay_url.clone()),
    };
    let paired =
        pairing::exchange(mailbox, Role::Initiator, &code, mailbox_id, &keys, &hints).await?;
    let (endpoint, pipes, _fallback) =
        transport::endpoint(socket, &endpoint_key, &paired.hints.endpoint_key)?;
    let gate = core_relay::Gate::default();
    let _link = core_relay::spawn(
        relay_url,
        Arc::clone(&endpoint_key),
        paired.hints.endpoint_key,
        pipes,
        gate.clone(),
    );
    let paths = transport::Paths {
        direct: Vec::new(),
        relay: Some(gate),
        relay_only: true,
    };
    let (conn, send, recv) =
        transport::sender_connection(&endpoint, &paths, Duration::from_secs(15)).await?;
    let mut chan = secure::handshake_on(
        send,
        recv,
        secure::HandshakeInput {
            keys: &keys,
            peer: &paired.peer,
            psk: paired.psk,
            mailbox_id: paired.mailbox_id,
        },
        false,
    )
    .await?;

    let transfer_id = totaldrop_crypto::new_transfer_id()?;
    let ck = ContentKey::generate()?;
    let payload_len = 4_194_304usize;
    let payload = pseudo_random_bytes(0xF2003, payload_len);
    let hash = *blake3::hash(&payload).as_bytes();
    let entry = Entry {
        path: vec!["payload_4m.bin".to_owned()],
        kind: EntryKind::File,
        size: u64::try_from(payload_len).unwrap_or(0),
        hash: Some(hash),
        mtime: None,
    };
    let manifest = Manifest {
        transfer_id,
        entries: vec![entry],
        total_size: u64::try_from(payload_len).unwrap_or(0),
        chunk_size: limits::CHUNK_SIZE,
    };
    let signature = keys.sign(&manifest.signed_bytes());
    let offer = Control::Offer {
        manifest,
        content_key: *ck.as_bytes(),
        signature,
        progress: true,
        text: false,
    };
    secure::send_control(&mut chan.sealer, &mut chan.send, &offer).await?;

    let reply = secure::recv_control(&mut chan.opener, &mut chan.recv).await?;
    if !matches!(reply, Control::Accept { .. }) {
        return Ok("declined".to_owned());
    }

    // Spawn dedicated control reader BEFORE sending chunk 0 so `Control::Cancel`
    // is decoded immediately with STOP_SENDING + CONNECTION_CLOSE at any instant.
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<Result<Control, String>>();
    let mut opener = chan.opener;
    let mut ctl_recv = chan.recv;
    let conn_for_ctl = conn.clone();
    let ctl_task = tokio::spawn(async move {
        loop {
            match secure::recv_control(&mut opener, &mut ctl_recv).await {
                Ok(Control::Cancel {
                    transfer_id: tid,
                    reason,
                }) => {
                    let _ = ctl_recv.stop(0u32.into());
                    conn_for_ctl.close(0u32.into(), b"peer_cancelled");
                    let _ = ctl_tx.send(Ok(Control::Cancel {
                        transfer_id: tid,
                        reason,
                    }));
                    break;
                }
                Ok(msg) => {
                    if ctl_tx.send(Ok(msg)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = ctl_tx.send(Err(e.to_string()));
                    break;
                }
            }
        }
    });

    let mut data_stream = conn.open_uni().await?;
    let dh = DataHeader {
        transfer_id,
        entry: 0,
        first_chunk: 0,
    };
    write_frame(&mut data_stream, &dh.encode()).await?;
    let cipher = EntryCipher::new(&ck, &transfer_id, 0);
    let chunk0 = payload.get(..1_048_576).unwrap_or(&payload);
    let ct0 = cipher.seal(0, false, chunk0)?;
    // Pace chunk 0 in 32 KiB slices (2 ms apart) so `PathSocket::to_relay` (bounded UDP queue)
    // never drops datagrams or triggers a 1s+ QUIC PTO retransmit on the control stream.
    let len0 = totaldrop_proto::wire::encode_length(ct0.len());
    data_stream.write_all(&len0).await?;
    for slice in ct0.chunks(32_768) {
        data_stream.write_all(slice).await?;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // Wait cooperatively for `Control::Cancel` while keeping the stream open mid-transfer.
    let outcome = loop {
        tokio::select! {
            biased;
            ctrl = ctl_rx.recv() => {
                match ctrl {
                    Some(Ok(Control::Cancel { reason, .. })) => {
                        // Keep `_link` alive briefly so Quinn pumps `STOP_SENDING` +
                        // `CONNECTION_CLOSE` through the relay back to the receiver.
                        tokio::time::sleep(Duration::from_millis(150)).await;
                        break format!("cancelled:{reason}");
                    }
                    Some(Ok(Control::Received { .. })) => {}
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break "eof".to_owned(),
                }
            }
            () = tokio::time::sleep(Duration::from_secs(15)) => {
                break "timeout".to_owned();
            }
        }
    };
    ctl_task.abort();
    Ok(outcome)
}

/// Fault-injecting relay-only sender that sends `DataHeader` + chunk 0 of a
/// `2 MiB` file (triggering `.totaldrop-*.part` creation and receiver `progress`)
/// and then goes completely silent.
async fn run_silent_stalled_relay_sender(
    rendezvous_url: String,
    relay_url: String,
    code_tx: oneshot::Sender<String>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let keys = DeviceKeys::generate()?;
    let alloc = rendezvous::allocate(&rendezvous_url).await?;
    let code = TransferCode::generate(alloc.nameplate, 2)?;
    let mailbox =
        rendezvous::Mailbox::claim(&rendezvous_url, alloc.nameplate, Some(&alloc)).await?;
    let mailbox_id = mailbox.id;
    let _ = code_tx.send(code.to_english());

    let socket = transport::bind_socket()?;
    let endpoint_key = Arc::new(transport::EndpointKey::generate()?);
    let hints = Hints {
        versions: pairing::VERSIONS.to_vec(),
        endpoint_key: endpoint_key.public(),
        public: Vec::new(),
        local: Vec::new(),
        relay: Some(relay_url.clone()),
    };
    let paired =
        pairing::exchange(mailbox, Role::Initiator, &code, mailbox_id, &keys, &hints).await?;
    let (endpoint, pipes, _fallback) =
        transport::endpoint(socket, &endpoint_key, &paired.hints.endpoint_key)?;
    let gate = core_relay::Gate::default();
    let _link = core_relay::spawn(
        relay_url,
        Arc::clone(&endpoint_key),
        paired.hints.endpoint_key,
        pipes,
        gate.clone(),
    );
    let paths = transport::Paths {
        direct: Vec::new(),
        relay: Some(gate),
        relay_only: true,
    };
    let (conn, send, recv) =
        transport::sender_connection(&endpoint, &paths, Duration::from_secs(15)).await?;
    let mut chan = secure::handshake_on(
        send,
        recv,
        secure::HandshakeInput {
            keys: &keys,
            peer: &paired.peer,
            psk: paired.psk,
            mailbox_id: paired.mailbox_id,
        },
        false,
    )
    .await?;

    let transfer_id = totaldrop_crypto::new_transfer_id()?;
    let ck = ContentKey::generate()?;
    let payload_len = 2_097_152usize;
    let payload = vec![0x55u8; payload_len];
    let hash = *blake3::hash(&payload).as_bytes();
    let entry = Entry {
        path: vec!["stalled.bin".to_owned()],
        kind: EntryKind::File,
        size: u64::try_from(payload_len).unwrap_or(0),
        hash: Some(hash),
        mtime: None,
    };
    let manifest = Manifest {
        transfer_id,
        entries: vec![entry],
        total_size: u64::try_from(payload_len).unwrap_or(0),
        chunk_size: limits::CHUNK_SIZE,
    };
    let signature = keys.sign(&manifest.signed_bytes());
    let offer = Control::Offer {
        manifest,
        content_key: *ck.as_bytes(),
        signature,
        progress: true,
        text: false,
    };
    secure::send_control(&mut chan.sealer, &mut chan.send, &offer).await?;

    // Wait for receiver Control::Accept
    let reply = secure::recv_control(&mut chan.opener, &mut chan.recv).await?;
    if !matches!(reply, Control::Accept { .. }) {
        return Ok(());
    }

    // Open data stream, write DataHeader + encrypted chunk 0 (1 MiB) so receiver creates
    // `.totaldrop-*.part` on disk and emits a `progress` event, then stall silently!
    let mut data_stream = conn.open_uni().await?;
    let dh = DataHeader {
        transfer_id,
        entry: 0,
        first_chunk: 0,
    };
    write_frame(&mut data_stream, &dh.encode()).await?;
    let cipher = EntryCipher::new(&ck, &transfer_id, 0);
    let chunk0 = payload.get(..1_048_576).unwrap_or(&payload);
    let ct0 = cipher.seal(0, false, chunk0)?;
    write_frame(&mut data_stream, &ct0).await?;

    tokio::time::sleep(Duration::from_secs(30)).await;
    Ok(())
}

fn make_relay_only_cfg(rdv_url: &str, relay_url: &str) -> String {
    json!({
        "rendezvous_server": rdv_url,
        "relay_server": relay_url,
        "stun_server": "",
        "privacy_relay_only": true,
        "stronger_three_word_code": false
    })
    .to_string()
}

fn poll_session_events(sid: u64) -> Result<Vec<Value>, Box<dyn StdError>> {
    let raw = take_raw_string(totaldrop_win_session_poll_events_ndjson(sid))?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            out.push(serde_json::from_str(trimmed)?);
        }
    }
    Ok(out)
}

fn wait_for_session_event(
    sid: u64,
    all: &mut Vec<Value>,
    target: &str,
    timeout: Duration,
) -> Result<Value, Box<dyn StdError>> {
    let started = Instant::now();
    loop {
        if let Some(ev) = all
            .iter()
            .find(|e| e.get("event").and_then(Value::as_str) == Some(target))
        {
            return Ok(ev.clone());
        }
        if target != "failed"
            && let Some(failed) = all
                .iter()
                .find(|e| e.get("event").and_then(Value::as_str) == Some("failed"))
        {
            return Err(format!("unexpected failed event waiting for {target:?}: {failed}").into());
        }
        all.extend(poll_session_events(sid)?);
        if started.elapsed() >= timeout {
            return Err(format!("timed out waiting for {target:?}; saw: {all:?}").into());
        }
        std::thread::sleep(Duration::from_millis(12));
    }
}

fn start_send_files(cfg_json: &str, paths: &[&Path]) -> Result<SessionGuard, Box<dyn StdError>> {
    let cfg_c = c_str(cfg_json)?;
    let path_strings: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let paths_json = serde_json::to_string(&path_strings)?;
    let paths_c = c_str(&paths_json)?;
    let lang_c = c_str("en-US")?;
    let reg_c = c_str("en-US")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let sid = unsafe {
        totaldrop_win_send_files_start(
            cfg_c.as_ptr(),
            paths_c.as_ptr(),
            lang_c.as_ptr(),
            reg_c.as_ptr(),
        )
    };
    if sid == 0 {
        return Err("totaldrop_win_send_files_start returned 0".into());
    }
    Ok(SessionGuard(sid))
}

fn start_send_text(cfg_json: &str, text: &str) -> Result<SessionGuard, Box<dyn StdError>> {
    let cfg_c = c_str(cfg_json)?;
    let text_c = c_str(text)?;
    let lang_c = c_str("en-US")?;
    let reg_c = c_str("en-US")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let sid = unsafe {
        totaldrop_win_send_text_start(
            cfg_c.as_ptr(),
            text_c.as_ptr(),
            lang_c.as_ptr(),
            reg_c.as_ptr(),
        )
    };
    if sid == 0 {
        return Err("totaldrop_win_send_text_start returned 0".into());
    }
    Ok(SessionGuard(sid))
}

fn start_receive_connect(cfg_json: &str, code: &str) -> Result<SessionGuard, Box<dyn StdError>> {
    let cfg_c = c_str(cfg_json)?;
    let code_c = c_str(code)?;
    let lang_c = c_str("en-US")?;
    let reg_c = c_str("en-US")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let sid = unsafe {
        totaldrop_win_receive_connect_start(
            cfg_c.as_ptr(),
            code_c.as_ptr(),
            lang_c.as_ptr(),
            reg_c.as_ptr(),
        )
    };
    if sid == 0 {
        return Err("totaldrop_win_receive_connect_start returned 0".into());
    }
    Ok(SessionGuard(sid))
}

fn accept_files(sid: u64, dest: &Path) -> Result<i32, Box<dyn StdError>> {
    let dest_c = c_str(&dest.to_string_lossy())?;
    // SAFETY: `dest_c` is a live NUL-terminated CString.
    Ok(unsafe { totaldrop_win_receive_accept_files(sid, dest_c.as_ptr()) })
}

// ---------------------------------------------------------------------------
// Live Loopback Shutdown & Busy-Transfer Tests (T1-F20-03, T2-F20-02, T2-F20-03, T3-07)

#[test]
fn t1_f20_03_cooperative_shutdown_under_800ms() -> TestResult {
    let _write_lock = SHUTDOWN_GATE
        .write()
        .map_err(|_| "SHUTDOWN_GATE poisoned")?;

    let rdv = MockRendezvous::start()?;
    let relay = MockRelay::start(RelayMode::Normal)?;
    let tmp = TempDirGuard::new("t1-f20-03")?;
    let dest = tmp.path().join("recv");
    std::fs::create_dir_all(&dest)?;

    // Run an independent paced cooperative remote sender on TEST_RUNTIME so
    // `totaldrop_win_shutdown(1500)` cancels ONLY the Windows FFI receiver while
    // the remote peer decodes `Control::Cancel` and closes cooperatively.
    let (code_tx, code_rx) = oneshot::channel::<String>();
    let (peer_res_tx, peer_res_rx) = oneshot::channel::<String>();
    let rdv_url = rdv.url.clone();
    let relay_url = relay.url.clone();
    let peer_task = TEST_RUNTIME.spawn(async move {
        let outcome = match run_paced_cooperative_relay_sender(rdv_url, relay_url, code_tx).await {
            Ok(s) => s,
            Err(e) => format!("err:{e}"),
        };
        let _ = peer_res_tx.send(outcome);
    });
    let code = TEST_RUNTIME
        .block_on(async { tokio::time::timeout(Duration::from_secs(15), code_rx).await })??;

    // privacy_relay_only: true avoids non-deterministic UPnP portmap SSDP timeout on Linux devbox.
    let cfg = make_relay_only_cfg(&rdv.url, &relay.url);
    let receiver = start_receive_connect(&cfg, &code)?;
    let mut r_evs = Vec::new();
    let _ = wait_for_session_event(
        receiver.id(),
        &mut r_evs,
        "offer_ready",
        Duration::from_secs(15),
    )?;
    assert_eq!(accept_files(receiver.id(), &dest)?, FFI_OK);
    let _ = wait_for_session_event(
        receiver.id(),
        &mut r_evs,
        "progress",
        Duration::from_secs(15),
    )?;

    let started = Instant::now();
    let rc = totaldrop_win_shutdown(1500);
    let elapsed = started.elapsed();

    // Remote peer must observe cooperative Control::Cancel / EOF promptly
    let peer_outcome = TEST_RUNTIME
        .block_on(async { tokio::time::timeout(Duration::from_secs(3), peer_res_rx).await })??;

    assert_eq!(rc, FFI_OK);
    assert!(
        elapsed < Duration::from_millis(800),
        "cooperative shutdown exceeded 800 ms bound: {elapsed:?} (peer={peer_outcome:?})"
    );
    assert!(
        peer_outcome.starts_with("cancelled:")
            || peer_outcome == "eof"
            || peer_outcome == "stream_reset",
        "expected remote peer to observe cooperative cancellation/EOF, got {peer_outcome:?}"
    );
    peer_task.abort();

    assert!(
        !has_part_files(&dest)?,
        "leftover .totaldrop-*.part files remained after cooperative shutdown"
    );

    // Subsequent polls must report invalid_handle (zero active sessions)
    let post_poll = take_json(totaldrop_win_session_poll_events_ndjson(receiver.id()))?;
    let _ = assert_error_envelope(&post_poll, Some("invalid_handle"), Some("errorOther"))?;
    Ok(())
}

#[test]
fn t2_f20_02_silent_stalled_peer_forced_50ms_shutdown() -> TestResult {
    let _write_lock = SHUTDOWN_GATE
        .write()
        .map_err(|_| "SHUTDOWN_GATE poisoned")?;

    let rdv = MockRendezvous::start()?;
    let relay = MockRelay::start(RelayMode::Normal)?;
    let tmp = TempDirGuard::new("t2-f20-02")?;
    let dest = tmp.path().join("recv");
    std::fs::create_dir_all(&dest)?;

    let (code_tx, code_rx) = oneshot::channel::<String>();
    let rdv_url = rdv.url.clone();
    let relay_url = relay.url.clone();
    let sender_task = TEST_RUNTIME.spawn(async move {
        let _ = run_silent_stalled_relay_sender(rdv_url, relay_url, code_tx).await;
    });
    let code = TEST_RUNTIME
        .block_on(async { tokio::time::timeout(Duration::from_secs(15), code_rx).await })??;

    let cfg = make_relay_only_cfg(&rdv.url, &relay.url);
    let receiver = start_receive_connect(&cfg, &code)?;
    let mut r_evs = Vec::new();
    let _ = wait_for_session_event(
        receiver.id(),
        &mut r_evs,
        "offer_ready",
        Duration::from_secs(15),
    )?;
    assert_eq!(accept_files(receiver.id(), &dest)?, FFI_OK);
    let _ = wait_for_session_event(
        receiver.id(),
        &mut r_evs,
        "progress",
        Duration::from_secs(15),
    )?;

    // Confirm receiver holds an active `.totaldrop-*.part` file on disk
    let wait_part = Instant::now();
    while !has_part_files(&dest)? && wait_part.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        has_part_files(&dest)?,
        "expected active .totaldrop-*.part file before forced shutdown"
    );

    // Freeze relay forwarding while keeping TCP WebSocket open so receiver's `tell_stopped()`
    // blocks past the 50 ms stop budget and hits deterministic hard abort.
    relay.freeze_forwarding.store(true, Ordering::SeqCst);
    let eof_before = relay.eof_count.load(Ordering::SeqCst);

    let started = Instant::now();
    let rc = totaldrop_win_shutdown(50);
    let elapsed = started.elapsed();

    assert_eq!(rc, FFI_OK);
    assert!(
        elapsed >= Duration::from_millis(45) && elapsed <= Duration::from_millis(600),
        "expected 45 ms <= elapsed <= 600 ms for forced 50 ms shutdown, got {elapsed:?}"
    );

    let eof_wait = Instant::now();
    while relay.eof_count.load(Ordering::SeqCst) <= eof_before
        && eof_wait.elapsed() < Duration::from_millis(500)
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        relay.eof_count.load(Ordering::SeqCst) > eof_before,
        "silent loopback peer/relay did not observe TCP EOF/close after forced shutdown"
    );
    assert!(
        !has_part_files(&dest)?,
        "leftover .totaldrop-*.part files remained after forced shutdown"
    );

    let post_poll = take_json(totaldrop_win_session_poll_events_ndjson(receiver.id()))?;
    let _ = assert_error_envelope(&post_poll, Some("invalid_handle"), Some("errorOther"))?;

    sender_task.abort();
    Ok(())
}

#[test]
fn t2_f20_03_idle_and_repeated_shutdown_idempotent_under_50ms() -> TestResult {
    let _write_lock = SHUTDOWN_GATE
        .write()
        .map_err(|_| "SHUTDOWN_GATE poisoned")?;

    // Drain anything prior so runtime starts truly idle
    assert_eq!(totaldrop_win_shutdown(1500), FFI_OK);

    for _ in 0..2 {
        let t0 = Instant::now();
        assert_eq!(totaldrop_win_shutdown(1500), FFI_OK);
        let dt = t0.elapsed();
        assert!(dt < Duration::from_millis(50), "idle shutdown took {dt:?}");
    }

    // Run and cancel a relay-only loopback session, then call shutdown twice more
    let rdv = MockRendezvous::start()?;
    let relay = MockRelay::start(RelayMode::Normal)?;
    let tmp = TempDirGuard::new("t2-f20-03")?;
    let src = tmp.path().join("small.bin");
    std::fs::write(&src, b"hello shutdown")?;
    let cfg = make_relay_only_cfg(&rdv.url, &relay.url);
    let sender = start_send_files(&cfg, &[src.as_path()])?;
    let mut s_evs = Vec::new();
    let _ = wait_for_session_event(sender.id(), &mut s_evs, "waiting", Duration::from_secs(15))?;
    assert_eq!(totaldrop_win_session_cancel(sender.id()), FFI_OK);
    let _ = wait_for_session_event(sender.id(), &mut s_evs, "failed", Duration::from_secs(15))?;
    drop(sender);
    // Ensure cancelled background task finishes unwinding before measuring idle shutdown
    assert_eq!(totaldrop_win_shutdown(1500), FFI_OK);

    for _ in 0..2 {
        let t0 = Instant::now();
        assert_eq!(totaldrop_win_shutdown(1500), FFI_OK);
        let dt = t0.elapsed();
        assert!(
            dt < Duration::from_millis(50),
            "post-completion repeated shutdown took {dt:?}"
        );
    }
    Ok(())
}

#[test]
fn t3_07_busy_router_rejects_explorer_send_while_loopback_transfer_completes() -> TestResult {
    let _read_lock = SHUTDOWN_GATE.read().map_err(|_| "SHUTDOWN_GATE poisoned")?;

    let rdv = MockRendezvous::start()?;
    let relay = MockRelay::start(RelayMode::ThrottledBulkOnly(Duration::from_millis(1)))?;
    let tmp = TempDirGuard::new("t3-07")?;
    let src = tmp.path().join("important.bin");
    let dest = tmp.path().join("recv");
    std::fs::create_dir_all(&dest)?;
    let payload = pseudo_random_bytes(0x307, 512 * 1024);
    let expected_hash = blake3::hash(&payload);
    std::fs::write(&src, &payload)?;

    let cfg = make_relay_only_cfg(&rdv.url, &relay.url);
    let sender = start_send_files(&cfg, &[src.as_path()])?;
    let mut s_evs = Vec::new();
    let code_ev = wait_for_session_event(
        sender.id(),
        &mut s_evs,
        "code_ready",
        Duration::from_secs(15),
    )?;
    let code = code_ev
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing display_english")?
        .to_owned();

    let receiver = start_receive_connect(&cfg, &code)?;
    let mut r_evs = Vec::new();
    let _ = wait_for_session_event(
        receiver.id(),
        &mut r_evs,
        "offer_ready",
        Duration::from_secs(15),
    )?;
    assert_eq!(accept_files(receiver.id(), &dest)?, FFI_OK);
    let _ = wait_for_session_event(
        receiver.id(),
        &mut r_evs,
        "progress",
        Duration::from_secs(15),
    )?;

    // Set router to transferring and ingest explorer_send -> reject_busy (shareBusy)
    let router = RouterGuard::create(307, "en-US", "en-US", "0.1.0-beta.1", true)?;
    let _ = router_set_activity(
        router.id(),
        r#"{"state":"transferring","done_bytes":512,"total_bytes":4096}"#,
    )?;
    let exp_frame = ActivationEnvelope::explorer_send(vec![r"C:\tmp\other.txt".to_owned()], None)?
        .encode_ipc_frame()?;
    let out = router_ingest(router.id(), &exp_frame)?;
    let dec = out
        .as_array()
        .and_then(|a| a.first())
        .ok_or("missing decision")?;
    assert_eq!(
        dec.get("decision").and_then(Value::as_str),
        Some("reject_busy")
    );
    let banner = dec
        .get("localized_banner")
        .and_then(Value::as_str)
        .ok_or("missing localized_banner")?;
    assert!(!banner.is_empty());

    // Active transfer still completes cleanly with 100% matching BLAKE3 hash
    let _ = wait_for_session_event(sender.id(), &mut s_evs, "done", Duration::from_secs(30))?;
    let _ = wait_for_session_event(receiver.id(), &mut r_evs, "done", Duration::from_secs(30))?;
    let recv_bytes = std::fs::read(dest.join("important.bin"))?;
    assert_eq!(blake3::hash(&recv_bytes), expected_hash);
    assert!(!has_part_files(&dest)?);
    Ok(())
}

#[test]
fn tier5_router_400k_duplicate_ipc_frame_and_concurrent_shutdown_race() -> TestResult {
    // 1. C1-F3: 10,001 duplicate paths & 400k-path <4 MiB IPC frame bounded rejection.
    let dups_10001 = vec![r"C:\t\dup.txt".to_owned(); MAX_SELECTION_ITEMS.saturating_add(1)];
    assert!(ActivationEnvelope::explorer_send(&dups_10001, None).is_err());

    let router = RouterGuard::create(501, "en-US", "en-US", "0.1.0-beta.1", true)?;
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
    let big_frame = frame_bytes(big_json.as_bytes())?;
    assert!(big_frame.len() <= MAX_IPC_FRAME_BYTES);

    let t0 = Instant::now();
    let res = router_ingest(router.id(), &big_frame)?;
    let elapsed = t0.elapsed();
    let msg = assert_error_envelope(&res, Some("too_many_items"), Some("errorStorage"))?;
    assert!(msg.contains("10001"), "{msg}");
    assert!(
        elapsed < Duration::from_secs(1),
        "400k-path frame rejection must be bounded (took {elapsed:?})"
    );

    // 2. C1-F4: Concurrent start_send_text / start_send_files vs totaldrop_win_shutdown
    // completes cleanly within bound and leaves runtime reusable.
    let _write_lock = SHUTDOWN_GATE
        .write()
        .map_err(|_| "SHUTDOWN_GATE poisoned")?;
    let rdv = MockRendezvous::start()?;
    let cfg = make_relay_only_cfg(&rdv.url, "");
    let cfg_clone = cfg.clone();

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let b_spawn = Arc::clone(&barrier);
    let spawner = std::thread::spawn(move || -> Result<Vec<u64>, String> {
        b_spawn.wait();
        let mut sids = Vec::new();
        for i in 0..6 {
            let sid = start_send_text(&cfg_clone, &format!("tier5-race-msg-{i}"))
                .map_err(|e| e.to_string())?;
            sids.push(sid.id());
            std::mem::forget(sid);
        }
        Ok(sids)
    });

    barrier.wait();
    let _ = totaldrop_win_shutdown(50);
    let sids = spawner
        .join()
        .map_err(|_| "spawner thread panicked")?
        .map_err(|e| format!("spawner error: {e}"))?;

    // Drain any sessions created right after the first shutdown wave.
    let final_t0 = Instant::now();
    assert_eq!(totaldrop_win_shutdown(100), FFI_OK);
    assert!(
        final_t0.elapsed() < Duration::from_secs(2),
        "final shutdown took too long: {:?}",
        final_t0.elapsed()
    );
    for sid in sids {
        // Sessions already drained by shutdown return invalid handle cleanly.
        let _ = totaldrop_win_session_destroy(sid);
    }

    // Verify the FFI runtime remains fully usable after concurrent shutdowns,
    // then drain cleanly before releasing SHUTDOWN_GATE so sibling timing tests
    // start from a completely idle runtime.
    let post = start_send_text(&cfg, "post-shutdown-ok")?;
    let mut evs = Vec::new();
    let _ = wait_for_session_event(post.id(), &mut evs, "code_ready", Duration::from_secs(10))?;
    assert_eq!(totaldrop_win_session_cancel(post.id()), FFI_OK);
    let _ = wait_for_session_event(post.id(), &mut evs, "failed", Duration::from_secs(10))?;
    drop(post);
    assert_eq!(totaldrop_win_shutdown(500), FFI_OK);
    Ok(())
}
