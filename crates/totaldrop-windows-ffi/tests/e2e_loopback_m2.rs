// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opaque-box E2E tests for Milestone M2 (`F08`–`F15`, Tier 3, Tier 4) across
//! `totaldrop-windows-ffi` and `totaldrop-windows-bridge`.
//!
//! - Uses Architecture A real `totaldrop-rendezvous` / `totaldrop-relay`
//!   subprocesses when `TOTALDROP_TEST_RENDEZVOUS_BIN` /
//!   `TOTALDROP_TEST_RELAY_BIN` are set (failing loudly if a configured path is
//!   missing or fails to bind), and Architecture B in-process MIT/Apache-2.0
//!   loopback servers (`127.0.0.1:0` / `[::1]:0`) for deterministic fault
//!   injection and standalone `cargo test --workspace --locked` fallback.
//! - Zero live production connections are ever opened: every network session
//!   fixture explicitly sets `relay_server: ""` (or loopback relay) and
//!   `stun_server: ""`.

use std::collections::{BTreeSet, HashMap};
use std::error::Error as StdError;
use std::ffi::{CStr, CString, c_char};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
use totaldrop_core::{pairing, path, rendezvous, secure, transport};
use totaldrop_crypto::cpace::Role;
use totaldrop_crypto::identity::DeviceKeys;
use totaldrop_crypto::{ContentKey, EntryCipher};
use totaldrop_l10n::{Domain, Strings, locale};
use totaldrop_proto::TransferCode;
use totaldrop_proto::limits;
use totaldrop_proto::relay as proto_relay;
use totaldrop_proto::wire::{
    Address, ClientMessage, Control, DataHeader, Entry, EntryKind, Hints, Manifest, Mood,
    ServerMessage,
};
use totaldrop_windows_bridge::{
    ActivationEnvelope, ActivationError, IpcFrameDecoder, MAX_IPC_FRAME_BYTES, RouterDecision,
    SUPPORTED_LANGUAGES, ScreenTarget, UriValidationError, ValidatedCode, WinUiBridgeMessage,
    WindowsSelectionPath, decode_ndjson_stream, encode_ndjson_batch, parse_launch_args,
    quote_win32_arg, split_win32_command_line,
};
use totaldrop_windows_ffi::{
    FFI_ERR_INVALID_ARG, FFI_ERR_INVALID_HANDLE, FFI_OK, totaldrop_win_code_completions_json,
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
};

type TestResult = Result<(), Box<dyn StdError>>;

/// Coordinates tests invoking global `totaldrop_win_shutdown` (write lock)
/// with concurrent session tests (read lock) inside the same test process.
static SHUTDOWN_GATE: LazyLock<RwLock<()>> = LazyLock::new(|| RwLock::new(()));

static TEST_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .thread_name("totaldrop-m2-srv")
        .build()
        .unwrap_or_else(|_| std::process::abort())
});

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// RAII Guards & Deterministic Helpers

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Result<Self, std::io::Error> {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("totaldrop-win-m2-e2e-{prefix}-{pid}-{id}"));
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

#[cfg(unix)]
struct ModeRestoreGuard {
    path: PathBuf,
    restore_mode: u32,
}

#[cfg(unix)]
impl ModeRestoreGuard {
    fn set(path: PathBuf, new_mode: u32, restore_mode: u32) -> Result<Self, std::io::Error> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(new_mode))?;
        Ok(Self { path, restore_mode })
    }
}

#[cfg(unix)]
impl Drop for ModeRestoreGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &self.path,
            std::fs::Permissions::from_mode(self.restore_mode),
        );
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

fn c_str(s: &str) -> Result<CString, Box<dyn StdError>> {
    Ok(CString::new(s)?)
}

fn take_json(ptr: *mut c_char) -> Result<Value, Box<dyn StdError>> {
    if ptr.is_null() {
        return Err("FFI returned NULL pointer".into());
    }
    // SAFETY: `ptr` was returned by a `totaldrop_win_*` FFI export.
    let raw = unsafe { CStr::from_ptr(ptr) }.to_str()?.to_owned();
    // SAFETY: Freed exactly once via `totaldrop_win_string_free`.
    unsafe { totaldrop_win_string_free(ptr) };
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

fn poll_events(sid: u64) -> Result<Vec<Value>, Box<dyn StdError>> {
    let ptr = totaldrop_win_session_poll_events_ndjson(sid);
    if ptr.is_null() {
        return Err("poll returned null".into());
    }
    // SAFETY: `ptr` was returned by `totaldrop_win_session_poll_events_ndjson`.
    let raw = unsafe { CStr::from_ptr(ptr) }.to_str()?.to_owned();
    // SAFETY: Freed once via `totaldrop_win_string_free`.
    unsafe { totaldrop_win_string_free(ptr) };

    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            out.push(serde_json::from_str(trimmed)?);
        }
    }
    Ok(out)
}

fn wait_for_event(
    sid: u64,
    all: &mut Vec<Value>,
    target_event: &str,
    timeout: Duration,
) -> Result<Value, Box<dyn StdError>> {
    let started = Instant::now();
    loop {
        if let Some(found) = all
            .iter()
            .find(|ev| ev.get("event").and_then(Value::as_str) == Some(target_event))
        {
            return Ok(found.clone());
        }
        if target_event != "failed"
            && let Some(failed) = all
                .iter()
                .find(|ev| ev.get("event").and_then(Value::as_str) == Some("failed"))
        {
            return Err(format!(
                "unexpected failed event while waiting for {target_event:?}: {failed}"
            )
            .into());
        }
        let batch = poll_events(sid)?;
        all.extend(batch);
        if let Some(found) = all
            .iter()
            .find(|ev| ev.get("event").and_then(Value::as_str) == Some(target_event))
        {
            return Ok(found.clone());
        }
        if target_event != "failed"
            && let Some(failed) = all
                .iter()
                .find(|ev| ev.get("event").and_then(Value::as_str) == Some("failed"))
        {
            return Err(format!(
                "unexpected failed event while waiting for {target_event:?}: {failed}"
            )
            .into());
        }
        if started.elapsed() >= timeout {
            return Err(
                format!("timed out waiting for event {target_event:?}; saw: {all:?}").into(),
            );
        }
        std::thread::sleep(Duration::from_millis(12));
    }
}

fn wait_for_any_terminal(
    sid: u64,
    all: &mut Vec<Value>,
    timeout: Duration,
) -> Result<Value, Box<dyn StdError>> {
    let started = Instant::now();
    loop {
        let batch = poll_events(sid)?;
        all.extend(batch);
        if let Some(found) = all.iter().find(|ev| {
            matches!(
                ev.get("event").and_then(Value::as_str).unwrap_or(""),
                "done" | "failed" | "declined"
            )
        }) {
            return Ok(found.clone());
        }
        if started.elapsed() >= timeout {
            return Err(format!("timed out waiting for terminal event; saw: {all:?}").into());
        }
        std::thread::sleep(Duration::from_millis(12));
    }
}

fn make_cfg_json(
    rendezvous_url: &str,
    relay_url: &str,
    privacy_relay_only: bool,
    stronger_three_word_code: bool,
) -> String {
    json!({
        "rendezvous_server": rendezvous_url,
        "relay_server": relay_url,
        "stun_server": "",
        "privacy_relay_only": privacy_relay_only,
        "stronger_three_word_code": stronger_three_word_code
    })
    .to_string()
}

fn start_send_files(
    cfg_json: &str,
    paths: &[&Path],
    lang: &str,
    region: &str,
) -> Result<SessionGuard, Box<dyn StdError>> {
    let cfg_c = c_str(cfg_json)?;
    let path_strings: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let paths_json = serde_json::to_string(&path_strings)?;
    let paths_c = c_str(&paths_json)?;
    let lang_c = c_str(lang)?;
    let region_c = c_str(region)?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let sid = unsafe {
        totaldrop_win_send_files_start(
            cfg_c.as_ptr(),
            paths_c.as_ptr(),
            lang_c.as_ptr(),
            region_c.as_ptr(),
        )
    };
    if sid == 0 {
        return Err("totaldrop_win_send_files_start returned 0".into());
    }
    Ok(SessionGuard(sid))
}

fn start_send_text(
    cfg_json: &str,
    text: &str,
    lang: &str,
    region: &str,
) -> Result<SessionGuard, Box<dyn StdError>> {
    let cfg_c = c_str(cfg_json)?;
    let text_c = c_str(text)?;
    let lang_c = c_str(lang)?;
    let region_c = c_str(region)?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let sid = unsafe {
        totaldrop_win_send_text_start(
            cfg_c.as_ptr(),
            text_c.as_ptr(),
            lang_c.as_ptr(),
            region_c.as_ptr(),
        )
    };
    if sid == 0 {
        return Err("totaldrop_win_send_text_start returned 0".into());
    }
    Ok(SessionGuard(sid))
}

fn start_receive_connect(
    cfg_json: &str,
    code_or_uri: &str,
    lang: &str,
    region: &str,
) -> Result<SessionGuard, Box<dyn StdError>> {
    let cfg_c = c_str(cfg_json)?;
    let code_c = c_str(code_or_uri)?;
    let lang_c = c_str(lang)?;
    let region_c = c_str(region)?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let sid = unsafe {
        totaldrop_win_receive_connect_start(
            cfg_c.as_ptr(),
            code_c.as_ptr(),
            lang_c.as_ptr(),
            region_c.as_ptr(),
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

fn dir_entry_count(dir: &Path) -> Result<usize, std::io::Error> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in std::fs::read_dir(dir)? {
        let _ = entry?;
        count = count.saturating_add(1);
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Architecture A Out-of-Process Real Subprocess Launcher (RAII Drop Cleanup)

struct SubprocessGuard {
    child: Child,
}

impl Drop for SubprocessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

enum LoopbackRendezvous {
    ArchA { url: String, _proc: SubprocessGuard },
    ArchB(MockRendezvous),
}

impl LoopbackRendezvous {
    fn start() -> Result<Self, Box<dyn StdError>> {
        if let Ok(bin_raw) = std::env::var("TOTALDROP_TEST_RENDEZVOUS_BIN")
            && !bin_raw.trim().is_empty()
        {
            let bin = PathBuf::from(bin_raw.trim());
            if !bin.is_file() {
                return Err(format!(
                    "TOTALDROP_TEST_RENDEZVOUS_BIN points to missing binary: {}",
                    bin.display()
                )
                .into());
            }
            let mut child = Command::new(&bin)
                .arg("127.0.0.1:0")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()?;
            let stderr = child
                .stderr
                .take()
                .ok_or("failed to capture totaldrop-rendezvous stderr")?;
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().map_while(Result::ok) {
                    if let Some(pos) = line.find("127.0.0.1:") {
                        let tail = line.get(pos..).unwrap_or("");
                        let addr = tail
                            .split(|c: char| c.is_whitespace() || c == ',')
                            .next()
                            .unwrap_or("");
                        if !addr.is_empty() {
                            let _ = tx.send(format!("ws://{addr}"));
                        }
                    }
                }
            });
            let guard = SubprocessGuard { child };
            let url = rx
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "timed out waiting for totaldrop-rendezvous listening address")?;
            return Ok(Self::ArchA { url, _proc: guard });
        }
        Ok(Self::ArchB(MockRendezvous::start(
            "127.0.0.1:0",
            RendezvousFault::None,
        )?))
    }

    fn url(&self) -> &str {
        match self {
            Self::ArchA { url, .. } => url,
            Self::ArchB(m) => &m.url,
        }
    }
}

enum LoopbackRelay {
    ArchA { url: String, _proc: SubprocessGuard },
    ArchB(MockRelay),
}

impl LoopbackRelay {
    fn start() -> Result<Self, Box<dyn StdError>> {
        if let Ok(bin_raw) = std::env::var("TOTALDROP_TEST_RELAY_BIN")
            && !bin_raw.trim().is_empty()
        {
            let bin = PathBuf::from(bin_raw.trim());
            if !bin.is_file() {
                return Err(format!(
                    "TOTALDROP_TEST_RELAY_BIN points to missing binary: {}",
                    bin.display()
                )
                .into());
            }
            let mut child = Command::new(&bin)
                .args(["127.0.0.1:0", "127.0.0.1:0"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()?;
            let stderr = child
                .stderr
                .take()
                .ok_or("failed to capture totaldrop-relay stderr")?;
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().map_while(Result::ok) {
                    if let Some(pos) = line.find("WebSocket on 127.0.0.1:") {
                        let start = pos.saturating_add("WebSocket on ".len());
                        let tail = line.get(start..).unwrap_or("");
                        let addr = tail
                            .split(|c: char| c.is_whitespace() || c == ',')
                            .next()
                            .unwrap_or("");
                        if !addr.is_empty() {
                            let _ = tx.send(format!("ws://{addr}/v0/relay"));
                        }
                    }
                }
            });
            let guard = SubprocessGuard { child };
            let url = rx
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "timed out waiting for totaldrop-relay listening address")?;
            return Ok(Self::ArchA { url, _proc: guard });
        }
        Ok(Self::ArchB(MockRelay::start(RelayMode::Normal)?))
    }

    fn url(&self) -> &str {
        match self {
            Self::ArchA { url, .. } => url,
            Self::ArchB(m) => &m.url,
        }
    }
}

// ---------------------------------------------------------------------------
// Architecture B In-Process Fault-Injecting Loopback Rendezvous & Relay

#[derive(Clone, Debug)]
enum RendezvousFault {
    None,
    AlwaysError(String),
    ErrorAfterClaim(String),
    PeerCloseOnPhase { phase: String, mood: Mood },
}

struct MailboxSlot {
    token: [u8; 16],
    mailbox_id: [u8; 16],
    peers: Vec<mpsc::UnboundedSender<ServerMessage>>,
    buffered_for_second: Vec<ServerMessage>,
    retired: bool,
}

struct RendezvousState {
    next_nameplate: AtomicU32,
    boxes: Mutex<HashMap<u32, MailboxSlot>>,
    fault: RendezvousFault,
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
    fn start(bind_addr: &str, fault: RendezvousFault) -> Result<Self, Box<dyn StdError>> {
        let (url, abort) = TEST_RUNTIME.block_on(async move {
            let listener = TcpListener::bind(bind_addr).await?;
            let local: SocketAddr = listener.local_addr()?;
            let url = match local {
                SocketAddr::V4(v4) => format!("ws://{v4}"),
                SocketAddr::V6(v6) => format!("ws://[{}]:{}", v6.ip(), v6.port()),
            };
            let state = Arc::new(RendezvousState {
                next_nameplate: AtomicU32::new(7),
                boxes: Mutex::new(HashMap::new()),
                fault,
            });
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let st = Arc::clone(&state);
                    tokio::spawn(async move {
                        let _ = handle_rendezvous_conn(stream, st).await;
                    });
                }
            });
            Ok::<_, std::io::Error>((url, task.abort_handle()))
        })?;
        Ok(Self { url, abort })
    }
}

async fn close_ws_gracefully(ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) {
    let _ = ws.close(None).await;
    // Drain until the peer acknowledges close (bounded) so Windows Winsock
    // never sends TCP RST (WSAECONNABORTED / os error 10053) while the client
    // is still reading the preceding binary frame.
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        while let Some(Ok(frame)) = ws.next().await {
            if matches!(frame, Message::Close(_)) {
                break;
            }
        }
    })
    .await;
}

async fn send_error_and_close(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    reason: &str,
) {
    let msg = ServerMessage::Error {
        reason: reason.to_owned(),
    };
    let _ = ws.send(Message::Binary(msg.encode().into())).await;
    close_ws_gracefully(ws).await;
}

async fn handle_rendezvous_conn(
    stream: tokio::net::TcpStream,
    state: Arc<RendezvousState>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let mut ws = tokio_tungstenite::accept_async(stream).await?;

    let first_msg = loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => break ClientMessage::decode(&b)?,
            Some(Ok(Message::Ping(p))) => {
                let _ = ws.send(Message::Pong(p)).await;
            }
            _ => return Ok(()),
        }
    };

    if let RendezvousFault::AlwaysError(ref reason) = state.fault {
        send_error_and_close(&mut ws, reason).await;
        return Ok(());
    }

    match first_msg {
        ClientMessage::Allocate => {
            let nameplate = state.next_nameplate.fetch_add(1, Ordering::Relaxed);
            let mut token = [0u8; 16];
            let mut mailbox_id = [0u8; 16];
            for (idx, b) in token.iter_mut().enumerate() {
                *b = u8::try_from(idx.wrapping_add(nameplate as usize) & 0xFF).unwrap_or(1);
            }
            for (idx, b) in mailbox_id.iter_mut().enumerate() {
                *b = u8::try_from(idx.wrapping_mul(7).wrapping_add(nameplate as usize) & 0xFF)
                    .unwrap_or(2);
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
                        retired: false,
                    },
                );
            }
            let reply = ServerMessage::Allocated { nameplate, token };
            let _ = ws.send(Message::Binary(reply.encode().into())).await;
            close_ws_gracefully(&mut ws).await;
        }
        ClientMessage::Claim { nameplate, token } => {
            let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
            let (mailbox_id, peer_index, replay) = {
                let mut boxes = state.boxes.lock().await;
                let Some(slot) = boxes.get_mut(&nameplate) else {
                    drop(boxes);
                    send_error_and_close(&mut ws, "unknown nameplate").await;
                    return Ok(());
                };
                if slot.retired {
                    drop(boxes);
                    send_error_and_close(&mut ws, "mailbox expired").await;
                    return Ok(());
                }
                if slot.peers.is_empty() {
                    if token != Some(slot.token) {
                        drop(boxes);
                        send_error_and_close(&mut ws, "unknown nameplate").await;
                        return Ok(());
                    }
                    slot.peers.push(tx);
                    (slot.mailbox_id, 0usize, Vec::new())
                } else if slot.peers.len() == 1 {
                    slot.peers.push(tx);
                    let replay = std::mem::take(&mut slot.buffered_for_second);
                    (slot.mailbox_id, 1usize, replay)
                } else {
                    drop(boxes);
                    send_error_and_close(&mut ws, "nameplate full").await;
                    return Ok(());
                }
            };

            let claimed = ServerMessage::Claimed {
                mailbox: mailbox_id,
            };
            ws.send(Message::Binary(claimed.encode().into())).await?;

            if let RendezvousFault::ErrorAfterClaim(ref reason) = state.fault {
                send_error_and_close(&mut ws, reason).await;
                return Ok(());
            }

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
                                        if let RendezvousFault::PeerCloseOnPhase { phase: ref target, mood } = state.fault
                                            && phase == *target
                                        {
                                            let _ = ws
                                                .send(Message::Binary(
                                                    ServerMessage::PeerClosed { mood }.encode().into(),
                                                ))
                                                .await;
                                            let _ = ws.close(None).await;
                                            break;
                                        }
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
                                            if mood == Mood::Scary {
                                                slot.retired = true;
                                            }
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
    Throttled(Duration),
    ThrottledStride { every_n: u64, delay: Duration },
    DropOnConnect,
}

type RelayPeerMap = HashMap<[u8; 32], mpsc::UnboundedSender<Vec<u8>>>;
type RelayPairTable = HashMap<([u8; 32], [u8; 32]), RelayPeerMap>;

struct RelayState {
    mode: RelayMode,
    pairs: Mutex<RelayPairTable>,
}

struct MockRelay {
    url: String,
    abort: tokio::task::AbortHandle,
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl MockRelay {
    fn start(mode: RelayMode) -> Result<Self, Box<dyn StdError>> {
        let (url, abort) = TEST_RUNTIME.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let local = listener.local_addr()?;
            let url = format!("ws://{local}/v0/relay");
            let state = Arc::new(RelayState {
                mode,
                pairs: Mutex::new(HashMap::new()),
            });
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let st = Arc::clone(&state);
                    tokio::spawn(async move {
                        let _ = handle_relay_conn(stream, st).await;
                    });
                }
            });
            Ok::<_, std::io::Error>((url, task.abort_handle()))
        })?;
        Ok(Self { url, abort })
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

    if matches!(state.mode, RelayMode::DropOnConnect) {
        let _ = ws.close(None).await;
        return Ok(());
    }

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

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        let mut pairs = state.pairs.lock().await;
        pairs.entry(pair).or_default().insert(key, tx);
    }

    let mut stride_ctr: u64 = 0;
    loop {
        tokio::select! {
            outbound = rx.recv() => {
                let Some(frame) = outbound else { break; };
                match state.mode {
                    RelayMode::Throttled(delay) => {
                        tokio::time::sleep(delay).await;
                    }
                    RelayMode::ThrottledStride { every_n, delay } => {
                        stride_ctr = stride_ctr.saturating_add(1);
                        if stride_ctr >= every_n.max(1) {
                            stride_ctr = 0;
                            tokio::time::sleep(delay).await;
                        }
                    }
                    RelayMode::Normal | RelayMode::DropOnConnect => {}
                }
                if ws.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
            inbound = ws.next() => {
                match inbound {
                    Some(Ok(Message::Binary(b))) => {
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
                        let pairs = state.pairs.lock().await;
                        if let Some(peer_tx) = pairs.get(&pair).and_then(|m| m.get(&dst)) {
                            let _ = peer_tx.send(delivered);
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

    let mut pairs = state.pairs.lock().await;
    if let Some(map) = pairs.get_mut(&pair) {
        map.remove(&key);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Architecture B Fault-Injecting Custom Sender

#[derive(Clone, Copy)]
enum SenderFault {
    CorruptTextBlake3Hash,
    InvalidUtf8TextPayload,
    TamperOfferAeadTag,
    TamperManifestSignature,
    MalformedControlFrame,
    UnsupportedProtocolVersion,
    ResetMidTransfer,
    SilentStallAfterDataHeader,
}

async fn run_fault_sender(
    rendezvous_url: String,
    fault: SenderFault,
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
    let versions = if matches!(fault, SenderFault::UnsupportedProtocolVersion) {
        vec![99u64]
    } else {
        pairing::VERSIONS.to_vec()
    };
    let hints = Hints {
        versions,
        endpoint_key: endpoint_key.public(),
        public: Vec::new(),
        local: transport::local_addresses(&socket)?
            .into_iter()
            .map(Address)
            .collect(),
        relay: None,
    };
    let paired =
        pairing::exchange(mailbox, Role::Initiator, &code, mailbox_id, &keys, &hints).await?;
    let (endpoint, _pipes, _fallback) =
        transport::endpoint(socket, &endpoint_key, &paired.hints.endpoint_key)?;
    let peer_addrs: Vec<SocketAddr> = paired
        .hints
        .local
        .iter()
        .map(|a| path::canonical(a.0))
        .collect();
    let paths = transport::Paths {
        direct: peer_addrs,
        relay: None,
        relay_only: false,
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

    if matches!(fault, SenderFault::MalformedControlFrame) {
        let ct = chan.sealer.seal(&[0xFFu8, 0xFFu8])?;
        write_frame(&mut chan.send, &ct).await?;
        let _ = tokio::time::timeout(Duration::from_secs(20), conn.closed()).await;
        drop(endpoint);
        return Ok(());
    }

    let transfer_id = totaldrop_crypto::new_transfer_id()?;
    let ck = ContentKey::generate()?;

    let (is_text, payload): (bool, Vec<u8>) = match fault {
        SenderFault::CorruptTextBlake3Hash => (true, b"valid utf-8 text".to_vec()),
        SenderFault::InvalidUtf8TextPayload => (true, vec![0xFF, 0xFE]),
        SenderFault::TamperOfferAeadTag => (true, b"tampered offer".to_vec()),
        SenderFault::TamperManifestSignature => (false, b"tampered signature file".to_vec()),
        SenderFault::ResetMidTransfer => (false, vec![0x33u8; 2_097_152]),
        SenderFault::SilentStallAfterDataHeader => (false, vec![0x55u8; 2_097_152]),
        SenderFault::MalformedControlFrame | SenderFault::UnsupportedProtocolVersion => {
            return Ok(());
        }
    };

    let mut hash = *blake3::hash(&payload).as_bytes();
    if matches!(fault, SenderFault::CorruptTextBlake3Hash)
        && let Some(first) = hash.first_mut()
    {
        *first ^= 0x01;
    }

    let filename = if is_text { "text.txt" } else { "stalled.bin" };
    let entry = Entry {
        path: vec![filename.to_owned()],
        kind: EntryKind::File,
        size: u64::try_from(payload.len()).unwrap_or(0),
        hash: Some(hash),
        mtime: None,
    };
    let manifest = Manifest {
        transfer_id,
        entries: vec![entry],
        total_size: u64::try_from(payload.len()).unwrap_or(0),
        chunk_size: limits::CHUNK_SIZE,
    };
    let mut signature = keys.sign(&manifest.signed_bytes());
    if matches!(fault, SenderFault::TamperManifestSignature)
        && let Some(first) = signature.first_mut()
    {
        *first ^= 0xFF;
    }

    let offer = Control::Offer {
        manifest,
        content_key: *ck.as_bytes(),
        signature,
        progress: true,
        text: is_text,
    };

    if matches!(fault, SenderFault::TamperOfferAeadTag) {
        let mut ct = chan.sealer.seal(&offer.encode())?;
        if let Some(last) = ct.last_mut() {
            *last ^= 0x01;
        }
        write_frame(&mut chan.send, &ct).await?;
        let _ = tokio::time::timeout(Duration::from_secs(20), conn.closed()).await;
        drop(endpoint);
        return Ok(());
    }

    secure::send_control(&mut chan.sealer, &mut chan.send, &offer).await?;

    if matches!(fault, SenderFault::TamperManifestSignature) {
        let _ = tokio::time::timeout(Duration::from_secs(20), conn.closed()).await;
        drop(endpoint);
        return Ok(());
    }

    let reply = secure::recv_control(&mut chan.opener, &mut chan.recv).await?;
    if !matches!(reply, Control::Accept { .. }) {
        return Ok(());
    }

    let mut uni = conn.open_uni().await?;
    let cipher = EntryCipher::new(&ck, &transfer_id, 0);
    let header = DataHeader {
        transfer_id,
        entry: 0,
        first_chunk: 0,
    };
    write_frame(&mut uni, &header.encode()).await?;

    if matches!(fault, SenderFault::ResetMidTransfer) {
        let first_chunk = payload.get(..1_048_576).unwrap_or(&payload);
        let sealed_chunk = cipher.seal(0, false, first_chunk)?;
        write_frame(&mut uni, &sealed_chunk).await?;
        tokio::time::sleep(Duration::from_millis(40)).await;
        conn.close(0u32.into(), b"failed");
        // Keep the QUIC endpoint alive until the caller aborts this task so
        // retransmissions or keep-alives from a descheduled receiver always
        // draw either a replayed CONNECTION_CLOSE or a stateless reset
        // (both Cause::ConnectionLost) instead of waiting 30s for idle timeout.
        endpoint.wait_idle().await;
        tokio::time::sleep(Duration::from_secs(20)).await;
        drop(endpoint);
        return Ok(());
    }

    if matches!(fault, SenderFault::SilentStallAfterDataHeader) {
        let first_chunk = payload.get(..1_048_576).unwrap_or(&payload);
        let sealed_chunk = cipher.seal(0, false, first_chunk)?;
        write_frame(&mut uni, &sealed_chunk).await?;
        // Deliberately go completely silent, ignoring any Control::Cancel.
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(endpoint);
        return Ok(());
    }

    let sealed_chunk = cipher.seal(0, true, &payload)?;
    write_frame(&mut uni, &sealed_chunk).await?;
    let _ = uni.finish();
    let _ = secure::recv_control(&mut chan.opener, &mut chan.recv).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// F08 (M2): Bridge URL Validation & Core Error Distinctions (10 tests)

#[test]
fn t1_f08_01_validate_server_url_valid_offline() -> TestResult {
    // Offline string validation checks only — zero network connections opened.
    for valid in [
        "wss://rendezvous.totaldrop.app",
        "ws://127.0.0.1:4000",
        "ws://[::1]:4000",
        "ws://localhost:4000",
    ] {
        let url_c = c_str(valid)?;
        // SAFETY: `url_c` is a live NUL-terminated CString.
        let val = take_json(unsafe { totaldrop_win_validate_server_url_json(url_c.as_ptr()) })?;
        assert_eq!(val, json!({"ok": true}), "expected ok:true for {valid:?}");
    }
    Ok(())
}

#[test]
fn t1_f08_02_mailbox_expired_sender_vs_receiver() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let tmp = TempDirGuard::new("t1-f08-02")?;
    let file = tmp.path().join("sample.txt");
    std::fs::write(&file, b"hello")?;

    // Sender receives `mailbox expired` after claim -> errorCodeExpired.
    let srv_sender = MockRendezvous::start(
        "127.0.0.1:0",
        RendezvousFault::ErrorAfterClaim("mailbox expired".to_owned()),
    )?;
    let cfg_s = make_cfg_json(&srv_sender.url, "", false, false);
    let send_sid = start_send_files(&cfg_s, &[file.as_path()], "en-US", "en-US")?;
    let mut s_events = Vec::new();
    let s_fail = wait_for_event(
        send_sid.id(),
        &mut s_events,
        "failed",
        Duration::from_secs(10),
    )?;
    assert_eq!(
        s_fail.get("kind").and_then(Value::as_str),
        Some("code_expired")
    );
    assert_eq!(
        s_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorCodeExpired")
    );
    assert!(
        s_fail
            .get("technical_english")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("mailbox expired"))
    );

    // Receiver receives `mailbox expired` -> errorCodeNotInUse.
    let srv_recv = MockRendezvous::start(
        "127.0.0.1:0",
        RendezvousFault::AlwaysError("mailbox expired".to_owned()),
    )?;
    let cfg_r = make_cfg_json(&srv_recv.url, "", false, false);
    let recv_sid = start_receive_connect(&cfg_r, "7-harbor-rocket", "en-US", "en-US")?;
    let mut r_events = Vec::new();
    let r_fail = wait_for_event(
        recv_sid.id(),
        &mut r_events,
        "failed",
        Duration::from_secs(10),
    )?;
    assert_eq!(
        r_fail.get("kind").and_then(Value::as_str),
        Some("code_not_in_use")
    );
    assert_eq!(
        r_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorCodeNotInUse")
    );
    assert!(
        r_fail
            .get("technical_english")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("mailbox expired"))
    );
    Ok(())
}

#[test]
fn t1_f08_03_unknown_nameplate_nameplate_full_and_bad_server() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let tmp = TempDirGuard::new("t1-f08-03")?;
    let file = tmp.path().join("payload.bin");
    std::fs::write(&file, b"ok")?;

    for reason in ["unknown nameplate", "nameplate full"] {
        let srv = MockRendezvous::start(
            "127.0.0.1:0",
            RendezvousFault::AlwaysError(reason.to_owned()),
        )?;
        let cfg = make_cfg_json(&srv.url, "", false, false);
        let recv_sid = start_receive_connect(&cfg, "7-harbor-rocket", "en-US", "en-US")?;
        let mut events = Vec::new();
        let fail = wait_for_event(
            recv_sid.id(),
            &mut events,
            "failed",
            Duration::from_secs(10),
        )?;
        assert_eq!(
            fail.get("l10n_key").and_then(Value::as_str),
            Some("errorCodeNotInUse"),
            "unexpected mapping for {reason:?}: {fail}"
        );
    }

    // Invalid URL `http://127.0.0.1:4000` -> errorBadServer (`kind == "bad_server"`).
    let bad_cfg = make_cfg_json("http://127.0.0.1:4000", "", false, false);
    let send_sid = start_send_files(&bad_cfg, &[file.as_path()], "en-US", "en-US")?;
    let mut s_events = Vec::new();
    let s_fail = wait_for_event(
        send_sid.id(),
        &mut s_events,
        "failed",
        Duration::from_secs(5),
    )?;
    assert_eq!(
        s_fail.get("kind").and_then(Value::as_str),
        Some("bad_server")
    );
    assert_eq!(
        s_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorBadServer")
    );

    let recv_sid = start_receive_connect(&bad_cfg, "7-harbor-rocket", "en-US", "en-US")?;
    let mut r_events = Vec::new();
    let r_fail = wait_for_event(
        recv_sid.id(),
        &mut r_events,
        "failed",
        Duration::from_secs(5),
    )?;
    assert_eq!(
        r_fail.get("kind").and_then(Value::as_str),
        Some("bad_server")
    );
    assert_eq!(
        r_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorBadServer")
    );
    Ok(())
}

#[test]
fn t1_f08_04_all_canonical_core_error_mappings() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let tmp = TempDirGuard::new("t1-f08-04")?;
    let sample = tmp.path().join("sample.bin");
    std::fs::write(&sample, pseudo_random_bytes(804, 65_536))?;
    let big_sample = tmp.path().join("big.bin");
    std::fs::write(&big_sample, pseudo_random_bytes(8042, 2_097_152))?;

    for (lang, region) in [("en-US", "en-US"), ("tr-TR", "tr-TR")] {
        let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
        let cfg = make_cfg_json(&srv.url, "", false, false);

        // 1. WrongCode (mismatched words)
        {
            let s = start_send_files(&cfg, &[sample.as_path()], lang, region)?;
            let mut s_ev = Vec::new();
            let cr = wait_for_event(s.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
            let nameplate = cr
                .get("code")
                .and_then(|c| c.get("nameplate"))
                .and_then(Value::as_u64)
                .ok_or("missing nameplate")?;
            let wrong = format!("{nameplate}-abandon-ability");
            let actual = cr
                .get("code")
                .and_then(|c| c.get("display_english"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let bad_code = if wrong == actual {
                format!("{nameplate}-zoo-zone")
            } else {
                wrong
            };
            let r = start_receive_connect(&cfg, &bad_code, lang, region)?;
            let mut r_ev = Vec::new();
            let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
            assert_eq!(
                rf.get("l10n_key").and_then(Value::as_str),
                Some("errorWrongCode")
            );
            assert!(
                rf.get("summary")
                    .and_then(Value::as_str)
                    .is_some_and(|x| !x.is_empty())
            );
            assert!(
                rf.get("technical_english")
                    .and_then(Value::as_str)
                    .is_some_and(|x| x.contains("code did not match"))
            );
        }

        // 2. PeerLeft (PeerClosed during "pake")
        {
            let peer_left_srv = MockRendezvous::start(
                "127.0.0.1:0",
                RendezvousFault::PeerCloseOnPhase {
                    phase: "pake".to_owned(),
                    mood: Mood::Lonely,
                },
            )?;
            let pl_cfg = make_cfg_json(&peer_left_srv.url, "", false, false);
            let s = start_send_files(&pl_cfg, &[sample.as_path()], lang, region)?;
            let mut s_ev = Vec::new();
            let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(10))?;
            assert_eq!(
                sf.get("l10n_key").and_then(Value::as_str),
                Some("errorPeerLeft")
            );
            assert!(
                sf.get("summary")
                    .and_then(Value::as_str)
                    .is_some_and(|x| !x.is_empty())
            );
            assert!(
                sf.get("technical_english")
                    .and_then(Value::as_str)
                    .is_some_and(|x| !x.is_empty())
            );
        }

        // 3. Rejected / errorDeclined
        {
            let s = start_send_files(&cfg, &[sample.as_path()], lang, region)?;
            let mut s_ev = Vec::new();
            let cr = wait_for_event(s.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
            let code = cr
                .get("code")
                .and_then(|c| c.get("display_english"))
                .and_then(Value::as_str)
                .ok_or("missing display_english")?;
            let r = start_receive_connect(&cfg, code, lang, region)?;
            let mut r_ev = Vec::new();
            let _ = wait_for_event(r.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
            assert_eq!(totaldrop_win_receive_decline(r.id()), FFI_OK);
            let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(10))?;
            assert_eq!(
                sf.get("l10n_key").and_then(Value::as_str),
                Some("errorDeclined")
            );
            assert!(
                sf.get("summary")
                    .and_then(Value::as_str)
                    .is_some_and(|x| !x.is_empty())
            );
            assert!(
                sf.get("technical_english")
                    .and_then(Value::as_str)
                    .is_some_and(|x| !x.is_empty())
            );
        }

        // 4 & 5. Stopped (local cancel) + Cancelled (remote cancel)
        {
            let relay = MockRelay::start(RelayMode::Throttled(Duration::from_millis(2)))?;
            let rcfg = make_cfg_json(&srv.url, &relay.url, true, false);
            let s = start_send_files(&rcfg, &[big_sample.as_path()], lang, region)?;
            let mut s_ev = Vec::new();
            let cr = wait_for_event(s.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
            let code = cr
                .get("code")
                .and_then(|c| c.get("display_english"))
                .and_then(Value::as_str)
                .ok_or("missing display_english")?;
            let r = start_receive_connect(&rcfg, code, lang, region)?;
            let mut r_ev = Vec::new();
            let _ = wait_for_event(r.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
            let dest = tmp.path().join(format!("cancel-dest-{lang}"));
            std::fs::create_dir_all(&dest)?;
            assert_eq!(accept_files(r.id(), &dest)?, FFI_OK);
            let _ = wait_for_event(s.id(), &mut s_ev, "progress", Duration::from_secs(15))?;
            assert_eq!(totaldrop_win_session_cancel(s.id()), FFI_OK);
            let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(15))?;
            let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
            assert_eq!(
                sf.get("l10n_key").and_then(Value::as_str),
                Some("errorStopped")
            );
            assert_eq!(
                rf.get("l10n_key").and_then(Value::as_str),
                Some("errorCancelled")
            );
        }

        // 6. Code ("0-harbor-rocket") -> errorInvalidCode
        {
            let r = start_receive_connect(&cfg, "0-harbor-rocket", lang, region)?;
            let mut r_ev = Vec::new();
            let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(5))?;
            assert_eq!(
                rf.get("l10n_key").and_then(Value::as_str),
                Some("errorInvalidCode")
            );
            assert!(
                rf.get("summary")
                    .and_then(Value::as_str)
                    .is_some_and(|x| !x.is_empty())
            );
        }

        // 7. InvalidOffer (tampered manifest signature) -> errorInvalidOffer
        {
            let (code_tx, code_rx) = oneshot::channel();
            let rdv_url = srv.url.clone();
            let task = TEST_RUNTIME.spawn(async move {
                let _ =
                    run_fault_sender(rdv_url, SenderFault::TamperManifestSignature, code_tx).await;
            });
            let code = TEST_RUNTIME.block_on(async {
                tokio::time::timeout(Duration::from_secs(10), code_rx).await
            })??;
            let r = start_receive_connect(&cfg, &code, lang, region)?;
            let mut r_ev = Vec::new();
            let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
            task.abort();
            assert_eq!(
                rf.get("l10n_key").and_then(Value::as_str),
                Some("errorInvalidOffer")
            );
            assert!(
                rf.get("summary")
                    .and_then(Value::as_str)
                    .is_some_and(|x| !x.is_empty())
            );
        }

        // 8. Connect (privacy_relay_only: true with relay_server: "") -> errorConnect
        {
            let priv_cfg = make_cfg_json(&srv.url, "", true, false);
            let s = start_send_files(&priv_cfg, &[sample.as_path()], lang, region)?;
            let mut s_ev = Vec::new();
            let cr = wait_for_event(s.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
            let code = cr
                .get("code")
                .and_then(|c| c.get("display_english"))
                .and_then(Value::as_str)
                .ok_or("missing display_english")?;
            let r = start_receive_connect(&priv_cfg, code, lang, region)?;
            let mut r_ev = Vec::new();
            let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(10))?;
            assert_eq!(
                rf.get("l10n_key").and_then(Value::as_str),
                Some("errorConnect")
            );
            assert!(
                rf.get("summary")
                    .and_then(Value::as_str)
                    .is_some_and(|x| !x.is_empty())
            );
        }

        // 9. Io (nonexistent file) -> errorStorage
        {
            let missing = tmp.path().join("does-not-exist.bin");
            let s = start_send_files(&cfg, &[missing.as_path()], lang, region)?;
            let mut s_ev = Vec::new();
            let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(5))?;
            assert_eq!(
                sf.get("l10n_key").and_then(Value::as_str),
                Some("errorStorage")
            );
            assert!(
                sf.get("summary")
                    .and_then(Value::as_str)
                    .is_some_and(|x| !x.is_empty())
            );
        }

        // 10. Protocol (malformed wire control frame) -> errorOther
        {
            let (code_tx, code_rx) = oneshot::channel();
            let rdv_url = srv.url.clone();
            let task = TEST_RUNTIME.spawn(async move {
                let _ =
                    run_fault_sender(rdv_url, SenderFault::MalformedControlFrame, code_tx).await;
            });
            let code = TEST_RUNTIME.block_on(async {
                tokio::time::timeout(Duration::from_secs(10), code_rx).await
            })??;
            let r = start_receive_connect(&cfg, &code, lang, region)?;
            let mut r_ev = Vec::new();
            let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
            task.abort();
            assert_eq!(
                rf.get("l10n_key").and_then(Value::as_str),
                Some("errorOther")
            );
            assert!(
                rf.get("summary")
                    .and_then(Value::as_str)
                    .is_some_and(|x| !x.is_empty())
            );
        }
    }
    Ok(())
}

#[test]
fn t1_f08_05_all_ten_causes_live_and_l10n() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let tmp = TempDirGuard::new("t1-f08-05")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let cfg = make_cfg_json(&srv.url, "", false, false);

    // (a1) causeNotFound: nonexistent source file
    {
        let missing = tmp.path().join("missing-file.dat");
        let s = start_send_files(&cfg, &[missing.as_path()], "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            f.get("cause").and_then(Value::as_str),
            Some("causeNotFound")
        );
        assert!(
            f.get("cause_detail")
                .and_then(Value::as_str)
                .is_some_and(|x| !x.is_empty())
        );
    }

    // (a2) causeNoPermission: unreadable file (chmod 0o000 with RAII restore)
    #[cfg(unix)]
    {
        let secret = tmp.path().join("no-perm.dat");
        std::fs::write(&secret, b"cannot read")?;
        let _perm = ModeRestoreGuard::set(secret.clone(), 0o000, 0o600)?;
        let s = start_send_files(&cfg, &[secret.as_path()], "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(10))?;
        assert_eq!(
            f.get("cause").and_then(Value::as_str),
            Some("causeNoPermission")
        );
        assert!(
            f.get("cause_detail")
                .and_then(Value::as_str)
                .is_some_and(|x| !x.is_empty())
        );
    }

    // (a3) causeFileChanged: mutate file length after code_ready (post-scan)
    {
        let changing = tmp.path().join("changing.dat");
        std::fs::write(&changing, vec![0x11u8; 4096])?;
        let s = start_send_files(&cfg, &[changing.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(s.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing display_english")?;
        // Overwrite with a different byte length before receiver accepts.
        std::fs::write(&changing, b"short")?;
        let r = start_receive_connect(&cfg, code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let _ = wait_for_event(r.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
        let dest = tmp.path().join("dest-changed");
        std::fs::create_dir_all(&dest)?;
        assert_eq!(accept_files(r.id(), &dest)?, FFI_OK);
        let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(15))?;
        assert_eq!(
            sf.get("l10n_key").and_then(Value::as_str),
            Some("errorStorage")
        );
        assert_eq!(
            sf.get("cause").and_then(Value::as_str),
            Some("causeFileChanged")
        );
        assert!(
            sf.get("cause_detail")
                .and_then(Value::as_str)
                .is_some_and(|x| !x.is_empty())
        );
    }

    // (a4) causeRelay: privacy_relay_only with mismatched loopback relays
    {
        let relay_a = MockRelay::start(RelayMode::Normal)?;
        let relay_b = MockRelay::start(RelayMode::Normal)?;
        let fpath = tmp.path().join("relay-mismatch.bin");
        std::fs::write(&fpath, b"relay check")?;
        let cfg_a = make_cfg_json(&srv.url, &relay_a.url, true, false);
        let cfg_b = make_cfg_json(&srv.url, &relay_b.url, true, false);
        let s = start_send_files(&cfg_a, &[fpath.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(s.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?;
        let r = start_receive_connect(&cfg_b, code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(10))?;
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorConnect")
        );
        assert_eq!(rf.get("cause").and_then(Value::as_str), Some("causeRelay"));
        assert!(
            rf.get("cause_detail")
                .and_then(Value::as_str)
                .is_some_and(|x| !x.is_empty())
        );
    }

    // (a5) causeConnectionLost: mid-transfer QUIC connection close
    {
        let (code_tx, code_rx) = oneshot::channel();
        let rdv_url = srv.url.clone();
        let task = TEST_RUNTIME.spawn(async move {
            let _ = run_fault_sender(rdv_url, SenderFault::ResetMidTransfer, code_tx).await;
        });
        let code = TEST_RUNTIME
            .block_on(async { tokio::time::timeout(Duration::from_secs(10), code_rx).await })??;
        let r = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let _ = wait_for_event(r.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
        let dest = tmp.path().join("dest-reset");
        std::fs::create_dir_all(&dest)?;
        assert_eq!(accept_files(r.id(), &dest)?, FFI_OK);
        let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
        task.abort();
        assert_eq!(
            rf.get("cause").and_then(Value::as_str),
            Some("causeConnectionLost")
        );
        assert!(
            rf.get("cause_detail")
                .and_then(Value::as_str)
                .is_some_and(|x| !x.is_empty())
        );
    }

    // (a6) causeProtocol: unsupported protocol version in Hints
    {
        let (code_tx, code_rx) = oneshot::channel();
        let rdv_url = srv.url.clone();
        let task = TEST_RUNTIME.spawn(async move {
            let _ =
                run_fault_sender(rdv_url, SenderFault::UnsupportedProtocolVersion, code_tx).await;
        });
        let code = TEST_RUNTIME
            .block_on(async { tokio::time::timeout(Duration::from_secs(10), code_rx).await })??;
        let r = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
        task.abort();
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorOther")
        );
        assert_eq!(
            rf.get("cause").and_then(Value::as_str),
            Some("causeProtocol")
        );
        assert!(
            rf.get("cause_detail")
                .and_then(Value::as_str)
                .is_some_and(|x| !x.is_empty())
        );
    }

    // (b) All 10 cause* keys via totaldrop_win_format_message_json in en-US and tr-TR.
    const ALL_CAUSES: [&str; 10] = [
        "causeTimedOut",
        "causeConnectionLost",
        "causeNoRoute",
        "causeRelay",
        "causeProtocol",
        "causeDiskFull",
        "causeNoPermission",
        "causeNotFound",
        "causeReadOnly",
        "causeFileChanged",
    ];
    let empty_args = c_str("{}")?;
    for (lang, region) in [("en-US", "en-US"), ("tr-TR", "tr-TR")] {
        let lang_c = c_str(lang)?;
        let reg_c = c_str(region)?;
        for cause_key in ALL_CAUSES {
            let key_c = c_str(cause_key)?;
            // SAFETY: All four pointers are live NUL-terminated CStrings.
            let val = take_json(unsafe {
                totaldrop_win_format_message_json(
                    key_c.as_ptr(),
                    empty_args.as_ptr(),
                    lang_c.as_ptr(),
                    reg_c.as_ptr(),
                )
            })?;
            assert_direct_dto_ok(&val)?;
            let formatted = val
                .get("formatted")
                .and_then(Value::as_str)
                .ok_or("missing formatted")?;
            assert!(
                !formatted.is_empty() && formatted != cause_key,
                "invalid localized string for {cause_key} in {lang}: {formatted:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn t2_f08_01_invalid_server_url_empty_ws_scheme() -> TestResult {
    // Offline string validation only — zero sockets opened.
    for invalid in [
        "wss://",
        "",
        "wss://rendezvous.totaldrop.app /bad",
        "http://127.0.0.1:4000",
    ] {
        let url_c = c_str(invalid)?;
        // SAFETY: `url_c` is a live NUL-terminated CString.
        let val = take_json(unsafe { totaldrop_win_validate_server_url_json(url_c.as_ptr()) })?;
        assert_error_envelope(&val, Some("bad_server"), Some("errorBadServer"))?;
    }
    Ok(())
}

#[test]
fn t2_f08_02_userinfo_spoofing_urls_api_and_sessions() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let tmp = TempDirGuard::new("t2-f08-02")?;
    let existing = tmp.path().join("existing.txt");
    std::fs::write(&existing, b"data")?;

    // Offline string validation & offline-rejected session start — zero sockets opened.
    for url in [
        "wss://user@rendezvous.totaldrop.app",
        "wss://user:pass@rendezvous.totaldrop.app",
        "ws://localhost@evil.example:4000",
    ] {
        // (a) validate_server_url_json
        let url_c = c_str(url)?;
        // SAFETY: `url_c` is a live NUL-terminated CString.
        let val = take_json(unsafe { totaldrop_win_validate_server_url_json(url_c.as_ptr()) })?;
        assert_error_envelope(&val, Some("bad_server"), Some("errorBadServer"))?;

        // (b) send_files_start & receive_connect_start reject offline before opening sockets
        let cfg = make_cfg_json(url, "", false, false);
        let s = start_send_files(&cfg, &[existing.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            sf.get("l10n_key").and_then(Value::as_str),
            Some("errorBadServer")
        );
        assert!(
            sf.get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|m| m.contains("the server address must not contain a user name")),
            "unexpected sender technical_english for {url:?}: {sf}"
        );

        let r = start_receive_connect(&cfg, "7-harbor-rocket", "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorBadServer")
        );
        assert!(
            rf.get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|m| m.contains("the server address must not contain a user name")),
            "unexpected receiver technical_english for {url:?}: {rf}"
        );
    }
    Ok(())
}

#[test]
fn t2_f08_03_non_loopback_ws_spoofing_urls_api_and_sessions() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let tmp = TempDirGuard::new("t2-f08-03")?;
    let existing = tmp.path().join("existing.txt");
    std::fs::write(&existing, b"data")?;

    for url in [
        "ws://127.0.0.1.evil.com:4000",
        "ws://localhost.evil.com:4000",
        "ws://192.168.1.10:4000",
        "ws://0.0.0.0:4000",
    ] {
        // (a) validate_server_url_json
        let url_c = c_str(url)?;
        // SAFETY: `url_c` is a live NUL-terminated CString.
        let val = take_json(unsafe { totaldrop_win_validate_server_url_json(url_c.as_ptr()) })?;
        assert_error_envelope(&val, Some("bad_server"), Some("errorBadServer"))?;

        // (b) send_files_start & receive_connect_start reject offline
        let cfg = make_cfg_json(url, "", false, false);
        let s = start_send_files(&cfg, &[existing.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            sf.get("l10n_key").and_then(Value::as_str),
            Some("errorBadServer")
        );
        assert!(
            sf.get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|m| {
                    m.contains("unencrypted ws:// is only allowed for a server on this machine")
                }),
            "unexpected sender technical_english for {url:?}: {sf}"
        );

        let r = start_receive_connect(&cfg, "7-harbor-rocket", "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorBadServer")
        );
        assert!(
            rf.get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|m| {
                    m.contains("unencrypted ws:// is only allowed for a server on this machine")
                }),
            "unexpected receiver technical_english for {url:?}: {rf}"
        );
    }
    Ok(())
}

#[test]
fn t2_f08_04_aead_tamper_unknown_cause_and_auth_error() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let tmp = TempDirGuard::new("t2-f08-04")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let cfg = make_cfg_json(&srv.url, "", false, false);

    let (code_tx, code_rx) = oneshot::channel();
    let rdv_url = srv.url.clone();
    let task = TEST_RUNTIME.spawn(async move {
        let _ = run_fault_sender(rdv_url, SenderFault::TamperOfferAeadTag, code_tx).await;
    });
    let code = TEST_RUNTIME
        .block_on(async { tokio::time::timeout(Duration::from_secs(10), code_rx).await })??;

    let r = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
    task.abort();

    assert_eq!(
        rf.get("l10n_key").and_then(Value::as_str),
        Some("errorOther")
    );
    assert_eq!(rf.get("cause").and_then(Value::as_str), Some(""));
    assert!(
        rf.get("cause_detail").is_none_or(Value::is_null),
        "AEAD tamper must have null cause_detail (Cause::Unknown), got: {rf}"
    );
    assert!(
        rf.get("technical_english")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("message failed authentication")),
        "expected 'message failed authentication' in technical_english, got: {rf}"
    );
    assert_eq!(dir_entry_count(tmp.path())?, 0);
    Ok(())
}

#[test]
fn t2_f08_05_non_code_server_errors_closed_port_and_connect() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let tmp = TempDirGuard::new("t2-f08-05")?;
    let file = tmp.path().join("data.txt");
    std::fs::write(&file, b"hello")?;

    // Non-code-not-in-use server errors map strictly to errorServer for BOTH roles.
    for reason in [
        "rate limit exceeded",
        "server overloaded",
        "internal db timeout",
    ] {
        let srv = MockRendezvous::start(
            "127.0.0.1:0",
            RendezvousFault::AlwaysError(reason.to_owned()),
        )?;
        let cfg = make_cfg_json(&srv.url, "", false, false);

        let s = start_send_files(&cfg, &[file.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(10))?;
        assert_eq!(
            sf.get("l10n_key").and_then(Value::as_str),
            Some("errorServer")
        );
        assert!(
            sf.get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|x| x.contains(reason))
        );

        let r = start_receive_connect(&cfg, "7-harbor-rocket", "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(10))?;
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorServer")
        );
        assert!(
            rf.get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|x| x.contains(reason))
        );
    }

    // (a) Unbound / closed loopback rendezvous port -> errorServer
    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.local_addr()?.port()
    };
    let closed_cfg = make_cfg_json(&format!("ws://127.0.0.1:{closed_port}"), "", false, false);
    let r = start_receive_connect(&closed_cfg, "7-harbor-rocket", "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(10))?;
    assert_eq!(
        rf.get("l10n_key").and_then(Value::as_str),
        Some("errorServer")
    );

    // (b1) privacy_relay_only: true with relay_server: "" -> errorConnect
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let no_relay_cfg = make_cfg_json(&srv.url, "", true, false);
    let s1 = start_send_files(&no_relay_cfg, &[file.as_path()], "en-US", "en-US")?;
    let mut s1_ev = Vec::new();
    let cr1 = wait_for_event(s1.id(), &mut s1_ev, "code_ready", Duration::from_secs(10))?;
    let code1 = cr1
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?;
    let r1 = start_receive_connect(&no_relay_cfg, code1, "en-US", "en-US")?;
    let mut r1_ev = Vec::new();
    let rf1 = wait_for_event(r1.id(), &mut r1_ev, "failed", Duration::from_secs(10))?;
    assert_eq!(
        rf1.get("l10n_key").and_then(Value::as_str),
        Some("errorConnect")
    );
    assert!(
        rf1.get("summary")
            .and_then(Value::as_str)
            .is_some_and(|x| !x.is_empty())
    );
    assert!(
        rf1.get("technical_english")
            .and_then(Value::as_str)
            .is_some_and(|x| !x.is_empty())
    );

    // (b2) Architecture B loopback relay closing before challenge -> errorConnect
    let drop_relay = MockRelay::start(RelayMode::DropOnConnect)?;
    let drop_cfg = make_cfg_json(&srv.url, &drop_relay.url, true, false);
    let s2 = start_send_files(&drop_cfg, &[file.as_path()], "en-US", "en-US")?;
    let mut s2_ev = Vec::new();
    let cr2 = wait_for_event(s2.id(), &mut s2_ev, "code_ready", Duration::from_secs(10))?;
    let code2 = cr2
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code2")?;
    let r2 = start_receive_connect(&drop_cfg, code2, "en-US", "en-US")?;
    let mut r2_ev = Vec::new();
    let rf2 = wait_for_event(r2.id(), &mut r2_ev, "failed", Duration::from_secs(30))?;
    assert_eq!(
        rf2.get("l10n_key").and_then(Value::as_str),
        Some("errorConnect")
    );
    assert!(
        rf2.get("summary")
            .and_then(Value::as_str)
            .is_some_and(|x| !x.is_empty())
    );
    assert!(
        rf2.get("technical_english")
            .and_then(Value::as_str)
            .is_some_and(|x| !x.is_empty())
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// F09 (M2): Full Async Transfer Lifecycle FFI (12 tests)

#[test]
fn t1_f09_01_loopback_file_transfer_256kib() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t1-f09-01")?;

    let payload = pseudo_random_bytes(901, 256 * 1024);
    let src_file = tmp.path().join("blob256.bin");
    std::fs::write(&src_file, &payload)?;
    let dest_dir = tmp.path().join("dest");
    std::fs::create_dir_all(&dest_dir)?;

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_files(&cfg, &[src_file.as_path()], "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing display_english")?
        .to_owned();
    let _ = wait_for_event(send.id(), &mut s_ev, "waiting", Duration::from_secs(10))?;

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    assert!(
        recv.id() > send.id(),
        "handles must be monotonic non-zero u64s"
    );

    let mut r_ev = Vec::new();
    let offer = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    let conn = wait_for_event(send.id(), &mut s_ev, "connected", Duration::from_secs(15))?;
    assert_eq!(
        conn.get("verification_words"),
        offer.get("verification_words"),
        "sender and receiver 4 English SAS words must match identically"
    );
    let words = offer
        .get("verification_words")
        .and_then(Value::as_array)
        .ok_or("missing verification_words")?;
    assert_eq!(words.len(), 4);

    assert_eq!(accept_files(recv.id(), &dest_dir)?, FFI_OK);
    let r_done = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(20))?;
    let s_done = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(20))?;
    assert_eq!(r_done.get("files_ok").and_then(Value::as_u64), Some(1));
    assert_eq!(s_done.get("files_ok").and_then(Value::as_u64), Some(1));
    assert!(
        s_ev.iter()
            .any(|e| e.get("event").and_then(Value::as_str) == Some("progress"))
    );
    assert!(
        r_ev.iter()
            .any(|e| e.get("event").and_then(Value::as_str) == Some("progress"))
    );

    let received = std::fs::read(dest_dir.join("blob256.bin"))?;
    assert_eq!(blake3::hash(&received), blake3::hash(&payload));
    assert!(!has_part_files(&dest_dir)?);

    let send_id = send.id();
    let recv_id = recv.id();
    std::mem::forget(send);
    std::mem::forget(recv);
    assert_eq!(totaldrop_win_session_destroy(send_id), FFI_OK);
    assert_eq!(totaldrop_win_session_destroy(recv_id), FFI_OK);
    Ok(())
}

#[test]
fn t1_f09_02_loopback_text_transfer_in_memory() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t1-f09-02")?;
    let empty_dir = tmp.path().join("recv-dir");
    std::fs::create_dir_all(&empty_dir)?;

    let message = "Hello TotalDrop \u{1F680}\nLine 2";
    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_text(&cfg, message, "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    assert_eq!(cr.get("is_text").and_then(Value::as_bool), Some(true));
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing display_english")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let offer = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(offer.get("is_text").and_then(Value::as_bool), Some(true));

    assert_eq!(totaldrop_win_receive_accept_text(recv.id()), FFI_OK);
    let r_done = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(15))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(15))?;
    assert_eq!(
        r_done.get("received_text").and_then(Value::as_str),
        Some(message)
    );
    assert_eq!(dir_entry_count(&empty_dir)?, 0);
    Ok(())
}

#[test]
fn t1_f09_03_loopback_receiver_decline() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t1-f09-03")?;
    let src = tmp.path().join("decline64k.bin");
    std::fs::write(&src, pseudo_random_bytes(903, 64 * 1024))?;
    let dest = tmp.path().join("dest");
    std::fs::create_dir_all(&dest)?;

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_files(&cfg, &[src.as_path()], "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;

    assert_eq!(totaldrop_win_receive_decline(recv.id()), FFI_OK);
    let r_dec = wait_for_event(recv.id(), &mut r_ev, "declined", Duration::from_secs(10))?;
    assert_eq!(r_dec.get("event").and_then(Value::as_str), Some("declined"));

    let s_fail = wait_for_event(send.id(), &mut s_ev, "failed", Duration::from_secs(15))?;
    assert_eq!(
        s_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorDeclined")
    );
    assert_eq!(dir_entry_count(&dest)?, 0);
    Ok(())
}

#[test]
fn t1_f09_04_loopback_throttled_sender_cancel_cleanup() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let relay = MockRelay::start(RelayMode::Throttled(Duration::from_millis(2)))?;
    let tmp = TempDirGuard::new("t1-f09-04")?;
    let src = tmp.path().join("cancel2m.bin");
    std::fs::write(&src, pseudo_random_bytes(904, 2 * 1024 * 1024))?;
    let dest = tmp.path().join("dest");
    std::fs::create_dir_all(&dest)?;

    let cfg = make_cfg_json(&srv.url, &relay.url, true, false);
    let send = start_send_files(&cfg, &[src.as_path()], "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(accept_files(recv.id(), &dest)?, FFI_OK);

    let _ = wait_for_event(send.id(), &mut s_ev, "progress", Duration::from_secs(15))?;
    assert_eq!(totaldrop_win_session_cancel(send.id()), FFI_OK);

    let sf = wait_for_event(send.id(), &mut s_ev, "failed", Duration::from_secs(15))?;
    let rf = wait_for_event(recv.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
    assert_eq!(
        sf.get("l10n_key").and_then(Value::as_str),
        Some("errorStopped")
    );
    assert_eq!(
        rf.get("l10n_key").and_then(Value::as_str),
        Some("errorCancelled")
    );
    assert!(!has_part_files(&dest)?);
    Ok(())
}

#[test]
fn t1_f09_05_privacy_relay_only_stronger_3_word_512kib() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let relay = LoopbackRelay::start()?;
    let tmp = TempDirGuard::new("t1-f09-05")?;
    let payload = pseudo_random_bytes(905, 512 * 1024);
    let src = tmp.path().join("relay512k.bin");
    std::fs::write(&src, &payload)?;
    let dest = tmp.path().join("dest");
    std::fs::create_dir_all(&dest)?;

    let cfg = make_cfg_json(srv.url(), relay.url(), true, true);
    let send = start_send_files(&cfg, &[src.as_path()], "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    assert_eq!(
        cr.get("code")
            .and_then(|c| c.get("word_count"))
            .and_then(Value::as_u64),
        Some(3)
    );
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(accept_files(recv.id(), &dest)?, FFI_OK);
    let _ = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(20))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(20))?;

    let got = std::fs::read(dest.join("relay512k.bin"))?;
    assert_eq!(blake3::hash(&got), blake3::hash(&payload));
    Ok(())
}

#[test]
fn t1_f09_06_shutdown_drain_active_and_idle() -> TestResult {
    let _guard = SHUTDOWN_GATE.write().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let tmp = TempDirGuard::new("t1-f09-06")?;
    let src = tmp.path().join("active.bin");
    std::fs::write(&src, b"active waiting session")?;

    let cfg = make_cfg_json(&srv.url, "", false, false);
    let send = start_send_files(&cfg, &[src.as_path()], "en-US", "en-US")?;
    let sid = send.id();
    let mut s_ev = Vec::new();
    let _ = wait_for_event(sid, &mut s_ev, "waiting", Duration::from_secs(10))?;

    let t0 = Instant::now();
    let rc_active = totaldrop_win_shutdown(1500);
    let elapsed_active = t0.elapsed();
    assert_eq!(rc_active, FFI_OK);
    assert!(
        elapsed_active <= Duration::from_millis(3500),
        "active shutdown exceeded 3500ms: {elapsed_active:?}"
    );

    // Subsequent poll on drained handle must report invalid_handle (zero leaked handles).
    let poll_after = take_json(totaldrop_win_session_poll_events_ndjson(sid))?;
    assert_error_envelope(&poll_after, Some("invalid_handle"), Some("errorOther"))?;
    std::mem::forget(send);

    // Idle shutdown must complete in < 100 ms.
    let t1 = Instant::now();
    let rc_idle = totaldrop_win_shutdown(1500);
    let elapsed_idle = t1.elapsed();
    assert_eq!(rc_idle, FFI_OK);
    assert!(
        elapsed_idle < Duration::from_millis(100),
        "idle shutdown took {elapsed_idle:?}, expected < 100 ms"
    );
    Ok(())
}

#[test]
fn t2_f09_01_text_damaged_corrupt_blake3_and_invalid_utf8() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let cfg = make_cfg_json(&srv.url, "", false, false);

    for fault in [
        SenderFault::CorruptTextBlake3Hash,
        SenderFault::InvalidUtf8TextPayload,
    ] {
        let tmp = TempDirGuard::new("t2-f09-01")?;
        let (code_tx, code_rx) = oneshot::channel();
        let rdv_url = srv.url.clone();
        let task = TEST_RUNTIME.spawn(async move {
            let _ = run_fault_sender(rdv_url, fault, code_tx).await;
        });
        let code = TEST_RUNTIME
            .block_on(async { tokio::time::timeout(Duration::from_secs(10), code_rx).await })??;

        let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let offer = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
        assert_eq!(offer.get("is_text").and_then(Value::as_bool), Some(true));
        assert_eq!(totaldrop_win_receive_accept_text(recv.id()), FFI_OK);

        let fail = wait_for_event(recv.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
        task.abort();
        assert_eq!(
            fail.get("kind").and_then(Value::as_str),
            Some("text_damaged")
        );
        assert_eq!(
            fail.get("l10n_key").and_then(Value::as_str),
            Some("errorTextDamaged")
        );
        assert!(fail.get("received_text").is_none_or(Value::is_null));
        assert_eq!(dir_entry_count(tmp.path())?, 0);
    }
    Ok(())
}

#[test]
fn t2_f09_02_wrong_code_cpace_scary_retirement() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t2-f09-02")?;
    let src = tmp.path().join("secret.bin");
    std::fs::write(&src, b"never delivered")?;
    let dest = tmp.path().join("dest");
    std::fs::create_dir_all(&dest)?;

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_files(&cfg, &[src.as_path()], "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let nameplate = cr
        .get("code")
        .and_then(|c| c.get("nameplate"))
        .and_then(Value::as_u64)
        .ok_or("missing nameplate")?;
    let actual_code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();
    let mut wrong_code = format!("{nameplate}-harbor-wrong");
    if wrong_code == actual_code {
        wrong_code = format!("{nameplate}-zoo-zone");
    }

    let recv = start_receive_connect(&cfg, &wrong_code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let rf = wait_for_event(recv.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
    let sf = wait_for_event(send.id(), &mut s_ev, "failed", Duration::from_secs(15))?;
    assert_eq!(
        rf.get("l10n_key").and_then(Value::as_str),
        Some("errorWrongCode")
    );
    assert_eq!(
        sf.get("l10n_key").and_then(Value::as_str),
        Some("errorWrongCode")
    );
    assert_eq!(dir_entry_count(&dest)?, 0);

    // Subsequent receiver trying the REAL code on the same nameplate must fail
    // because the nameplate was retired (`Mood::Scary`).
    let retry = start_receive_connect(&cfg, &actual_code, "en-US", "en-US")?;
    let mut retry_ev = Vec::new();
    let retry_fail = wait_for_event(retry.id(), &mut retry_ev, "failed", Duration::from_secs(10))?;
    assert_eq!(
        retry_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorCodeNotInUse")
    );
    Ok(())
}

#[test]
fn t2_f09_03_invalid_and_double_destroyed_handles() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;

    let poll_zero = take_json(totaldrop_win_session_poll_events_ndjson(0))?;
    assert_error_envelope(&poll_zero, Some("invalid_handle"), Some("errorOther"))?;
    assert_eq!(totaldrop_win_session_cancel(0), FFI_ERR_INVALID_HANDLE);
    assert_eq!(totaldrop_win_session_destroy(0), FFI_ERR_INVALID_HANDLE);

    let tmp_dir = c_str("/tmp")?;
    // SAFETY: `tmp_dir` is a live NUL-terminated CString.
    let rc_invalid_accept =
        unsafe { totaldrop_win_receive_accept_files(999_999, tmp_dir.as_ptr()) };
    assert_eq!(rc_invalid_accept, FFI_ERR_INVALID_HANDLE);
    assert_eq!(
        totaldrop_win_receive_accept_text(999_999),
        FFI_ERR_INVALID_HANDLE
    );
    assert_eq!(
        totaldrop_win_receive_decline(999_999),
        FFI_ERR_INVALID_HANDLE
    );

    // Create valid session, destroy twice, then cancel.
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let cfg = make_cfg_json(&srv.url, "", false, false);
    let session = start_send_text(&cfg, "handle test", "en-US", "en-US")?;
    let sid = session.id();
    std::mem::forget(session);

    assert_eq!(totaldrop_win_session_destroy(sid), FFI_OK);
    assert_eq!(totaldrop_win_session_destroy(sid), FFI_ERR_INVALID_HANDLE);
    assert_eq!(totaldrop_win_session_cancel(sid), FFI_ERR_INVALID_HANDLE);
    let poll_gone = take_json(totaldrop_win_session_poll_events_ndjson(sid))?;
    assert_error_envelope(&poll_gone, Some("invalid_handle"), Some("errorOther"))?;
    Ok(())
}

#[test]
fn t2_f09_04_send_files_and_text_immediate_rejections() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let tmp = TempDirGuard::new("t2-f09-04")?;
    let existing = tmp.path().join("exists.txt");
    std::fs::write(&existing, b"x")?;
    let cfg = make_cfg_json(&srv.url, "", false, false);

    // 1. Empty path list "[]"
    {
        let s = start_send_files(&cfg, &[], "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            f.get("l10n_key").and_then(Value::as_str),
            Some("errorInvalidOffer")
        );
    }

    // 2. Nonexistent file path
    {
        let missing = tmp.path().join("nope.bin");
        let s = start_send_files(&cfg, &[missing.as_path()], "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            f.get("l10n_key").and_then(Value::as_str),
            Some("errorStorage")
        );
    }

    // 3. Invalid server URL "http://bad" with existing file
    {
        let bad_cfg = make_cfg_json("http://bad", "", false, false);
        let s = start_send_files(&bad_cfg, &[existing.as_path()], "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            f.get("l10n_key").and_then(Value::as_str),
            Some("errorBadServer")
        );
    }

    // 4. Empty text ""
    {
        let s = start_send_text(&cfg, "", "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            f.get("l10n_key").and_then(Value::as_str),
            Some("errorInvalidOffer")
        );
    }

    // 5. Oversized text 1_048_577 bytes (1 MiB + 1 B)
    {
        let huge = "a".repeat(1_048_577);
        let s = start_send_text(&cfg, &huge, "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            f.get("l10n_key").and_then(Value::as_str),
            Some("sendTextTooLong")
        );
    }

    // 6. Invalid cfg JSON returns 0 immediately (no handle leak)
    let bad_json = c_str("{not-json")?;
    let empty_text = c_str("hello")?;
    let en = c_str("en-US")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let zero_sid = unsafe {
        totaldrop_win_send_text_start(
            bad_json.as_ptr(),
            empty_text.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    assert_eq!(zero_sid, 0);
    Ok(())
}

#[test]
fn t2_f09_05_privacy_relay_drop_and_cause_relay() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let tmp = TempDirGuard::new("t2-f09-05")?;
    let src = tmp.path().join("relay.bin");
    std::fs::write(&src, b"privacy relay test")?;

    // Part 1: Deterministic `< 1 s` mismatched privacy relay -> errorConnect + causeRelay.
    {
        let relay_a = MockRelay::start(RelayMode::Normal)?;
        let relay_b = MockRelay::start(RelayMode::Normal)?;
        let cfg_a = make_cfg_json(&srv.url, &relay_a.url, true, false);
        let cfg_b = make_cfg_json(&srv.url, &relay_b.url, true, false);

        let send = start_send_files(&cfg_a, &[src.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?
            .to_owned();

        let recv = start_receive_connect(&cfg_b, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let rf = wait_for_event(recv.id(), &mut r_ev, "failed", Duration::from_secs(10))?;
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorConnect")
        );
        assert_eq!(rf.get("cause").and_then(Value::as_str), Some("causeRelay"));
    }

    // Part 2: Genuine Architecture B DropOnConnect relay under privacy_relay_only == true
    // terminates cleanly within timeout emitting errorConnect.
    {
        let drop_relay = MockRelay::start(RelayMode::DropOnConnect)?;
        let cfg = make_cfg_json(&srv.url, &drop_relay.url, true, false);
        let send = start_send_files(&cfg, &[src.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?
            .to_owned();

        let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let rf = wait_for_event(recv.id(), &mut r_ev, "failed", Duration::from_secs(30))?;
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorConnect")
        );
    }
    Ok(())
}

#[test]
fn t2_f09_06_silent_peer_shutdown_abort_and_idempotent_second_call() -> TestResult {
    let _guard = SHUTDOWN_GATE.write().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let tmp = TempDirGuard::new("t2-f09-06")?;
    let dest = tmp.path().join("dest");
    std::fs::create_dir_all(&dest)?;

    let (code_tx, code_rx) = oneshot::channel();
    let rdv_url = srv.url.clone();
    let task = TEST_RUNTIME.spawn(async move {
        let _ = run_fault_sender(rdv_url, SenderFault::SilentStallAfterDataHeader, code_tx).await;
    });
    let code = TEST_RUNTIME
        .block_on(async { tokio::time::timeout(Duration::from_secs(10), code_rx).await })??;

    let cfg = make_cfg_json(&srv.url, "", false, false);
    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(accept_files(recv.id(), &dest)?, FFI_OK);

    // Wait until receiver has created `.totaldrop-*.part` on disk and written chunk 0.
    let _ = wait_for_event(recv.id(), &mut r_ev, "progress", Duration::from_secs(15))?;
    let wait_part_start = Instant::now();
    while !has_part_files(&dest)? {
        if wait_part_start.elapsed() > Duration::from_secs(5) {
            task.abort();
            return Err("expected .totaldrop-*.part file on disk during stalled receive".into());
        }
        std::thread::sleep(Duration::from_millis(15));
    }

    let t0 = Instant::now();
    let rc1 = totaldrop_win_shutdown(1500);
    let elapsed1 = t0.elapsed();
    task.abort();
    std::mem::forget(recv);

    assert_eq!(rc1, FFI_OK);
    assert!(
        elapsed1 <= Duration::from_millis(3500),
        "silent-peer shutdown exceeded 3500 ms bound: {elapsed1:?}"
    );
    assert!(
        !has_part_files(&dest)?,
        "partial .totaldrop-*.part file must be removed by shutdown abort unwind"
    );

    // Second shutdown immediately afterward must return 0 idempotently in < 50 ms.
    let t1 = Instant::now();
    let rc2 = totaldrop_win_shutdown(1500);
    let elapsed2 = t1.elapsed();
    assert_eq!(rc2, FFI_OK);
    assert!(
        elapsed2 < Duration::from_millis(50),
        "second shutdown took {elapsed2:?}, expected < 50 ms"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// F10 (M2): End-to-End SendPage (9 Rust cross-platform tests)

#[test]
fn t1_f10_01_validate_paths_mixed_drive_forward_unc_dedup() -> TestResult {
    let paths_json = serde_json::to_string(&[
        r"C:\Users\Alice\report.pdf",
        "d:/media/clip.mp4",
        r"\\nas01\team\spec.docx",
        r"c:\users\alice\REPORT.PDF",
    ])?;
    let paths_c = c_str(&paths_json)?;
    // SAFETY: `paths_c` is a live NUL-terminated CString.
    let val = take_json(unsafe { totaldrop_win_validate_paths_json(paths_c.as_ptr()) })?;
    assert_direct_dto_ok(&val)?;
    let arr = val.as_array().ok_or("expected JSON array")?;
    assert_eq!(arr.len(), 3);
    assert_eq!(
        arr.first()
            .and_then(|v| v.get("extended_path"))
            .and_then(Value::as_str),
        Some(r"\\?\C:\Users\Alice\report.pdf")
    );
    assert_eq!(
        arr.get(1)
            .and_then(|v| v.get("extended_path"))
            .and_then(Value::as_str),
        Some(r"\\?\D:\media\clip.mp4")
    );
    assert_eq!(
        arr.get(2)
            .and_then(|v| v.get("extended_path"))
            .and_then(Value::as_str),
        Some(r"\\?\UNC\nas01\team\spec.docx")
    );
    Ok(())
}

#[test]
fn t1_f10_02_send_nested_dir_3_files_zero_byte_and_utf8() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t1-f10-02")?;

    // Strict nested directory: 2 dirs (`bundle`, `bundle/sub`) + 3 files (incl. 0-byte & `rapor-2026.txt`).
    let bundle = tmp.path().join("src").join("bundle");
    let sub = bundle.join("sub");
    std::fs::create_dir_all(&sub)?;
    let empty_bytes: &[u8] = b"";
    let rapor_bytes: &[u8] = "Türkiye 2026 raporu — UTF-8 içerik".as_bytes();
    let third_bytes = pseudo_random_bytes(1002, 4096);
    std::fs::write(bundle.join("empty.txt"), empty_bytes)?;
    std::fs::write(bundle.join("rapor-2026.txt"), rapor_bytes)?;
    std::fs::write(sub.join("third.bin"), &third_bytes)?;
    let expected_total =
        u64::try_from(rapor_bytes.len())?.saturating_add(u64::try_from(third_bytes.len())?);

    let dest = tmp.path().join("dest");
    std::fs::create_dir_all(&dest)?;

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_files(&cfg, &[bundle.as_path()], "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;

    // STRICT UNWEAKENED ORACLE on sender `code_ready`:
    assert_eq!(cr.get("files").and_then(Value::as_u64), Some(3));
    assert_eq!(cr.get("dirs").and_then(Value::as_u64), Some(2));
    assert_eq!(
        cr.get("total_bytes").and_then(Value::as_u64),
        Some(expected_total)
    );
    let code_obj = cr.get("code").ok_or("missing code object")?;
    let code = code_obj
        .get("display_english")
        .and_then(Value::as_str)
        .ok_or("missing display_english")?
        .to_owned();
    assert_eq!(
        code_obj.get("ltr_isolated").and_then(Value::as_str),
        Some(format!("\u{2068}{code}\u{2069}").as_str())
    );
    // Offline string validation check only — zero network connection.
    assert_eq!(
        code_obj.get("web_uri").and_then(Value::as_str),
        Some(format!("https://totaldrop.app/r#{code}").as_str())
    );

    let waiting = wait_for_event(send.id(), &mut s_ev, "waiting", Duration::from_secs(10))?;
    assert!(
        waiting
            .get("caption")
            .and_then(Value::as_str)
            .is_some_and(|c| !c.is_empty())
    );

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let offer = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(offer.get("files").and_then(Value::as_u64), Some(3));
    assert_eq!(offer.get("dirs").and_then(Value::as_u64), Some(2));
    assert_eq!(
        offer.get("total_bytes").and_then(Value::as_u64),
        Some(expected_total)
    );

    assert_eq!(accept_files(recv.id(), &dest)?, FFI_OK);
    let _ = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(20))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(20))?;

    assert_eq!(
        std::fs::read(dest.join("bundle").join("empty.txt"))?,
        empty_bytes
    );
    assert_eq!(
        std::fs::read(dest.join("bundle").join("rapor-2026.txt"))?,
        rapor_bytes
    );
    assert_eq!(
        blake3::hash(&std::fs::read(
            dest.join("bundle").join("sub").join("third.bin")
        )?),
        blake3::hash(&third_bytes)
    );
    Ok(())
}

#[test]
fn t1_f10_03_send_4096_byte_text_2_word_and_sas_words() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let note = "A".repeat(4096);
    assert_eq!(note.len(), 4096);

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_text(&cfg, &note, "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    assert_eq!(cr.get("total_bytes").and_then(Value::as_u64), Some(4096));
    assert_eq!(
        cr.get("code")
            .and_then(|c| c.get("word_count"))
            .and_then(Value::as_u64),
        Some(2)
    );
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    let conn = wait_for_event(send.id(), &mut s_ev, "connected", Duration::from_secs(15))?;
    let words = conn
        .get("verification_words")
        .and_then(Value::as_array)
        .ok_or("missing verification_words")?;
    assert_eq!(words.len(), 4);
    let expected_joined = words
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("  ");
    let joined_ltr = conn
        .get("joined_words_ltr")
        .and_then(Value::as_str)
        .ok_or("missing joined_words_ltr")?;
    assert!(joined_ltr.contains(&expected_joined));

    assert_eq!(totaldrop_win_receive_accept_text(recv.id()), FFI_OK);
    let r_done = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(15))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(15))?;
    assert_eq!(
        r_done.get("received_text").and_then(Value::as_str),
        Some(note.as_str())
    );
    Ok(())
}

#[test]
fn t1_f10_04_progress_ticks_throttled_tr_tr_floor_percent() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let relay = MockRelay::start(RelayMode::ThrottledStride {
        every_n: 64,
        delay: Duration::from_millis(16),
    })?;
    let tmp = TempDirGuard::new("t1-f10-04")?;
    // 3 MiB payload (3 x 1 MiB chunks) ensures genuine intermediate 1..=99% progress ticks.
    let payload = pseudo_random_bytes(1004, 3 * 1024 * 1024);
    let src = tmp.path().join("three-mib.bin");
    std::fs::write(&src, &payload)?;
    let dest = tmp.path().join("dest");
    std::fs::create_dir_all(&dest)?;

    let cfg = make_cfg_json(&srv.url, &relay.url, true, false);
    let send = start_send_files(&cfg, &[src.as_path()], "tr-TR", "tr-TR")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "tr-TR", "tr-TR")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(accept_files(recv.id(), &dest)?, FFI_OK);
    let _ = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(40))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(40))?;

    let total_u64 = u64::try_from(payload.len())?;
    let mut prev_done = 0u64;
    let mut saw_intermediate = false;
    let mut saw_100 = false;
    for ev in s_ev
        .iter()
        .filter(|e| e.get("event").and_then(Value::as_str) == Some("progress"))
    {
        let done = ev
            .get("done_bytes")
            .and_then(Value::as_u64)
            .ok_or("missing done_bytes")?;
        let pct = ev.get("percent").ok_or("missing percent")?;
        let whole = pct
            .get("whole")
            .and_then(Value::as_u64)
            .ok_or("missing whole")?;
        let formatted = pct
            .get("formatted")
            .and_then(Value::as_str)
            .ok_or("missing formatted")?;
        assert!(done >= prev_done, "progress done_bytes must be monotonic");
        prev_done = done;
        assert!(
            formatted.starts_with('%'),
            "tr-TR percent must start with '%', got {formatted:?}"
        );
        assert!(
            ev.get("formatted_done")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        );
        assert!(
            ev.get("formatted_total")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        );
        if done < total_u64 {
            assert!(
                whole <= 99,
                "#483 floor: 100% must never appear while done < total"
            );
            if whole >= 1 {
                saw_intermediate = true;
            }
        } else if whole == 100 {
            saw_100 = true;
        }
    }
    assert!(
        saw_intermediate,
        "expected real intermediate 1..=99% progress ticks"
    );
    assert!(saw_100, "expected final 100% completion tick");
    Ok(())
}

#[test]
fn t2_f10_01_max_text_utf8_byte_boundaries_ascii_and_turkish() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let cfg = make_cfg_json(&srv.url, "", false, false);

    // 1. Exact 1_048_576 B ASCII -> succeeds (`code_ready`)
    let exact_ascii = "a".repeat(1_048_576);
    {
        let s = start_send_text(&cfg, &exact_ascii, "en-US", "en-US")?;
        let mut ev = Vec::new();
        let cr = wait_for_event(s.id(), &mut ev, "code_ready", Duration::from_secs(10))?;
        assert_eq!(
            cr.get("total_bytes").and_then(Value::as_u64),
            Some(1_048_576)
        );
    }

    // 2. 1_048_577 B ASCII -> fails with sendTextTooLong
    let over_ascii = "a".repeat(1_048_577);
    {
        let s = start_send_text(&cfg, &over_ascii, "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            f.get("l10n_key").and_then(Value::as_str),
            Some("sendTextTooLong")
        );
    }

    // 3. 524_288 * "ğ" (2 B UTF-8 each = 1_048_576 B) -> succeeds
    let exact_tr = "ğ".repeat(524_288);
    assert_eq!(exact_tr.len(), 1_048_576);
    {
        let s = start_send_text(&cfg, &exact_tr, "en-US", "en-US")?;
        let mut ev = Vec::new();
        let cr = wait_for_event(s.id(), &mut ev, "code_ready", Duration::from_secs(10))?;
        assert_eq!(
            cr.get("total_bytes").and_then(Value::as_u64),
            Some(1_048_576)
        );
    }

    // 4. 524_289 * "ğ" (1_048_578 B) -> fails with sendTextTooLong (proves UTF-8 byte counting)
    let over_tr = "ğ".repeat(524_289);
    assert_eq!(over_tr.len(), 1_048_578);
    {
        let s = start_send_text(&cfg, &over_tr, "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            f.get("l10n_key").and_then(Value::as_str),
            Some("sendTextTooLong")
        );
    }

    // 5. Empty "" -> refused (`errorInvalidOffer`)
    {
        let s = start_send_text(&cfg, "", "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            f.get("l10n_key").and_then(Value::as_str),
            Some("errorInvalidOffer")
        );
    }
    Ok(())
}

#[test]
fn t2_f10_02_unc_normalization_and_case_folding() -> TestResult {
    let paths_json = serde_json::to_string(&[
        r"\\server\share\a.txt",
        r"\\?\UNC\server\share\a.txt",
        r"\\SERVER\SHARE\A.TXT",
    ])?;
    let paths_c = c_str(&paths_json)?;
    // SAFETY: `paths_c` is a live NUL-terminated CString.
    let val = take_json(unsafe { totaldrop_win_validate_paths_json(paths_c.as_ptr()) })?;
    assert_direct_dto_ok(&val)?;
    let arr = val.as_array().ok_or("expected array")?;
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr.first()
            .and_then(|v| v.get("extended_path"))
            .and_then(Value::as_str),
        Some(r"\\?\UNC\server\share\a.txt")
    );
    Ok(())
}

#[test]
fn t2_f10_03_dangerous_drag_drop_paths_rejected() -> TestResult {
    for (bad_path, expected_kind) in [
        (r"C:\tmp\CON.txt", "device_namespace_forbidden"),
        ("C:\\tmp\\LPT\u{00B9}", "device_namespace_forbidden"),
        (
            r"C:\tmp\doc.pdf:Zone.Identifier",
            "forbidden_segment_character",
        ),
        (r"\\.\PhysicalDrive0", "device_namespace_forbidden"),
        (r"C:\tmp\..\secret.txt", "dot_traversal_segment"),
        (r"C:\tmp\trailing.", "trailing_dot_or_space"),
    ] {
        let json_str = serde_json::to_string(&[bad_path])?;
        let c = c_str(&json_str)?;
        // SAFETY: `c` is a live NUL-terminated CString.
        let val = take_json(unsafe { totaldrop_win_validate_paths_json(c.as_ptr()) })?;
        assert_error_envelope(&val, Some(expected_kind), Some("errorStorage"))?;
    }
    Ok(())
}

#[test]
fn t2_f10_04_20k_char_text_with_rlo_sanitized_preview_and_full_delivery() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;

    let mut text = String::with_capacity(20_100);
    text.push_str("prefix-\u{202E}rlo-");
    while text.chars().count() < 20_000 {
        text.push('x');
    }
    assert_eq!(text.chars().count(), 20_000);

    let text_c = c_str(&text)?;
    // SAFETY: `text_c` is a live NUL-terminated CString.
    let san = take_json(unsafe { totaldrop_win_sanitize_text_json(text_c.as_ptr()) })?;
    assert_direct_dto_ok(&san)?;
    assert_eq!(san.get("shortened").and_then(Value::as_bool), Some(true));
    assert_eq!(
        san.get("has_hidden_controls").and_then(Value::as_bool),
        Some(true)
    );
    let display = san
        .get("display_text")
        .and_then(Value::as_str)
        .ok_or("missing display_text")?;
    assert!(display.contains("<U+202E>"));
    assert_eq!(display.chars().count(), 16_384);

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_text(&cfg, &text, "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(totaldrop_win_receive_accept_text(recv.id()), FFI_OK);
    let r_done = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(15))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(15))?;
    let delivered = r_done
        .get("received_text")
        .and_then(Value::as_str)
        .ok_or("missing received_text")?;
    assert_eq!(delivered.chars().count(), 20_000);
    assert_eq!(delivered, text);
    Ok(())
}

#[test]
fn t2_f10_05_file_mutated_missing_and_unreadable_causes() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let tmp = TempDirGuard::new("t2-f10-05")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let cfg = make_cfg_json(&srv.url, "", false, false);

    // 1. Deleted between prepare (code_ready) and read -> errorStorage + causeNotFound
    {
        let victim = tmp.path().join("disappearing.bin");
        std::fs::write(&victim, vec![0x44u8; 4096])?;
        let send = start_send_files(&cfg, &[victim.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?
            .to_owned();
        std::fs::remove_file(&victim)?;
        let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
        let dest = tmp.path().join("dest-deleted");
        std::fs::create_dir_all(&dest)?;
        assert_eq!(accept_files(recv.id(), &dest)?, FFI_OK);
        let sf = wait_for_event(send.id(), &mut s_ev, "failed", Duration::from_secs(15))?;
        assert_eq!(
            sf.get("l10n_key").and_then(Value::as_str),
            Some("errorStorage")
        );
        assert_eq!(
            sf.get("cause").and_then(Value::as_str),
            Some("causeNotFound")
        );
    }

    // 2. Modified between prepare and read -> errorStorage + causeFileChanged
    {
        let mutating = tmp.path().join("mutating.bin");
        std::fs::write(&mutating, vec![0x77u8; 4096])?;
        let send = start_send_files(&cfg, &[mutating.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?
            .to_owned();
        std::fs::write(&mutating, b"changed-length")?;
        let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
        let dest = tmp.path().join("dest-mutated");
        std::fs::create_dir_all(&dest)?;
        assert_eq!(accept_files(recv.id(), &dest)?, FFI_OK);
        let sf = wait_for_event(send.id(), &mut s_ev, "failed", Duration::from_secs(15))?;
        assert_eq!(
            sf.get("l10n_key").and_then(Value::as_str),
            Some("errorStorage")
        );
        assert_eq!(
            sf.get("cause").and_then(Value::as_str),
            Some("causeFileChanged")
        );
    }

    // 3. Unreadable permission-denied file -> errorStorage + causeNoPermission
    #[cfg(unix)]
    {
        let locked = tmp.path().join("locked.bin");
        std::fs::write(&locked, b"secret")?;
        let _perm = ModeRestoreGuard::set(locked.clone(), 0o000, 0o600)?;
        let send = start_send_files(&cfg, &[locked.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let sf = wait_for_event(send.id(), &mut s_ev, "failed", Duration::from_secs(10))?;
        assert_eq!(
            sf.get("l10n_key").and_then(Value::as_str),
            Some("errorStorage")
        );
        assert_eq!(
            sf.get("cause").and_then(Value::as_str),
            Some("causeNoPermission")
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// F11 (M2): End-to-End ReceivePage (9 Rust cross-platform tests)

#[test]
fn t1_f11_01_code_completions_and_clipboard_extraction() -> TestResult {
    let prefix_c = c_str("har")?;
    // SAFETY: `prefix_c` is a live NUL-terminated CString.
    let comp = take_json(unsafe { totaldrop_win_code_completions_json(prefix_c.as_ptr(), 4) })?;
    let arr = comp.as_array().ok_or("expected JSON array")?;
    assert!(!arr.is_empty() && arr.len() <= 4);
    let mut found_harbor = false;
    for item in arr {
        let word = item.as_str().ok_or("expected string item")?;
        assert!(word.starts_with("har") && word.is_ascii() && word == word.to_ascii_lowercase());
        if word == "harbor" {
            found_harbor = true;
        }
    }
    assert!(
        found_harbor,
        "expected 'harbor' in completions for 'har': {comp}"
    );

    // Offline string extraction only — zero network connection.
    let clip_c = c_str("Download via https://totaldrop.app/r#7-harbor-rocket now")?;
    // SAFETY: `clip_c` is a live NUL-terminated CString.
    let extracted =
        take_json(unsafe { totaldrop_win_extract_clipboard_code_json(clip_c.as_ptr()) })?;
    assert_direct_dto_ok(&extracted)?;
    assert_eq!(
        extracted.get("display_english").and_then(Value::as_str),
        Some("7-harbor-rocket")
    );
    assert_eq!(extracted.get("nameplate").and_then(Value::as_u64), Some(7));
    assert_eq!(
        extracted.get("canonical").and_then(Value::as_str),
        Some("7-840-1499")
    );
    Ok(())
}

#[test]
fn t1_f11_02_receive_7_top_level_files_offer_overflow_and_sas() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t1-f11-02")?;

    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    for idx in 1usize..=7 {
        let p = tmp.path().join(format!("item-{idx:02}.txt"));
        let content = format!("file content #{idx}");
        total_bytes = total_bytes.saturating_add(u64::try_from(content.len())?);
        std::fs::write(&p, content)?;
        files.push(p);
    }
    let path_refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_files(&cfg, &path_refs, "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let offer = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    let conn = wait_for_event(send.id(), &mut s_ev, "connected", Duration::from_secs(15))?;

    assert_eq!(offer.get("files").and_then(Value::as_u64), Some(7));
    assert_eq!(offer.get("is_text").and_then(Value::as_bool), Some(false));
    assert_eq!(
        offer.get("total_bytes").and_then(Value::as_u64),
        Some(total_bytes)
    );
    assert_eq!(
        offer.get("verification_words"),
        conn.get("verification_words")
    );
    assert_eq!(offer.get("more_count").and_then(Value::as_u64), Some(2));
    let top_san = offer
        .get("top_level_sanitized")
        .and_then(Value::as_array)
        .ok_or("missing top_level_sanitized")?;
    assert_eq!(top_san.len(), 7);
    assert_eq!(totaldrop_win_receive_decline(recv.id()), FFI_OK);
    Ok(())
}

#[test]
fn t1_f11_03_receive_no_clobber_note_2_txt() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t1-f11-03")?;
    let src_dir = tmp.path().join("src");
    let dest_dir = tmp.path().join("dest");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::create_dir_all(&dest_dir)?;

    std::fs::write(dest_dir.join("note.txt"), b"ORIGINAL")?;
    let src_file = src_dir.join("note.txt");
    std::fs::write(&src_file, b"INCOMING")?;

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_files(&cfg, &[src_file.as_path()], "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(accept_files(recv.id(), &dest_dir)?, FFI_OK);
    let _ = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(15))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(15))?;

    assert_eq!(std::fs::read(dest_dir.join("note.txt"))?, b"ORIGINAL");
    assert_eq!(std::fs::read(dest_dir.join("note (2).txt"))?, b"INCOMING");
    assert!(!has_part_files(&dest_dir)?);
    Ok(())
}

#[test]
fn t1_f11_04_receive_plain_text_in_memory_zero_disk_writes() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t1-f11-04")?;
    let text = "Meeting link: https://example.test/room";

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_text(&cfg, text, "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let offer = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(offer.get("is_text").and_then(Value::as_bool), Some(true));

    assert_eq!(totaldrop_win_receive_accept_text(recv.id()), FFI_OK);
    let r_done = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(15))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(15))?;
    assert_eq!(
        r_done.get("received_text").and_then(Value::as_str),
        Some(text)
    );
    let san = r_done
        .get("sanitized_text")
        .ok_or("missing sanitized_text in done event")?;
    assert_eq!(san.get("shortened").and_then(Value::as_bool), Some(false));
    assert_eq!(
        san.get("has_hidden_controls").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(dir_entry_count(tmp.path())?, 0);

    let recv_id = recv.id();
    std::mem::forget(recv);
    assert_eq!(totaldrop_win_session_destroy(recv_id), FFI_OK);
    Ok(())
}

#[test]
fn t2_f11_01_validate_input_arabic_persian_fsi_turkish_empty() -> TestResult {
    for valid in [
        "\u{0667} Harbor ROCKET",
        "\u{06F7}-840-1499",
        "\u{2068}7-harbor-rocket\u{2069}",
    ] {
        let c = c_str(valid)?;
        // SAFETY: `c` is a live NUL-terminated CString.
        let val = take_json(unsafe { totaldrop_win_validate_input_json(c.as_ptr()) })?;
        assert_direct_dto_ok(&val)?;
        assert_eq!(
            val.get("display_english").and_then(Value::as_str),
            Some("7-harbor-rocket")
        );
        assert_eq!(val.get("nameplate").and_then(Value::as_u64), Some(7));
    }

    let turkish_bad = c_str("7-\u{0130}NSAN-rocket")?;
    // SAFETY: `turkish_bad` is a live NUL-terminated CString.
    let bad_val = take_json(unsafe { totaldrop_win_validate_input_json(turkish_bad.as_ptr()) })?;
    assert_error_envelope(&bad_val, Some("unknown_word"), Some("receiveCodeInvalid"))?;

    let empty_c = c_str("")?;
    // SAFETY: `empty_c` is a live NUL-terminated CString.
    let empty_val = take_json(unsafe { totaldrop_win_validate_input_json(empty_c.as_ptr()) })?;
    assert_error_envelope(&empty_val, Some("empty"), Some("receiveCodeInvalid"))?;
    Ok(())
}

#[test]
fn t2_f11_02_code_completions_boundary_inputs() -> TestResult {
    for (prefix, limit) in [("", 4u32), ("12", 4), ("\u{00C4}", 4), ("zz", 4), ("a", 0)] {
        let c = c_str(prefix)?;
        // SAFETY: `c` is a live NUL-terminated CString.
        let val = take_json(unsafe { totaldrop_win_code_completions_json(c.as_ptr(), limit) })?;
        assert_eq!(val, json!([]), "expected [] for ({prefix:?}, {limit})");
    }

    let exact_c = c_str("harbor")?;
    // SAFETY: `exact_c` is a live NUL-terminated CString.
    let exact = take_json(unsafe { totaldrop_win_code_completions_json(exact_c.as_ptr(), 4) })?;
    assert_eq!(exact, json!(["harbor"]));

    let h_c = c_str("h")?;
    // SAFETY: `h_c` is a live NUL-terminated CString.
    let h_val = take_json(unsafe { totaldrop_win_code_completions_json(h_c.as_ptr(), 4) })?;
    let arr = h_val.as_array().ok_or("expected array")?;
    assert_eq!(arr.len(), 4);
    let mut prev = "";
    for item in arr {
        let word = item.as_str().ok_or("expected str")?;
        assert!(word.starts_with('h') && word.is_ascii() && word == word.to_ascii_lowercase());
        assert!(word >= prev, "completions must be sorted: {h_val}");
        prev = word;
    }
    Ok(())
}

#[test]
fn t2_f11_03_clipboard_extract_empty_and_8_non_code_inputs() -> TestResult {
    for empty in ["", "   "] {
        let c = c_str(empty)?;
        // SAFETY: `c` is a live NUL-terminated CString.
        let val = take_json(unsafe { totaldrop_win_extract_clipboard_code_json(c.as_ptr()) })?;
        assert_error_envelope(&val, Some("empty"), Some("receiveCodeInvalid"))?;
    }

    for non_code in [
        "no code here",
        "0-harbor-rocket",
        "7-harbor",
        "7-harbor-rocket-harbor-rocket",
        "7-notaword-rocket",
        "Date: \u{2068}2026 10 30\u{2069}",
        "foo7-harbor-rocket",
        "7-harbor-rocket9",
    ] {
        let c = c_str(non_code)?;
        // SAFETY: `c` is a live NUL-terminated CString.
        let val = take_json(unsafe { totaldrop_win_extract_clipboard_code_json(c.as_ptr()) })?;
        assert_error_envelope(
            &val,
            Some("no_code_found_in_text"),
            Some("errorInvalidCode"),
        )?;
    }
    Ok(())
}

#[test]
fn t2_f11_04_receive_accept_invalid_dest_file_and_readonly_dir() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let tmp = TempDirGuard::new("t2-f11-04")?;
    let src = tmp.path().join("incoming.bin");
    std::fs::write(&src, b"payload")?;
    let cfg = make_cfg_json(&srv.url, "", false, false);

    // (a) Existing regular file passed as destination directory -> errorStorage + Cause::Unknown
    {
        let existing_file = tmp.path().join("not-a-dir.txt");
        std::fs::write(&existing_file, b"KEEP-ME")?;
        let send = start_send_files(&cfg, &[src.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?
            .to_owned();
        let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
        assert_eq!(accept_files(recv.id(), &existing_file)?, FFI_OK);
        let rf = wait_for_event(recv.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorStorage")
        );
        assert_eq!(rf.get("cause").and_then(Value::as_str), Some(""));
        assert!(rf.get("cause_detail").is_none_or(Value::is_null));
        assert!(
            rf.get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|s| s.to_ascii_lowercase().contains("not a folder")
                    || s.to_ascii_lowercase().contains("not a directory")),
            "expected not-a-directory diagnostic, got: {rf}"
        );
        assert_eq!(std::fs::read(&existing_file)?, b"KEEP-ME");
    }

    // (b) Read-only unwritable directory (`chmod 0o500` with RAII restore) -> errorStorage + causeNoPermission/causeReadOnly
    #[cfg(unix)]
    {
        let ro_dir = tmp.path().join("readonly-dest");
        std::fs::create_dir_all(&ro_dir)?;
        let _perm = ModeRestoreGuard::set(ro_dir.clone(), 0o500, 0o700)?;

        let send = start_send_files(&cfg, &[src.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?
            .to_owned();
        let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
        assert_eq!(accept_files(recv.id(), &ro_dir)?, FFI_OK);
        let rf = wait_for_event(recv.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorStorage")
        );
        let cause = rf.get("cause").and_then(Value::as_str).unwrap_or("");
        assert!(
            cause == "causeNoPermission" || cause == "causeReadOnly",
            "expected causeNoPermission or causeReadOnly, got {rf}"
        );
        assert!(
            rf.get("cause_detail")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        );
        assert!(!has_part_files(&ro_dir)?);
    }
    Ok(())
}

#[test]
fn t2_f11_05_receive_32kib_text_with_hidden_controls_and_destroy() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t2-f11-05")?;

    let prefix = "start \x1b[31mred \u{202E}rlo fake\rreal nonchar\u{FDD0} ";
    let mut payload = String::with_capacity(32 * 1024);
    payload.push_str(prefix);
    while payload.len() < 32 * 1024 {
        payload.push('A');
    }
    assert_eq!(payload.len(), 32 * 1024);

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_text(&cfg, &payload, "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(totaldrop_win_receive_accept_text(recv.id()), FFI_OK);
    let r_done = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(15))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(15))?;

    let received = r_done
        .get("received_text")
        .and_then(Value::as_str)
        .ok_or("missing received_text")?;
    assert_eq!(received.len(), 32 * 1024);
    assert_eq!(received, payload);

    let rec_c = c_str(received)?;
    // SAFETY: `rec_c` is a live NUL-terminated CString.
    let san = take_json(unsafe { totaldrop_win_sanitize_text_json(rec_c.as_ptr()) })?;
    assert_direct_dto_ok(&san)?;
    assert_eq!(san.get("shortened").and_then(Value::as_bool), Some(true));
    assert_eq!(
        san.get("has_hidden_controls").and_then(Value::as_bool),
        Some(true)
    );
    let display = san
        .get("display_text")
        .and_then(Value::as_str)
        .ok_or("missing display_text")?;
    assert_eq!(display.chars().count(), 16_384);
    for token in ["<U+001B>", "<U+202E>", "<U+000D>", "<U+FDD0>"] {
        assert!(
            display.contains(token),
            "expected {token} in sanitized display preview"
        );
    }
    assert_eq!(dir_entry_count(tmp.path())?, 0);

    let recv_id = recv.id();
    std::mem::forget(recv);
    assert_eq!(totaldrop_win_session_destroy(recv_id), FFI_OK);
    Ok(())
}

// ---------------------------------------------------------------------------
// F12 (M2): SettingsPage L10n Bundle (1 Rust cross-platform test)

#[test]
fn t1_f12_04_settings_l10n_en_tr_de_draft_and_version() -> TestResult {
    let app_ver = c_str("0.1.0-beta.1")?;
    let ver_args = c_str(r#"{"version":"0.1.0-beta.1"}"#)?;
    let empty_args = c_str("{}")?;

    for (tag, expected_draft, expected_ver_label) in [
        ("en-US", false, "Version 0.1.0-beta.1"),
        ("tr-TR", false, "Sürüm 0.1.0-beta.1"),
        ("de-DE", true, "Version 0.1.0-beta.1"),
    ] {
        let tag_c = c_str(tag)?;
        // SAFETY: All three pointers are live NUL-terminated CStrings.
        let bundle = take_json(unsafe {
            totaldrop_win_ui_bundle_json(tag_c.as_ptr(), tag_c.as_ptr(), app_ver.as_ptr())
        })?;
        assert_direct_dto_ok(&bundle)?;
        assert_eq!(
            bundle
                .get("has_draft_translations")
                .and_then(Value::as_bool),
            Some(expected_draft),
            "unexpected draft flag for {tag}"
        );
        assert_eq!(
            bundle.get("version_label").and_then(Value::as_str),
            Some(expected_ver_label),
            "unexpected version_label for {tag}"
        );

        let key_ver = c_str("settingsVersion")?;
        // SAFETY: All four pointers are live NUL-terminated CStrings.
        let fmt_ver = take_json(unsafe {
            totaldrop_win_format_message_json(
                key_ver.as_ptr(),
                ver_args.as_ptr(),
                tag_c.as_ptr(),
                tag_c.as_ptr(),
            )
        })?;
        assert_direct_dto_ok(&fmt_ver)?;
        assert!(
            fmt_ver
                .get("formatted")
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains("0.1.0-beta.1"))
        );

        for key in ["settingsWordsEnglish", "draftTranslation"] {
            let key_c = c_str(key)?;
            // SAFETY: All four pointers are live NUL-terminated CStrings.
            let fmt = take_json(unsafe {
                totaldrop_win_format_message_json(
                    key_c.as_ptr(),
                    empty_args.as_ptr(),
                    tag_c.as_ptr(),
                    tag_c.as_ptr(),
                )
            })?;
            assert_direct_dto_ok(&fmt)?;
            assert!(
                fmt.get("formatted")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty() && s != key),
                "missing localized text for {key} in {tag}"
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// F13 (M2): 35-Language Runtime L10n, RTL/Bidi & #483 Regional Percent (11 tests)

#[test]
fn t1_f13_01_all_35_canonical_locales_rtl_and_draft_flags() -> TestResult {
    const RTL: [&str; 4] = ["ar", "fa", "he", "ur"];
    assert_eq!(SUPPORTED_LANGUAGES.len(), 35);
    let app_ver = c_str("0.1.0-beta.1")?;

    for &tag in &SUPPORTED_LANGUAGES {
        let tag_c = c_str(tag)?;
        // SAFETY: All three pointers are live NUL-terminated CStrings.
        let bundle = take_json(unsafe {
            totaldrop_win_ui_bundle_json(tag_c.as_ptr(), tag_c.as_ptr(), app_ver.as_ptr())
        })?;
        assert_direct_dto_ok(&bundle)?;
        let expected_dir = if RTL.contains(&tag) {
            "RightToLeft"
        } else {
            "LeftToRight"
        };
        assert_eq!(
            bundle.get("flow_direction").and_then(Value::as_str),
            Some(expected_dir),
            "wrong flow_direction for {tag}"
        );
        let expected_draft = !matches!(tag, "en" | "tr");
        assert_eq!(
            bundle
                .get("has_draft_translations")
                .and_then(Value::as_bool),
            Some(expected_draft),
            "wrong has_draft_translations for {tag}"
        );
    }
    Ok(())
}

#[test]
fn t1_f13_02_11_critical_security_keys_app_and_cli_gate() -> TestResult {
    // Load local l10n/status.json to verify the 11 critical keys contract.
    let status_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("l10n")
        .join("status.json");
    let status_json: Value = serde_json::from_str(&std::fs::read_to_string(&status_path)?)?;
    let critical_arr = status_json
        .get("critical")
        .and_then(Value::as_array)
        .ok_or("missing critical array in l10n/status.json")?;
    assert_eq!(critical_arr.len(), 11);

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
    for key in APP_CRITICAL.iter().chain(CLI_CRITICAL.iter()) {
        assert!(
            critical_arr.iter().any(|v| v.as_str() == Some(*key)),
            "critical key {key} missing from l10n/status.json"
        );
    }

    // (a) Collect English reference for all 6 App critical keys via C ABI.
    let en_c = c_str("en")?;
    let empty_args = c_str("{}")?;
    let app_ver = c_str("0.1.0-beta.1")?;
    let mut en_app: HashMap<&str, String> = HashMap::new();
    for &key in &APP_CRITICAL {
        let key_c = c_str(key)?;
        // SAFETY: All four pointers are live NUL-terminated CStrings.
        let val = take_json(unsafe {
            totaldrop_win_format_message_json(
                key_c.as_ptr(),
                empty_args.as_ptr(),
                en_c.as_ptr(),
                en_c.as_ptr(),
            )
        })?;
        assert_direct_dto_ok(&val)?;
        let formatted = val
            .get("formatted")
            .and_then(Value::as_str)
            .ok_or("missing formatted")?
            .to_owned();
        en_app.insert(key, formatted);
    }

    // Reviewed Turkish must return reviewed Turkish strings.
    let tr_c = c_str("tr")?;
    // SAFETY: All three pointers are live NUL-terminated CStrings.
    let tr_bundle = take_json(unsafe {
        totaldrop_win_ui_bundle_json(tr_c.as_ptr(), tr_c.as_ptr(), app_ver.as_ptr())
    })?;
    assert_eq!(
        tr_bundle.get("verification_title").and_then(Value::as_str),
        Some("Doğrulama kelimeleri")
    );
    assert_eq!(
        tr_bundle.get("receive_accept").and_then(Value::as_str),
        Some("Kabul et")
    );
    assert_eq!(
        tr_bundle.get("receive_decline").and_then(Value::as_str),
        Some("Reddet")
    );

    // All 33 unreviewed locales must return verbatim English for all 6 App critical keys.
    for &tag in &SUPPORTED_LANGUAGES {
        if matches!(tag, "en" | "tr") {
            continue;
        }
        let tag_c = c_str(tag)?;
        // SAFETY: All three pointers are live NUL-terminated CStrings.
        let bundle = take_json(unsafe {
            totaldrop_win_ui_bundle_json(tag_c.as_ptr(), tag_c.as_ptr(), app_ver.as_ptr())
        })?;
        assert_eq!(
            bundle.get("verification_title").and_then(Value::as_str),
            en_app.get("verificationTitle").map(String::as_str),
            "unreviewed {tag} leaked verification_title"
        );
        assert_eq!(
            bundle.get("verification_hint").and_then(Value::as_str),
            en_app.get("verificationHint").map(String::as_str),
            "unreviewed {tag} leaked verification_hint"
        );
        assert_eq!(
            bundle.get("receive_accept").and_then(Value::as_str),
            en_app.get("receiveAccept").map(String::as_str),
            "unreviewed {tag} leaked receive_accept"
        );
        assert_eq!(
            bundle.get("receive_decline").and_then(Value::as_str),
            en_app.get("receiveDecline").map(String::as_str),
            "unreviewed {tag} leaked receive_decline"
        );

        for &key in &APP_CRITICAL {
            let key_c = c_str(key)?;
            // SAFETY: All four pointers are live NUL-terminated CStrings.
            let val = take_json(unsafe {
                totaldrop_win_format_message_json(
                    key_c.as_ptr(),
                    empty_args.as_ptr(),
                    tag_c.as_ptr(),
                    tag_c.as_ptr(),
                )
            })?;
            assert_eq!(
                val.get("formatted").and_then(Value::as_str),
                en_app.get(key).map(String::as_str),
                "unreviewed {tag} leaked app critical key {key}"
            );
        }
    }

    // (b) 5 CLI critical keys via totaldrop_l10n::Domain::Cli.
    let en_cli_locale = locale::parse("en").ok_or("parse en")?;
    let en_cli = Strings::new(Domain::Cli, &[en_cli_locale], None);
    let tr_cli_locale = locale::parse("tr").ok_or("parse tr")?;
    let tr_cli = Strings::new(Domain::Cli, &[tr_cli_locale], None);
    assert_eq!(tr_cli.tag(), "tr");
    assert_ne!(
        tr_cli.get("cliVerification", &[]),
        en_cli.get("cliVerification", &[])
    );

    const RTL: [&str; 4] = ["ar", "fa", "he", "ur"];
    for &tag in &SUPPORTED_LANGUAGES {
        if matches!(tag, "en" | "tr") {
            continue;
        }
        let loc = locale::parse(tag).ok_or_else(|| format!("parse {tag}"))?;
        let cli = Strings::new(Domain::Cli, &[loc], None);
        if RTL.contains(&tag) {
            assert_eq!(cli.tag(), "en", "RTL CLI locale {tag} must resolve to en");
        }
        for &key in &CLI_CRITICAL {
            assert_eq!(
                cli.get(key, &[]),
                en_cli.get(key, &[]),
                "unreviewed CLI locale {tag} leaked critical key {key}"
            );
        }
    }
    Ok(())
}

#[test]
fn t1_f13_03_regional_percent_decoupled_across_7_regions() -> TestResult {
    for (region, expected) in [
        ("en-US", "50%"),
        ("tr-TR", "%50"),
        ("en-TR", "%50"),
        ("de-DE", "50 %"),
        ("en-DE", "50 %"),
        ("fr-FR", "50\u{00A0}%"),
    ] {
        let reg_c = c_str(region)?;
        // SAFETY: `reg_c` is a live NUL-terminated CString.
        let val = take_json(unsafe { totaldrop_win_format_percent_json(50, 100, reg_c.as_ptr()) })?;
        assert_direct_dto_ok(&val)?;
        assert_eq!(val.get("whole").and_then(Value::as_u64), Some(50));
        assert_eq!(
            val.get("formatted").and_then(Value::as_str),
            Some(expected),
            "wrong percent format for region {region}"
        );
    }

    let ar_eg = c_str("ar-EG")?;
    // SAFETY: `ar_eg` is a live NUL-terminated CString.
    let ar_val = take_json(unsafe { totaldrop_win_format_percent_json(50, 100, ar_eg.as_ptr()) })?;
    assert_direct_dto_ok(&ar_val)?;
    assert_eq!(ar_val.get("whole").and_then(Value::as_u64), Some(50));
    let ar_fmt = ar_val
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing formatted")?;
    assert!(
        ar_fmt.contains('\u{066A}')
            && ar_fmt
                .chars()
                .any(|c| ('\u{0660}'..='\u{0669}').contains(&c)),
        "expected Arabic-Indic digits + U+066A for ar-EG, got {ar_fmt:?}"
    );
    Ok(())
}

#[test]
fn t1_f13_04_icu_plurals_and_si_bytes_formatting() -> TestResult {
    let format_msg =
        |key: &str, args: &str, lang: &str, reg: &str| -> Result<String, Box<dyn StdError>> {
            let key_c = c_str(key)?;
            let args_c = c_str(args)?;
            let lang_c = c_str(lang)?;
            let reg_c = c_str(reg)?;
            // SAFETY: All four pointers are live NUL-terminated CStrings.
            let val = take_json(unsafe {
                totaldrop_win_format_message_json(
                    key_c.as_ptr(),
                    args_c.as_ptr(),
                    lang_c.as_ptr(),
                    reg_c.as_ptr(),
                )
            })?;
            assert_direct_dto_ok(&val)?;
            Ok(val
                .get("formatted")
                .and_then(Value::as_str)
                .ok_or("missing formatted")?
                .to_owned())
        };

    assert_eq!(
        format_msg("sendDoneBody", r#"{"count":1}"#, "en", "en-US")?,
        "The file arrived intact."
    );
    assert_eq!(
        format_msg("sendDoneBody", r#"{"count":3}"#, "en", "en-US")?,
        "All 3 files arrived intact."
    );
    assert_eq!(
        format_msg(
            "itemsAndSize",
            r#"{"count":1234,"size":"2 MB"}"#,
            "en",
            "en-US"
        )?,
        "1,234 items \u{00B7} 2 MB"
    );

    // Russian distinct plural forms: 21 (one), 3 (few), 11 (many)
    let mut ru_set = BTreeSet::new();
    for n in [21u64, 3, 11] {
        ru_set.insert(format_msg(
            "sendDoneBody",
            &format!(r#"{{"count":{n}}}"#),
            "ru",
            "ru-RU",
        )?);
    }
    assert_eq!(
        ru_set.len(),
        3,
        "Russian must produce 3 distinct plural forms"
    );

    // Arabic distinct plural forms: 0, 1, 2, 5, 11
    let mut ar_set = BTreeSet::new();
    for n in [0u64, 1, 2, 5, 11] {
        ar_set.insert(format_msg(
            "itemsAndSize",
            &format!(r#"{{"count":{n},"size":"2 MB"}}"#),
            "ar",
            "ar-EG",
        )?);
    }
    assert_eq!(
        ar_set.len(),
        5,
        "Arabic must produce 5 distinct plural forms"
    );

    // Polish distinct plural forms: 1, 22 (few), 5 (many)
    let mut pl_set = BTreeSet::new();
    for n in [1u64, 22, 5] {
        pl_set.insert(format_msg(
            "sendDoneBody",
            &format!(r#"{{"count":{n}}}"#),
            "pl",
            "pl-PL",
        )?);
    }
    assert_eq!(
        pl_set.len(),
        3,
        "Polish must produce 3 distinct plural forms"
    );

    // German regional grouping separator
    let de_items = format_msg(
        "itemsAndSize",
        r#"{"count":1234,"size":"2 MB"}"#,
        "de",
        "de-DE",
    )?;
    assert!(
        de_items.contains("1.234"),
        "expected German thousands separator: {de_items:?}"
    );

    // SI bytes formatting
    let en_c = c_str("en")?;
    let us_c = c_str("en-US")?;
    for (bytes, expected) in [
        (0u64, "0 B"),
        (999, "999 B"),
        (1_000, "1.0 kB"),
        (1_549_999, "1.5 MB"),
        (9_960_000, "10 MB"),
        (999_999_999, "1.0 GB"),
    ] {
        // SAFETY: `en_c` and `us_c` are live NUL-terminated CStrings.
        let val = take_json(unsafe {
            totaldrop_win_format_bytes_json(bytes, en_c.as_ptr(), us_c.as_ptr())
        })?;
        assert_direct_dto_ok(&val)?;
        assert_eq!(
            val.get("formatted").and_then(Value::as_str),
            Some(expected),
            "SI bytes mismatch for {bytes}"
        );
    }

    let de_c = c_str("de-DE")?;
    // SAFETY: `en_c` and `de_c` are live NUL-terminated CStrings.
    let de_bytes = take_json(unsafe {
        totaldrop_win_format_bytes_json(1_549_999, en_c.as_ptr(), de_c.as_ptr())
    })?;
    assert_eq!(
        de_bytes.get("formatted").and_then(Value::as_str),
        Some("1,5 MB")
    );
    Ok(())
}

#[test]
fn t1_f13_05_sanitize_filename_zwnj_and_35_locale_share_roundtrip() -> TestResult {
    let fname_c = c_str("report.pdf")?;
    // SAFETY: `fname_c` is a live NUL-terminated CString.
    let fn_val = take_json(unsafe { totaldrop_win_sanitize_filename_json(fname_c.as_ptr()) })?;
    assert_direct_dto_ok(&fn_val)?;
    assert_eq!(
        fn_val.get("sanitized").and_then(Value::as_str),
        Some("\u{2068}report.pdf\u{2069}")
    );
    assert_eq!(
        fn_val.get("has_hidden_controls").and_then(Value::as_bool),
        Some(false)
    );

    let zwnj_text = "می\u{200C}خواهم\r\nline 2\tok";
    let zwnj_c = c_str(zwnj_text)?;
    // SAFETY: `zwnj_c` is a live NUL-terminated CString.
    let txt_val = take_json(unsafe { totaldrop_win_sanitize_text_json(zwnj_c.as_ptr()) })?;
    assert_direct_dto_ok(&txt_val)?;
    assert_eq!(
        txt_val.get("display_text").and_then(Value::as_str),
        Some("می\u{200C}خواهم\nline 2\tok")
    );
    assert_eq!(
        txt_val.get("has_hidden_controls").and_then(Value::as_bool),
        Some(false)
    );

    // sendShareText(code="7-harbor-rocket") round-trips via extract_clipboard_code_json across ALL 35 locales
    let key_c = c_str("sendShareText")?;
    let args_c = c_str(r#"{"code":"\u20687-harbor-rocket\u2069"}"#)?;
    for &tag in &SUPPORTED_LANGUAGES {
        let tag_c = c_str(tag)?;
        // SAFETY: All four pointers are live NUL-terminated CStrings.
        let share = take_json(unsafe {
            totaldrop_win_format_message_json(
                key_c.as_ptr(),
                args_c.as_ptr(),
                tag_c.as_ptr(),
                tag_c.as_ptr(),
            )
        })?;
        assert_direct_dto_ok(&share)?;
        let sentence = share
            .get("formatted")
            .and_then(Value::as_str)
            .ok_or("missing formatted")?;
        if tag == "ar" {
            assert!(
                sentence.contains("\u{2068}7-harbor-rocket\u{2069}"),
                "Arabic share sentence must preserve FSI/PDI isolation: {sentence:?}"
            );
        }
        let sent_c = c_str(sentence)?;
        // SAFETY: `sent_c` is a live NUL-terminated CString.
        let extracted =
            take_json(unsafe { totaldrop_win_extract_clipboard_code_json(sent_c.as_ptr()) })?;
        assert_direct_dto_ok(&extracted)?;
        assert_eq!(
            extracted.get("display_english").and_then(Value::as_str),
            Some("7-harbor-rocket"),
            "share sentence failed clipboard round-trip in {tag}: {sentence:?}"
        );
    }
    Ok(())
}

#[test]
fn t1_f13_06_negotiation_json_vectors_live_c_abi_and_pseudo_locales() -> TestResult {
    // (a) Verify all canonical 35-locale negotiation vectors from l10n/tests/negotiation.json.
    let neg_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("l10n")
        .join("tests")
        .join("negotiation.json");
    let neg_json: Value = serde_json::from_str(&std::fs::read_to_string(&neg_path)?)?;
    let available: Vec<&str> = neg_json
        .get("available")
        .and_then(Value::as_array)
        .ok_or("missing available")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(available.len(), 35);
    let cases = neg_json
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("missing cases")?;
    for case in cases {
        let prefs: Vec<_> = case
            .get("prefs")
            .and_then(Value::as_array)
            .ok_or("missing prefs")?
            .iter()
            .filter_map(Value::as_str)
            .filter_map(locale::parse)
            .collect();
        let expect = case
            .get("expect")
            .and_then(Value::as_str)
            .ok_or("missing expect")?;
        let got = locale::negotiate(&prefs, &available).unwrap_or("en");
        assert_eq!(got, expect, "negotiation mismatch for case {case}");
    }

    // (b) Live C ABI resolution across regional/script/fallback tags & pseudo-locales.
    let app_ver = c_str("0.1.0-beta.1")?;
    for (langs, expect_tag, expect_settings) in [
        ("pt", "pt", Some("Configurações")),
        ("pt-AO", "pt-PT", Some("Definições")),
        ("zh-CN", "zh", Some("设置")),
        ("zh-Hans", "zh", Some("设置")),
        ("zh-TW", "zh-Hant", Some("設定")),
        ("tr_TR", "tr", None),
        ("ar-EG", "ar", None),
        ("nn-NO", "nb", None),
        (r#"["xx","de-AT","tr"]"#, "de", None),
        (r#"["sr","hr"]"#, "en", None),
    ] {
        let langs_c = c_str(langs)?;
        // SAFETY: `langs_c` and `app_ver` are live NUL-terminated CStrings.
        let bundle = take_json(unsafe {
            totaldrop_win_ui_bundle_json(langs_c.as_ptr(), ptr::null(), app_ver.as_ptr())
        })?;
        assert_direct_dto_ok(&bundle)?;
        assert_eq!(
            bundle.get("language_tag").and_then(Value::as_str),
            Some(expect_tag),
            "wrong language_tag for {langs:?}"
        );
        if let Some(settings) = expect_settings {
            assert_eq!(
                bundle.get("settings_title").and_then(Value::as_str),
                Some(settings),
                "wrong settings_title for {langs:?}"
            );
        }
    }

    // Pseudo-locale `en-XA`
    let en_xa = c_str("en-XA")?;
    // SAFETY: `en_xa` and `app_ver` are live NUL-terminated CStrings.
    let xa_bundle = take_json(unsafe {
        totaldrop_win_ui_bundle_json(en_xa.as_ptr(), ptr::null(), app_ver.as_ptr())
    })?;
    assert_eq!(
        xa_bundle.get("language_tag").and_then(Value::as_str),
        Some("en-XA")
    );
    assert_eq!(
        xa_bundle.get("flow_direction").and_then(Value::as_str),
        Some("LeftToRight")
    );
    assert_eq!(
        xa_bundle
            .get("has_draft_translations")
            .and_then(Value::as_bool),
        Some(false)
    );
    let xa_vt = xa_bundle
        .get("verification_title")
        .and_then(Value::as_str)
        .ok_or("missing en-XA verification_title")?;
    assert_eq!(xa_vt, "Vérîfîçátîöñ wördš······");
    assert_eq!(xa_vt.chars().count(), 24);

    let key_share = c_str("sendShareText")?;
    let share_args = c_str(r#"{"code":"7-harbor-rocket"}"#)?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let xa_share = take_json(unsafe {
        totaldrop_win_format_message_json(
            key_share.as_ptr(),
            share_args.as_ptr(),
            en_xa.as_ptr(),
            ptr::null(),
        )
    })?;
    let xa_share_text = xa_share
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing formatted")?;
    assert!(
        xa_share_text.starts_with("Gét mý fîléš") && xa_share_text.contains("7-harbor-rocket"),
        "unexpected en-XA sendShareText: {xa_share_text:?}"
    );

    // Pseudo-locale `ar-XB`
    let ar_xb = c_str("ar-XB")?;
    // SAFETY: `ar_xb` and `app_ver` are live NUL-terminated CStrings.
    let xb_bundle = take_json(unsafe {
        totaldrop_win_ui_bundle_json(ar_xb.as_ptr(), ptr::null(), app_ver.as_ptr())
    })?;
    assert_eq!(
        xb_bundle.get("language_tag").and_then(Value::as_str),
        Some("ar-XB")
    );
    assert_eq!(
        xb_bundle.get("flow_direction").and_then(Value::as_str),
        Some("RightToLeft")
    );
    assert_eq!(
        xb_bundle
            .get("has_draft_translations")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        xb_bundle.get("settings_title").and_then(Value::as_str),
        Some("Settings")
    );
    Ok(())
}

#[test]
fn t2_f13_01_part_a_regional_subtags_unreviewed_critical_keys() -> TestResult {
    const APP_CRITICAL: [&str; 6] = [
        "verificationTitle",
        "verificationHint",
        "errorWrongCode",
        "errorInvalidOffer",
        "receiveAccept",
        "receiveDecline",
    ];
    let en_c = c_str("en")?;
    let empty_args = c_str("{}")?;
    let app_ver = c_str("0.1.0-beta.1")?;

    let mut en_ref: HashMap<&str, String> = HashMap::new();
    for &key in &APP_CRITICAL {
        let key_c = c_str(key)?;
        // SAFETY: All four pointers are live NUL-terminated CStrings.
        let val = take_json(unsafe {
            totaldrop_win_format_message_json(
                key_c.as_ptr(),
                empty_args.as_ptr(),
                en_c.as_ptr(),
                en_c.as_ptr(),
            )
        })?;
        en_ref.insert(
            key,
            val.get("formatted")
                .and_then(Value::as_str)
                .ok_or("missing en formatted")?
                .to_owned(),
        );
    }

    for subtag in [
        "de-AT",
        "ar-EG",
        "zh-HK",
        "pt-AO",
        "es-419",
        "fr-CA",
        r#"["xx-YY","de-AT","tr-TR"]"#,
    ] {
        let sub_c = c_str(subtag)?;
        // SAFETY: `sub_c` and `app_ver` are live NUL-terminated CStrings.
        let bundle = take_json(unsafe {
            totaldrop_win_ui_bundle_json(sub_c.as_ptr(), ptr::null(), app_ver.as_ptr())
        })?;
        assert_direct_dto_ok(&bundle)?;
        assert_eq!(
            bundle
                .get("has_draft_translations")
                .and_then(Value::as_bool),
            Some(true),
            "regional subtag {subtag:?} must report has_draft_translations == true"
        );
        assert_eq!(
            bundle.get("verification_title").and_then(Value::as_str),
            Some("Verification words")
        );
        assert_eq!(
            bundle.get("receive_accept").and_then(Value::as_str),
            Some("Accept")
        );
        assert_eq!(
            bundle.get("receive_decline").and_then(Value::as_str),
            Some("Decline")
        );

        for &key in &APP_CRITICAL {
            let key_c = c_str(key)?;
            // SAFETY: All four pointers are live NUL-terminated CStrings.
            let msg = take_json(unsafe {
                totaldrop_win_format_message_json(
                    key_c.as_ptr(),
                    empty_args.as_ptr(),
                    sub_c.as_ptr(),
                    ptr::null(),
                )
            })?;
            assert_eq!(
                msg.get("formatted").and_then(Value::as_str),
                en_ref.get(key).map(String::as_str),
                "regional subtag {subtag:?} leaked critical key {key}"
            );
        }
    }
    Ok(())
}

#[test]
fn t2_f13_02_percent_boundary_and_u64_max_overflow_safety() -> TestResult {
    for region in ["en-US", "en-TR", "de-DE", "fr-FR"] {
        let reg_c = c_str(region)?;
        for (done, total, expected_whole) in [
            (0u64, 0u64, 0u64),
            (0, 1_000, 0),
            (999_999, 1_000_000, 99),
            (u64::MAX.saturating_sub(1), u64::MAX, 99),
            (1_000_000, 1_000_000, 100),
            (1_500_000, 1_000_000, 100),
        ] {
            // SAFETY: `reg_c` is a live NUL-terminated CString.
            let val = take_json(unsafe {
                totaldrop_win_format_percent_json(done, total, reg_c.as_ptr())
            })?;
            assert_direct_dto_ok(&val)?;
            assert_eq!(
                val.get("whole").and_then(Value::as_u64),
                Some(expected_whole),
                "wrong floor percent for ({done}, {total}, {region}): {val}"
            );
        }
    }
    Ok(())
}

#[test]
fn t2_f13_03_sanitize_rlo_ansi_cr_nonchars_and_preserve_zwnj_zwj() -> TestResult {
    let fname_c = c_str("invoice\u{202E}fdp.exe")?;
    // SAFETY: `fname_c` is a live NUL-terminated CString.
    let fn_val = take_json(unsafe { totaldrop_win_sanitize_filename_json(fname_c.as_ptr()) })?;
    assert_direct_dto_ok(&fn_val)?;
    assert_eq!(
        fn_val.get("sanitized").and_then(Value::as_str),
        Some("\u{2068}invoice<U+202E>fdp.exe\u{2069}")
    );
    assert_eq!(
        fn_val.get("has_hidden_controls").and_then(Value::as_bool),
        Some(true)
    );

    let text = "one\ttwo\r\nred\u{1b}[31m \u{202e}evil\nfake\rreal\u{FDD0}\u{FFFF}\u{200C}\u{200D}";
    let text_c = c_str(text)?;
    // SAFETY: `text_c` is a live NUL-terminated CString.
    let txt_val = take_json(unsafe { totaldrop_win_sanitize_text_json(text_c.as_ptr()) })?;
    assert_direct_dto_ok(&txt_val)?;
    assert_eq!(
        txt_val.get("has_hidden_controls").and_then(Value::as_bool),
        Some(true)
    );
    let display = txt_val
        .get("display_text")
        .and_then(Value::as_str)
        .ok_or("missing display_text")?;
    assert_eq!(
        display,
        "one\ttwo\nred<U+001B>[31m <U+202E>evil\nfake<U+000D>real<U+FDD0><U+FFFF>\u{200C}\u{200D}"
    );
    Ok(())
}

#[test]
fn t2_f13_04_sanitize_text_16384_boundary_and_u64_max_bytes() -> TestResult {
    let exact_16k = "ğ".repeat(16_384);
    let exact_c = c_str(&exact_16k)?;
    // SAFETY: `exact_c` is a live NUL-terminated CString.
    let exact_val = take_json(unsafe { totaldrop_win_sanitize_text_json(exact_c.as_ptr()) })?;
    assert_eq!(
        exact_val.get("shortened").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        exact_val
            .get("display_text")
            .and_then(Value::as_str)
            .map(|s| s.chars().count()),
        Some(16_384)
    );

    let over_16k = "ğ".repeat(16_385);
    let over_c = c_str(&over_16k)?;
    // SAFETY: `over_c` is a live NUL-terminated CString.
    let over_val = take_json(unsafe { totaldrop_win_sanitize_text_json(over_c.as_ptr()) })?;
    assert_eq!(
        over_val.get("shortened").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        over_val
            .get("display_text")
            .and_then(Value::as_str)
            .map(|s| s.chars().count()),
        Some(16_384)
    );

    let en_c = c_str("en")?;
    let us_c = c_str("en-US")?;
    // SAFETY: `en_c` and `us_c` are live NUL-terminated CStrings.
    let max_bytes = take_json(unsafe {
        totaldrop_win_format_bytes_json(u64::MAX, en_c.as_ptr(), us_c.as_ptr())
    })?;
    assert_direct_dto_ok(&max_bytes)?;
    assert_eq!(
        max_bytes.get("formatted").and_then(Value::as_str),
        Some("18,447 PB")
    );
    Ok(())
}

#[test]
fn t2_f13_05_zh_hant_variants_unknown_locales_and_format_message_errors() -> TestResult {
    let app_ver = c_str("0.1.0-beta.1")?;
    // (a1) Traditional Chinese tags -> zh-Hant, settings_title == "設定", English-gated verification_title
    for tag in ["zh-Hant", "zh-TW", "zh-HK", "zh-MO"] {
        let tag_c = c_str(tag)?;
        // SAFETY: `tag_c` and `app_ver` are live NUL-terminated CStrings.
        let bundle = take_json(unsafe {
            totaldrop_win_ui_bundle_json(tag_c.as_ptr(), ptr::null(), app_ver.as_ptr())
        })?;
        assert_direct_dto_ok(&bundle)?;
        assert_eq!(
            bundle.get("language_tag").and_then(Value::as_str),
            Some("zh-Hant"),
            "wrong tag for {tag}"
        );
        assert_eq!(
            bundle.get("settings_title").and_then(Value::as_str),
            Some("設定"),
            "expected Traditional Chinese settings_title for {tag}"
        );
        assert_eq!(
            bundle.get("verification_title").and_then(Value::as_str),
            Some("Verification words")
        );
    }

    // (a2) Unknown/empty tags fall back cleanly to "en"
    for tag in ["sr-RS", "xx-YY", ""] {
        let tag_c = c_str(tag)?;
        // SAFETY: `tag_c` and `app_ver` are live NUL-terminated CStrings.
        let bundle = take_json(unsafe {
            totaldrop_win_ui_bundle_json(tag_c.as_ptr(), ptr::null(), app_ver.as_ptr())
        })?;
        assert_direct_dto_ok(&bundle)?;
        assert_eq!(
            bundle.get("language_tag").and_then(Value::as_str),
            Some("en")
        );
    }

    // (b) Invalid/oversized format_message_json calls return clean error envelopes
    let en_c = c_str("en")?;
    let empty_args = c_str("{}")?;
    let unknown_key = c_str("nonexistentKey")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let e1 = take_json(unsafe {
        totaldrop_win_format_message_json(
            unknown_key.as_ptr(),
            empty_args.as_ptr(),
            en_c.as_ptr(),
            en_c.as_ptr(),
        )
    })?;
    assert_error_envelope(&e1, Some("unknown_key"), Some("errorOther"))?;

    let empty_key = c_str("")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let e2 = take_json(unsafe {
        totaldrop_win_format_message_json(
            empty_key.as_ptr(),
            empty_args.as_ptr(),
            en_c.as_ptr(),
            en_c.as_ptr(),
        )
    })?;
    assert_error_envelope(&e2, Some("empty_key"), Some("errorOther"))?;

    let valid_key = c_str("sendTitle")?;
    let bad_args = c_str("{bad")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let e3 = take_json(unsafe {
        totaldrop_win_format_message_json(
            valid_key.as_ptr(),
            bad_args.as_ptr(),
            en_c.as_ptr(),
            en_c.as_ptr(),
        )
    })?;
    assert_error_envelope(&e3, Some("invalid_json"), Some("errorOther"))?;

    let huge_args = c_str(&format!(r#"{{"pad":"{}"}}"#, "x".repeat(20_000)))?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let e4 = take_json(unsafe {
        totaldrop_win_format_message_json(
            valid_key.as_ptr(),
            huge_args.as_ptr(),
            en_c.as_ptr(),
            en_c.as_ptr(),
        )
    })?;
    assert_error_envelope(&e4, Some("args_too_large"), Some("errorOther"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// F15 (M2): Windows Parser Error Variants & Fuzz Invariants (8 Rust tests)

#[test]
fn t1_f15_03_all_7_uri_validation_error_variants() -> TestResult {
    // Exact variant match for all 7 UriValidationError variants:
    assert_eq!(
        ValidatedCode::from_activation_uri("   "),
        Err(UriValidationError::Empty)
    );
    let oversized = format!("totaldrop://r/{}", "a".repeat(1020));
    assert!(matches!(
        ValidatedCode::from_activation_uri(&oversized),
        Err(UriValidationError::LinkTooLong { limit: 1024, .. })
    ));
    assert_eq!(
        ValidatedCode::from_activation_uri("https://evil.example/r#7-harbor-rocket"),
        Err(UriValidationError::InvalidActivationLink)
    );
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
    assert_eq!(
        ValidatedCode::from_clipboard_text("plain prose without any code"),
        Err(UriValidationError::NoCodeFoundInText)
    );
    Ok(())
}

#[test]
fn t1_f15_04_all_16_activation_error_variants() -> TestResult {
    // 1. EmptyPath
    assert_eq!(
        WindowsSelectionPath::parse(""),
        Err(ActivationError::EmptyPath)
    );
    // 2. ControlCharacter
    assert_eq!(
        WindowsSelectionPath::parse("C:\\tmp\\bad\0file.txt"),
        Err(ActivationError::ControlCharacter)
    );
    // 3. PathTooLong
    let too_long = format!(r"C:\{}", "a".repeat(32_770));
    assert!(matches!(
        WindowsSelectionPath::parse(&too_long),
        Err(ActivationError::PathTooLong { .. })
    ));
    // 4. NotAbsoluteWindowsPath
    assert_eq!(
        WindowsSelectionPath::parse(r"relative\file.txt"),
        Err(ActivationError::NotAbsoluteWindowsPath)
    );
    // 5. DeviceNamespaceForbidden
    assert_eq!(
        WindowsSelectionPath::parse(r"\\.\PhysicalDrive0"),
        Err(ActivationError::DeviceNamespaceForbidden)
    );
    // 6. DotTraversalSegment
    assert_eq!(
        WindowsSelectionPath::parse(r"C:\tmp\..\secret.txt"),
        Err(ActivationError::DotTraversalSegment)
    );
    // 7. ForbiddenSegmentCharacter
    assert_eq!(
        WindowsSelectionPath::parse(r"C:\tmp\file.txt:stream"),
        Err(ActivationError::ForbiddenSegmentCharacter(':'))
    );
    // 8. TrailingDotOrSpace
    assert_eq!(
        WindowsSelectionPath::parse(r"C:\tmp\trailing."),
        Err(ActivationError::TrailingDotOrSpace)
    );
    // 9. TooManyItems
    let too_many: Vec<String> = (0..10_001usize)
        .map(|i| format!(r"C:\tmp\f{i}.txt"))
        .collect();
    assert_eq!(
        ActivationEnvelope::explorer_send(&too_many, None),
        Err(ActivationError::TooManyItems { count: 10_001 })
    );
    // 10. EmptyExplorerSelection
    assert_eq!(
        ActivationEnvelope::explorer_send(Vec::<&str>::new(), None),
        Err(ActivationError::EmptyExplorerSelection)
    );
    // 11. EnvelopeTooLarge
    let mut dec = IpcFrameDecoder::new();
    let over_hdr = u32::try_from(MAX_IPC_FRAME_BYTES.saturating_add(1))?.to_le_bytes();
    assert!(matches!(
        dec.push_bytes(&over_hdr),
        Err(ActivationError::EnvelopeTooLarge { .. })
    ));
    // 12. MalformedIpcFrame
    assert_eq!(
        ActivationEnvelope::decode_ipc_frame(&[1u8, 2u8]),
        Err(ActivationError::MalformedIpcFrame)
    );
    // 13. UnsupportedSchemaVersion
    let bad_ver_json = br#"{"version":2,"payload":{"kind":"open_screen","screen":"send"}}"#;
    let mut bad_ver_frame = u32::try_from(bad_ver_json.len())?.to_le_bytes().to_vec();
    bad_ver_frame.extend_from_slice(bad_ver_json);
    assert_eq!(
        ActivationEnvelope::decode_ipc_frame(&bad_ver_frame),
        Err(ActivationError::UnsupportedSchemaVersion(2))
    );
    // 14. InvalidJson
    let bad_json = b"{invalid";
    let mut bad_json_frame = u32::try_from(bad_json.len())?.to_le_bytes().to_vec();
    bad_json_frame.extend_from_slice(bad_json);
    assert!(matches!(
        ActivationEnvelope::decode_ipc_frame(&bad_json_frame),
        Err(ActivationError::InvalidJson(_))
    ));
    // 15. InvalidUri
    assert!(matches!(
        parse_launch_args(["totaldrop://r/0-bad-code"]),
        Err(ActivationError::InvalidUri(_))
    ));
    // 16. MalformedCommandLine
    assert_eq!(
        split_win32_command_line("\"unterminated quote", false),
        Err(ActivationError::MalformedCommandLine)
    );
    Ok(())
}

#[test]
fn t1_f15_05_curated_100_case_seed_corpus_round_trip() -> TestResult {
    let mut cases_run = 0usize;

    // 20 IPC envelope round-trip cases
    for i in 0usize..20 {
        let env = match i % 4 {
            0 => ActivationEnvelope::explorer_send(
                [format!(r"C:\Users\Seed\file_{i}.bin")],
                Some(i as u32),
            )?,
            1 => ActivationEnvelope::share_target(
                [format!(r"\\nas{i}\share\doc_{i}.pdf")],
                Some(format!("Note #{i}")),
                None,
            )?,
            2 => ActivationEnvelope::protocol_uri("totaldrop://r/7-harbor-rocket", None)?,
            _ => ActivationEnvelope::open_screen(
                match i % 3 {
                    0 => ScreenTarget::Send,
                    1 => ScreenTarget::Receive,
                    _ => ScreenTarget::Settings,
                },
                None,
            ),
        };
        let frame = env.encode_ipc_frame()?;
        let decoded = ActivationEnvelope::decode_ipc_frame(&frame)?;
        assert_eq!(decoded, env);
        let re_encoded = decoded.encode_ipc_frame()?;
        assert_eq!(ActivationEnvelope::decode_ipc_frame(&re_encoded)?, env);
        cases_run = cases_run.saturating_add(1);
    }

    // 20 Windows path round-trip & rejection cases
    let path_seeds = [
        r"C:\Users\Alice\a.txt",
        r"D:\Media\clip.mp4",
        "e:/slashes/ok.bin",
        r"\\nas01\share\file.pdf",
        r"\\?\C:\Extended\Path\data.dat",
        r"\\?\UNC\server\share\sub\item.txt",
        r"C:\Users\Alice\My Docs (2026)\report & summary.txt",
        r"C:\Users\Alice\rapor-2026-türkçe.txt",
        r"\\fileserver\pub\a b c\x^y.bin",
        r"Z:\root.txt",
        "",
        r"relative\path.txt",
        r"C:drive-relative.txt",
        r"\\.\PhysicalDrive0",
        r"C:\tmp\..\escape.txt",
        r"C:\tmp\CON.txt",
        r"C:\tmp\a.txt:ads",
        r"C:\tmp\dot.",
        r"C:\tmp\space ",
        "C:\\tmp\\nul\0byte",
    ];
    for raw in path_seeds {
        if let Ok(parsed) = WindowsSelectionPath::parse(raw) {
            assert_eq!(WindowsSelectionPath::parse(parsed.extended_path())?, parsed);
            assert_eq!(
                WindowsSelectionPath::parse(parsed.unprefixed_path())?,
                parsed
            );
        }
        cases_run = cases_run.saturating_add(1);
    }

    // 20 Win32 command-line quoting & splitting cases
    let cmd_seeds = [
        "simple",
        "with spaces",
        r"C:\Program Files\TotalDrop\totaldrop-winui.exe",
        r#"has "quotes" inside"#,
        r"trailing\backslash\",
        r#"many\\\quotes\"here"#,
        "shell & calc.exe | sort ^ %TEMP%",
        "(parens) and <angles>",
        "empty-next",
        "unicode-köşe-🚀",
        "tab\tinside",
        "leading space",
        "trailing space ",
        r"\\?\UNC\server\share\a b\c.bin",
        "--explorer-send",
        "--",
        "a\"b\"c",
        r"\\",
        r#"\\\"#,
        "C:\\bad\nnewline",
    ];
    for raw in cmd_seeds {
        if let Ok(quoted) = quote_win32_arg(raw) {
            let split = split_win32_command_line(&quoted, false)?;
            assert_eq!(split, vec![raw.to_owned()]);
        }
        cases_run = cases_run.saturating_add(1);
    }

    // 20 URI / user-input / clipboard round-trip cases
    let uri_seeds = [
        "totaldrop://r/7-harbor-rocket",
        "totaldrop:7-harbor-rocket",
        "https://totaldrop.app/r#7-harbor-rocket",
        "totaldrop://r/42-zoo-zone-able",
        "totaldrop://r/1-abandon-ability",
        "totaldrop://r/999-harbor-rocket-able",
        "totaldrop://r/7%20harbor%20rocket",
        "\u{2068}totaldrop://r/7-harbor-rocket\u{2069}",
        "7-harbor-rocket",
        "42-zoo-zone-able",
        "",
        "   ",
        "https://evil.example/r#7-harbor-rocket",
        "totaldrop://r/%2537-harbor-rocket",
        "totaldrop://r/7-harbor-rocket?x=1",
        "totaldrop://r/7-harbor-rocket/extra",
        "0-harbor-rocket",
        "7-harbor",
        "7-harbor-notaword",
        r"C:\Users\Alice\7-harbor-rocket.pdf",
    ];
    for raw in uri_seeds {
        if let Ok(code) = ValidatedCode::from_activation_uri(raw) {
            assert_eq!(
                ValidatedCode::from_activation_uri(&code.protocol_uri)?,
                code
            );
            assert_eq!(ValidatedCode::from_activation_uri(&code.web_uri)?, code);
            assert_eq!(ValidatedCode::from_user_input(&code.display_english)?, code);
        }
        cases_run = cases_run.saturating_add(1);
    }

    // 20 NDJSON batch round-trip cases
    for i in 0usize..20 {
        let msgs = vec![
            WinUiBridgeMessage::MarkAnimationState {
                animate: i % 2 == 0,
                hex_light: "#6D4AE0".to_owned(),
                hex_dark: "#A68BFF".to_owned(),
                cycle_ms: 3200,
            },
            WinUiBridgeMessage::RouteDecision(RouterDecision::RejectBusy {
                localized_banner: format!("busy notice #{i}"),
            }),
        ];
        let encoded = encode_ndjson_batch(&msgs)?;
        let decoded = decode_ndjson_stream(&encoded)?;
        assert_eq!(decoded, msgs);
        cases_run = cases_run.saturating_add(1);
    }

    assert_eq!(cases_run, 100);
    Ok(())
}

#[test]
fn t2_f15_01_ipc_frame_decoder_4mib_plus_1_u32_max_and_zero() -> TestResult {
    // 4 MiB + 1 (`4_194_305` LE = [0x01, 0x00, 0x40, 0x00]) -> EnvelopeTooLarge, payload_capacity == 0
    let mut dec1 = IpcFrameDecoder::new();
    let res1 = dec1.push_bytes(&[0x01, 0x00, 0x40, 0x00]);
    assert!(matches!(
        res1,
        Err(ActivationError::EnvelopeTooLarge {
            byte_len: 4_194_305
        })
    ));
    assert_eq!(dec1.payload_capacity(), 0);

    // u32::MAX ([0xFF, 0xFF, 0xFF, 0xFF]) -> EnvelopeTooLarge, payload_capacity == 0
    let mut dec2 = IpcFrameDecoder::new();
    let res2 = dec2.push_bytes(&[0xFF, 0xFF, 0xFF, 0xFF]);
    assert!(matches!(
        res2,
        Err(ActivationError::EnvelopeTooLarge { .. })
    ));
    assert_eq!(dec2.payload_capacity(), 0);

    // 0 ([0x00, 0x00, 0x00, 0x00]) -> MalformedIpcFrame, payload_capacity == 0
    let mut dec3 = IpcFrameDecoder::new();
    let res3 = dec3.push_bytes(&[0x00, 0x00, 0x00, 0x00]);
    assert_eq!(res3, Err(ActivationError::MalformedIpcFrame));
    assert_eq!(dec3.payload_capacity(), 0);
    Ok(())
}

#[test]
fn t2_f15_02_windows_selection_path_adversarial_inputs() -> TestResult {
    // 32_767 UTF-16 code units (including \\?\) -> PathTooLong
    let long_ascii = format!(r"C:\{}", "a".repeat(32_760));
    // `\\?\` (4) + `C:\` (3) + 32_760 = 32_767 UTF-16 code units
    assert!(matches!(
        WindowsSelectionPath::parse(&long_ascii),
        Err(ActivationError::PathTooLong { utf16_len: 32_767 })
    ));

    // Surrogate-pair boundary: emoji `😀` = 2 UTF-16 units pushing 32_765 -> 32_767
    let long_emoji = format!(r"C:\{}😀", "a".repeat(32_758));
    assert!(matches!(
        WindowsSelectionPath::parse(&long_emoji),
        Err(ActivationError::PathTooLong { utf16_len: 32_767 })
    ));

    // Exact 32_766 UTF-16 succeeds and satisfies utf16_len() <= 32_766
    let ok_max = format!(r"C:\{}", "a".repeat(32_759));
    let parsed_ok = WindowsSelectionPath::parse(&ok_max)?;
    assert_eq!(parsed_ok.utf16_len(), 32_766);

    // U+202E in NTFS filename: accepted by path parser, escaped as <U+202E> with zero hidden chars in safe_display_path()
    let rlo_path = WindowsSelectionPath::parse("C:\\Downloads\\invoice\u{202E}fdp.exe")?;
    let safe_display = rlo_path.safe_display_path();
    assert!(safe_display.contains("<U+202E>"));
    assert!(!safe_display.chars().any(totaldrop_l10n::is_hidden));

    // Forbidden inputs must all return typed Err(ActivationError::...)
    for bad in [
        "C:\\tmp\\nul\0char.txt",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\x",
        r"C:\tmp\CON.txt",
        r"C:\tmp\a:b",
        r"C:\tmp\a\..",
    ] {
        assert!(
            WindowsSelectionPath::parse(bad).is_err(),
            "expected error for adversarial path {bad:?}"
        );
    }
    Ok(())
}

#[test]
fn t2_f15_03_win32_cmdline_pathological_quoting_and_round_trip() -> TestResult {
    // Unterminated quote -> MalformedCommandLine
    assert_eq!(
        split_win32_command_line("\"unterminated", false),
        Err(ActivationError::MalformedCommandLine)
    );

    // NUL byte rejected
    assert_eq!(
        quote_win32_arg("bad\0arg"),
        Err(ActivationError::ControlCharacter)
    );
    assert_eq!(
        split_win32_command_line("bad\0cmd", false),
        Err(ActivationError::MalformedCommandLine)
    );

    // 100 consecutive backslashes before quote, shell metacharacters, and 64 KiB string
    let hundred_bs = format!("{}\"", "\\".repeat(100));
    let meta = r#"a & b < c > d ^ e | %TEMP% "q""#;
    let big_64k = "k".repeat(65_536);
    for s in [hundred_bs.as_str(), meta, big_64k.as_str()] {
        let quoted = quote_win32_arg(s)?;
        let decoded = split_win32_command_line(&quoted, false)?;
        assert_eq!(decoded, vec![s.to_owned()]);
    }
    Ok(())
}

#[test]
fn t2_f15_04_validated_code_fuzz_derived_adversarial_uris() -> TestResult {
    // 1025-byte URI -> LinkTooLong
    let long_1025 = format!("totaldrop://r/{}", "a".repeat(1011));
    assert_eq!(long_1025.len(), 1025);
    assert!(matches!(
        ValidatedCode::from_activation_uri(&long_1025),
        Err(UriValidationError::LinkTooLong {
            byte_len: 1025,
            limit: 1024
        })
    ));

    // Multi-megabyte clipboard garbage -> NoCodeFoundInText without panic/OOM
    let big_garbage = "garbage ".repeat(262_144);
    assert_eq!(
        ValidatedCode::from_clipboard_text(&big_garbage),
        Err(UriValidationError::NoCodeFoundInText)
    );

    // Nested percent-encoding and zero/overflow nameplate must be rejected.
    for bad_uri in [
        "totaldrop://r/%252537-harbor-rocket",
        "totaldrop://r/0-harbor-rocket",
        "totaldrop://r/4294967296-harbor-rocket",
        "totaldrop://r/\u{202E}0-harbor-rocket",
    ] {
        assert!(
            ValidatedCode::from_activation_uri(bad_uri).is_err(),
            "must reject {bad_uri:?}"
        );
    }

    // Mixed Bidi overrides: never panic; any accepted code must strip invisible
    // format characters so display_english and canonical are strictly ASCII.
    for bidi_input in [
        "totaldrop://r/\u{202E}7-harbor-rocket\u{202C}",
        "\u{202E}7-harbor-rocket\u{2066}",
        "Copy \u{202E}7-harbor-rocket\u{2069} now",
    ] {
        for code in [
            ValidatedCode::from_activation_uri(bidi_input),
            ValidatedCode::from_user_input(bidi_input),
            ValidatedCode::from_clipboard_text(bidi_input),
        ]
        .into_iter()
        .flatten()
        {
            assert!(code.display_english.is_ascii());
            assert!(code.canonical.is_ascii());
            assert!(!code.display_english.chars().any(totaldrop_l10n::is_hidden));
            assert!(!code.canonical.chars().any(totaldrop_l10n::is_hidden));
        }
    }

    assert_eq!(
        ValidatedCode::from_user_input("4294967296-harbor-rocket"),
        Err(UriValidationError::BadNameplate)
    );

    let accepted = ValidatedCode::from_activation_uri("totaldrop://r/7-harbor-rocket")?;
    assert!(accepted.display_english.is_ascii() && accepted.canonical.is_ascii());
    Ok(())
}

#[test]
fn t2_f15_05_ndjson_stream_adversarial_nesting_and_recovery() -> TestResult {
    // Deeply nested JSON `{"a":` x 256 -> clean decode error (no stack overflow/panic)
    let deep = format!(
        "{}{}",
        "{\"a\":".repeat(256),
        "0".to_owned() + &"}".repeat(256)
    );
    assert!(WinUiBridgeMessage::from_ndjson_line(&deep).is_err());

    // Unknown "kind"
    assert!(WinUiBridgeMessage::from_ndjson_line(r#"{"kind":"unknown_kind","data":{}}"#).is_err());

    // Trailing partial line without \n
    assert!(decode_ndjson_stream("{\"kind\":\"diagnostic\",\"data\":").is_err());

    // 0-byte input -> empty batch cleanly
    assert!(decode_ndjson_stream("")?.is_empty());

    // CRLF/LF mix with valid messages decodes cleanly after prior errors
    let m1 = WinUiBridgeMessage::MarkAnimationState {
        animate: true,
        hex_light: "#6D4AE0".to_owned(),
        hex_dark: "#A68BFF".to_owned(),
        cycle_ms: 3200,
    };
    let m2 = WinUiBridgeMessage::RouteDecision(RouterDecision::RejectBusy {
        localized_banner: "Transfer in progress".to_owned(),
    });
    let mixed = format!(
        "{}\r\n{}\n",
        serde_json::to_string(&m1)?,
        serde_json::to_string(&m2)?
    );
    assert_eq!(decode_ndjson_stream(&mixed)?, vec![m1, m2]);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tier 3 — Cross-Feature Pairwise Interactions (6 cross-platform + T3-22 FFI part)

#[test]
fn t3_01_rtl_ar_en_tr_region_rlo_filename_and_floor_percent() -> TestResult {
    let ar = c_str("ar")?;
    let en_tr = c_str("en-TR")?;
    let ver = c_str("0.1.0-beta.1")?;
    // SAFETY: All three pointers are live NUL-terminated CStrings.
    let bundle = take_json(unsafe {
        totaldrop_win_ui_bundle_json(ar.as_ptr(), en_tr.as_ptr(), ver.as_ptr())
    })?;
    assert_direct_dto_ok(&bundle)?;
    assert_eq!(
        bundle.get("flow_direction").and_then(Value::as_str),
        Some("RightToLeft")
    );
    assert_eq!(
        bundle.get("verification_title").and_then(Value::as_str),
        Some("Verification words")
    );
    assert_eq!(
        bundle.get("receive_accept").and_then(Value::as_str),
        Some("Accept")
    );
    assert_eq!(
        bundle.get("receive_decline").and_then(Value::as_str),
        Some("Decline")
    );

    let rlo = c_str("invoice\u{202E}fdp.exe")?;
    // SAFETY: `rlo` is a live NUL-terminated CString.
    let san = take_json(unsafe { totaldrop_win_sanitize_filename_json(rlo.as_ptr()) })?;
    assert_eq!(
        san.get("sanitized").and_then(Value::as_str),
        Some("\u{2068}invoice<U+202E>fdp.exe\u{2069}")
    );

    // SAFETY: `en_tr` is a live NUL-terminated CString.
    let pct = take_json(unsafe {
        totaldrop_win_format_percent_json(999_999, 1_000_000, en_tr.as_ptr())
    })?;
    assert_eq!(pct.get("whole").and_then(Value::as_u64), Some(99));
    assert_eq!(pct.get("formatted").and_then(Value::as_str), Some("%99"));
    Ok(())
}

#[test]
fn t3_05_20k_text_rlo_ansi_loopback_receive_sanitize_destroy() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t3-05")?;

    let mut note = String::with_capacity(20_100);
    note.push_str("note-\u{202E}rlo-\x1b[31mansi-");
    while note.chars().count() < 20_000 {
        note.push('z');
    }

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_text(&cfg, &note, "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(totaldrop_win_receive_accept_text(recv.id()), FFI_OK);
    let r_done = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(15))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(15))?;

    let raw = r_done
        .get("received_text")
        .and_then(Value::as_str)
        .ok_or("missing received_text")?;
    assert_eq!(raw.chars().count(), 20_000);
    assert_eq!(raw, note);

    let raw_c = c_str(raw)?;
    // SAFETY: `raw_c` is a live NUL-terminated CString.
    let san = take_json(unsafe { totaldrop_win_sanitize_text_json(raw_c.as_ptr()) })?;
    assert_eq!(san.get("shortened").and_then(Value::as_bool), Some(true));
    assert_eq!(
        san.get("has_hidden_controls").and_then(Value::as_bool),
        Some(true)
    );
    let display = san
        .get("display_text")
        .and_then(Value::as_str)
        .ok_or("missing display_text")?;
    assert_eq!(display.chars().count(), 16_384);
    assert!(display.contains("<U+202E>") && display.contains("<U+001B>"));
    assert_eq!(dir_entry_count(tmp.path())?, 0);

    let recv_id = recv.id();
    std::mem::forget(recv);
    assert_eq!(totaldrop_win_session_destroy(recv_id), FFI_OK);
    Ok(())
}

#[test]
fn t3_06_unc_long_drive_dangerous_paths_and_fuzz_idempotence() -> TestResult {
    let mut long_drive = String::from(r"C:\Archive");
    for idx in 0usize..12 {
        long_drive.push_str(&format!(r"\segment_long_folder_{idx:02}_2026"));
    }
    long_drive.push_str(r"\payload.bin");
    assert!(long_drive.encode_utf16().count() >= 310);

    let unc = r"\\fileserver\share\dir\file.bin";
    let valid_json = serde_json::to_string(&[unc, long_drive.as_str()])?;
    let valid_c = c_str(&valid_json)?;
    // SAFETY: `valid_c` is a live NUL-terminated CString.
    let res = take_json(unsafe { totaldrop_win_validate_paths_json(valid_c.as_ptr()) })?;
    assert_direct_dto_ok(&res)?;
    let arr = res.as_array().ok_or("expected array")?;
    assert_eq!(arr.len(), 2);
    let ext_unc = arr
        .first()
        .and_then(|v| v.get("extended_path"))
        .and_then(Value::as_str)
        .ok_or("missing unc extended_path")?;
    assert_eq!(ext_unc, r"\\?\UNC\fileserver\share\dir\file.bin");
    let ext_long = arr
        .get(1)
        .and_then(|v| v.get("extended_path"))
        .and_then(Value::as_str)
        .ok_or("missing long extended_path")?;
    assert!(ext_long.starts_with(r"\\?\C:\Archive\"));

    // Idempotence invariant: parse(extended_path) == Ok(p)
    for raw in [unc, long_drive.as_str()] {
        let parsed = WindowsSelectionPath::parse(raw)?;
        assert_eq!(WindowsSelectionPath::parse(parsed.extended_path())?, parsed);
    }

    // Dangerous inputs return exact typed ActivationError variants
    for (bad, kind) in [
        (r"C:\tmp\CON.txt", "device_namespace_forbidden"),
        (r"C:\tmp\file.txt:ads", "forbidden_segment_character"),
        (r"\\.\PhysicalDrive0", "device_namespace_forbidden"),
    ] {
        let j = serde_json::to_string(&[bad])?;
        let c = c_str(&j)?;
        // SAFETY: `c` is a live NUL-terminated CString.
        let v = take_json(unsafe { totaldrop_win_validate_paths_json(c.as_ptr()) })?;
        assert_error_envelope(&v, Some(kind), Some("errorStorage"))?;
    }
    Ok(())
}

#[test]
fn t3_18_mailbox_expired_bad_server_and_wrong_code_en_tr_de() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let tmp = TempDirGuard::new("t3-18")?;
    let file = tmp.path().join("sample.bin");
    std::fs::write(&file, b"sample")?;

    // Collect English WrongCode reference for unreviewed `de` gate verification.
    let en_c = c_str("en")?;
    let wc_key = c_str("errorWrongCode")?;
    let empty_args = c_str("{}")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let en_wc = take_json(unsafe {
        totaldrop_win_format_message_json(
            wc_key.as_ptr(),
            empty_args.as_ptr(),
            en_c.as_ptr(),
            en_c.as_ptr(),
        )
    })?;
    let en_wc_str = en_wc
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing en errorWrongCode")?
        .to_owned();

    let tr_c = c_str("tr")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let tr_wc = take_json(unsafe {
        totaldrop_win_format_message_json(
            wc_key.as_ptr(),
            empty_args.as_ptr(),
            tr_c.as_ptr(),
            tr_c.as_ptr(),
        )
    })?;
    let tr_wc_str = tr_wc
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing tr errorWrongCode")?
        .to_owned();
    assert_ne!(tr_wc_str, en_wc_str);

    for (lang, region) in [("en", "en-US"), ("tr", "tr-TR"), ("de", "de-DE")] {
        // 1. mailbox expired -> errorCodeExpired (sender) vs errorCodeNotInUse (receiver)
        let exp_s = MockRendezvous::start(
            "127.0.0.1:0",
            RendezvousFault::ErrorAfterClaim("mailbox expired".to_owned()),
        )?;
        let s = start_send_files(
            &make_cfg_json(&exp_s.url, "", false, false),
            &[file.as_path()],
            lang,
            region,
        )?;
        let mut s_ev = Vec::new();
        let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(10))?;
        assert_eq!(
            sf.get("l10n_key").and_then(Value::as_str),
            Some("errorCodeExpired")
        );
        assert!(
            sf.get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|x| x.contains("mailbox expired"))
        );

        let exp_r = MockRendezvous::start(
            "127.0.0.1:0",
            RendezvousFault::AlwaysError("mailbox expired".to_owned()),
        )?;
        let r = start_receive_connect(
            &make_cfg_json(&exp_r.url, "", false, false),
            "7-harbor-rocket",
            lang,
            region,
        )?;
        let mut r_ev = Vec::new();
        let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(10))?;
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorCodeNotInUse")
        );
        assert!(
            rf.get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|x| x.contains("mailbox expired"))
        );

        // 2. invalid server URL -> errorBadServer
        let bad = start_receive_connect(
            &make_cfg_json("http://127.0.0.1:4000", "", false, false),
            "7-harbor-rocket",
            lang,
            region,
        )?;
        let mut b_ev = Vec::new();
        let bf = wait_for_event(bad.id(), &mut b_ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            bf.get("l10n_key").and_then(Value::as_str),
            Some("errorBadServer")
        );

        // 3. CPace WrongCode -> translated in tr, English-gated in de
        let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
        let cfg = make_cfg_json(&srv.url, "", false, false);
        let ws = start_send_files(&cfg, &[file.as_path()], lang, region)?;
        let mut ws_ev = Vec::new();
        let cr = wait_for_event(ws.id(), &mut ws_ev, "code_ready", Duration::from_secs(10))?;
        let np = cr
            .get("code")
            .and_then(|c| c.get("nameplate"))
            .and_then(Value::as_u64)
            .ok_or("missing nameplate")?;
        let real = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let wrong = if format!("{np}-harbor-wrong") == real {
            format!("{np}-zoo-zone")
        } else {
            format!("{np}-harbor-wrong")
        };
        let wr = start_receive_connect(&cfg, &wrong, lang, region)?;
        let mut wr_ev = Vec::new();
        let wrf = wait_for_event(wr.id(), &mut wr_ev, "failed", Duration::from_secs(15))?;
        assert_eq!(
            wrf.get("l10n_key").and_then(Value::as_str),
            Some("errorWrongCode")
        );
        let summary = wrf
            .get("summary")
            .and_then(Value::as_str)
            .ok_or("missing summary")?;
        match lang {
            "tr" => assert_eq!(summary, tr_wc_str),
            "de" | "en" => assert_eq!(summary, en_wc_str),
            _ => {}
        }
    }
    Ok(())
}

#[test]
fn t3_19_cross_language_tr_sender_ja_receiver_arabic_digits() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t3-19")?;
    let src = tmp.path().join("cross-lang.txt");
    std::fs::write(&src, b"cross-language loopback")?;
    let dest = tmp.path().join("dest");
    std::fs::create_dir_all(&dest)?;

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_files(&cfg, &[src.as_path()], "tr-TR", "tr-TR")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let display = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing display_english")?
        .to_owned();

    // Convert ASCII digits of nameplate to Arabic-Indic digits + uppercase English words.
    let mut arabic_upper = String::new();
    for ch in display.chars() {
        if let Some(d) = ch.to_digit(10) {
            if let Some(ar_digit) = char::from_u32(0x0660u32.saturating_add(d)) {
                arabic_upper.push(ar_digit);
            }
        } else {
            arabic_upper.push(ch.to_ascii_uppercase());
        }
    }

    let recv = start_receive_connect(&cfg, &arabic_upper, "ja-JP", "ja-JP")?;
    let mut r_ev = Vec::new();
    let offer = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    let conn = wait_for_event(send.id(), &mut s_ev, "connected", Duration::from_secs(15))?;
    assert_eq!(
        offer.get("verification_words"),
        conn.get("verification_words")
    );

    // Check UI bundles: `tr` has reviewed Turkish security strings (`has_draft_translations == false`),
    // `ja` has English-gated security strings (`has_draft_translations == true`).
    let ver = c_str("0.1.0-beta.1")?;
    let tr = c_str("tr-TR")?;
    let ja = c_str("ja-JP")?;
    // SAFETY: All three pointers are live NUL-terminated CStrings.
    let tr_b =
        take_json(unsafe { totaldrop_win_ui_bundle_json(tr.as_ptr(), tr.as_ptr(), ver.as_ptr()) })?;
    // SAFETY: All three pointers are live NUL-terminated CStrings.
    let ja_b =
        take_json(unsafe { totaldrop_win_ui_bundle_json(ja.as_ptr(), ja.as_ptr(), ver.as_ptr()) })?;
    assert_eq!(
        tr_b.get("has_draft_translations").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        tr_b.get("verification_title").and_then(Value::as_str),
        Some("Doğrulama kelimeleri")
    );
    assert_eq!(
        ja_b.get("has_draft_translations").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        ja_b.get("verification_title").and_then(Value::as_str),
        Some("Verification words")
    );
    assert_eq!(
        ja_b.get("receive_accept").and_then(Value::as_str),
        Some("Accept")
    );

    assert_eq!(accept_files(recv.id(), &dest)?, FFI_OK);
    let _ = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(15))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(15))?;
    assert_eq!(
        std::fs::read(dest.join("cross-lang.txt"))?,
        b"cross-language loopback"
    );
    Ok(())
}

#[test]
fn t3_21_stronger_3_word_code_share_clipboard_autocomplete_transfer() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t3-21")?;
    let payload = pseudo_random_bytes(321, 16_384);
    let src = tmp.path().join("strong3.bin");
    std::fs::write(&src, &payload)?;
    let dest = tmp.path().join("dest");
    std::fs::create_dir_all(&dest)?;

    let cfg = make_cfg_json(srv.url(), "", false, true);
    let send = start_send_files(&cfg, &[src.as_path()], "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    assert_eq!(
        cr.get("code")
            .and_then(|c| c.get("word_count"))
            .and_then(Value::as_u64),
        Some(3)
    );
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing display_english")?
        .to_owned();

    // Offline share link format -> extract_clipboard_code_json recovers exact 3-word code.
    let share_link = format!("https://totaldrop.app/r#{code}");
    let share_c = c_str(&share_link)?;
    // SAFETY: `share_c` is a live NUL-terminated CString.
    let extracted =
        take_json(unsafe { totaldrop_win_extract_clipboard_code_json(share_c.as_ptr()) })?;
    assert_eq!(
        extracted.get("display_english").and_then(Value::as_str),
        Some(code.as_str())
    );
    assert_eq!(extracted.get("word_count").and_then(Value::as_u64), Some(3));

    // Autocomplete on 2-letter prefix of word 1.
    let mut parts = code.split('-');
    let _nameplate = parts.next().ok_or("missing nameplate part")?;
    let word1 = parts.next().ok_or("missing word 1")?;
    let prefix2: String = word1.chars().take(2).collect();
    let p2_c = c_str(&prefix2)?;
    // SAFETY: `p2_c` is a live NUL-terminated CString.
    let top4 = take_json(unsafe { totaldrop_win_code_completions_json(p2_c.as_ptr(), 4) })?;
    let top4_arr = top4.as_array().ok_or("expected array")?;
    assert!(!top4_arr.is_empty() && top4_arr.len() <= 4);
    for item in top4_arr {
        assert!(item.as_str().is_some_and(|w| w.starts_with(&prefix2)));
    }
    // Full wordlist prefix query must contain word1.
    // SAFETY: `p2_c` is a live NUL-terminated CString.
    let all_matches =
        take_json(unsafe { totaldrop_win_code_completions_json(p2_c.as_ptr(), 2048) })?;
    let all_arr = all_matches.as_array().ok_or("expected array")?;
    assert!(
        all_arr.iter().any(|v| v.as_str() == Some(word1)),
        "autocomplete for {prefix2:?} did not include {word1:?}"
    );

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(accept_files(recv.id(), &dest)?, FFI_OK);
    let _ = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(15))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(15))?;
    assert_eq!(
        blake3::hash(&std::fs::read(dest.join("strong3.bin"))?),
        blake3::hash(&payload)
    );
    Ok(())
}

#[test]
fn t3_22_ffi_adversarial_corpus() -> TestResult {
    // 1. NULL pointers across validate_uri_json, validate_input_json, validate_paths_json
    // SAFETY: NULL is explicitly handled by all three FFI exports.
    let e_uri_null = take_json(unsafe { totaldrop_win_validate_uri_json(ptr::null()) })?;
    assert_error_envelope(&e_uri_null, Some("null_pointer"), Some("errorInvalidCode"))?;

    // SAFETY: NULL is explicitly handled by all three FFI exports.
    let e_in_null = take_json(unsafe { totaldrop_win_validate_input_json(ptr::null()) })?;
    assert_error_envelope(&e_in_null, Some("null_pointer"), Some("receiveCodeInvalid"))?;

    // SAFETY: NULL is explicitly handled by all three FFI exports.
    let e_path_null = take_json(unsafe { totaldrop_win_validate_paths_json(ptr::null()) })?;
    assert_error_envelope(&e_path_null, Some("null_pointer"), Some("errorStorage"))?;

    // 2. Invalid UTF-8 `[0xFF, 0xFE, 0x00]`
    let bad_utf8: [u8; 3] = [0xFF, 0xFE, 0x00];
    let bad_ptr = bad_utf8.as_ptr().cast::<c_char>();
    // SAFETY: `bad_utf8` is a NUL-terminated buffer alive for each call.
    let e_uri_utf8 = take_json(unsafe { totaldrop_win_validate_uri_json(bad_ptr) })?;
    assert_error_envelope(&e_uri_utf8, Some("invalid_utf8"), Some("errorInvalidCode"))?;

    // SAFETY: `bad_utf8` is a NUL-terminated buffer alive for each call.
    let e_in_utf8 = take_json(unsafe { totaldrop_win_validate_input_json(bad_ptr) })?;
    assert_error_envelope(&e_in_utf8, Some("invalid_utf8"), Some("receiveCodeInvalid"))?;

    // SAFETY: `bad_utf8` is a NUL-terminated buffer alive for each call.
    let e_path_utf8 = take_json(unsafe { totaldrop_win_validate_paths_json(bad_ptr) })?;
    assert_error_envelope(&e_path_utf8, Some("invalid_utf8"), Some("errorStorage"))?;

    // 3. 1025-byte URI
    let long_uri = c_str(&format!("totaldrop://r/{}", "a".repeat(1011)))?;
    // SAFETY: `long_uri` is a live NUL-terminated CString.
    let e_long_uri = take_json(unsafe { totaldrop_win_validate_uri_json(long_uri.as_ptr()) })?;
    assert_error_envelope(&e_long_uri, Some("link_too_long"), Some("errorInvalidCode"))?;

    // 4. 32_767-UTF-16 path
    let long_path = format!(r"C:\{}", "a".repeat(32_760));
    let long_path_json = serde_json::to_string(&[long_path])?;
    let long_path_c = c_str(&long_path_json)?;
    // SAFETY: `long_path_c` is a live NUL-terminated CString.
    let e_long_path =
        take_json(unsafe { totaldrop_win_validate_paths_json(long_path_c.as_ptr()) })?;
    let msg = assert_error_envelope(&e_long_path, Some("path_too_long"), Some("errorStorage"))?;
    assert!(msg.contains("32767"), "expected 32767 in message: {msg:?}");

    // 5. Verify IpcFrameDecoder zero pre-allocation invariant on 4 MiB + 1 & 0xFFFFFFFF
    let mut dec = IpcFrameDecoder::new();
    assert!(dec.push_bytes(&[0x01, 0x00, 0x40, 0x00]).is_err());
    assert_eq!(dec.payload_capacity(), 0);
    let mut dec2 = IpcFrameDecoder::new();
    assert!(dec2.push_bytes(&[0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    assert_eq!(dec2.payload_capacity(), 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tier 4 — Real-World End-to-End Application Workloads (3 cross-platform tests)

#[test]
fn t4_01_multi_file_nested_dir_blake3_no_clobber_and_shutdown() -> TestResult {
    let _guard = SHUTDOWN_GATE.write().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t4-01")?;

    let src_root = tmp.path().join("src");
    let photos_dir = src_root.join("photos").join("2026");
    std::fs::create_dir_all(&photos_dir)?;

    let empty_file = src_root.join("empty.txt");
    let archive_file = src_root.join("archive.bin");
    let kose_file = photos_dir.join("köşe-ünicode.bin");
    let note_file = src_root.join("note.txt");

    let archive_bytes = pseudo_random_bytes(401, 5 * 1024 * 1024);
    let kose_bytes = pseudo_random_bytes(4012, 32 * 1024);
    let note_incoming: &[u8] = b"INCOMING-T4-01-NOTE";

    std::fs::write(&empty_file, b"")?;
    std::fs::write(&archive_file, &archive_bytes)?;
    std::fs::write(&kose_file, &kose_bytes)?;
    std::fs::write(&note_file, note_incoming)?;

    let dest_dir = tmp.path().join("Downloads").join("TotalDrop");
    std::fs::create_dir_all(&dest_dir)?;
    std::fs::write(dest_dir.join("note.txt"), b"PRE-EXISTING-NOTE")?;

    let cfg = make_cfg_json(srv.url(), "", false, false);
    let send = start_send_files(
        &cfg,
        &[
            empty_file.as_path(),
            archive_file.as_path(),
            src_root.join("photos").as_path(),
            note_file.as_path(),
        ],
        "en-US",
        "en-US",
    )?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(15))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing display_english")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let offer = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    let conn = wait_for_event(send.id(), &mut s_ev, "connected", Duration::from_secs(15))?;
    assert_eq!(
        offer.get("verification_words"),
        conn.get("verification_words")
    );

    assert_eq!(accept_files(recv.id(), &dest_dir)?, FFI_OK);
    let _ = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(40))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(40))?;

    // Check monotonic #483 floor progress ticks.
    let expected_total = u64::try_from(archive_bytes.len())?
        .saturating_add(u64::try_from(kose_bytes.len())?)
        .saturating_add(u64::try_from(note_incoming.len())?);
    let mut prev = 0u64;
    for ev in s_ev
        .iter()
        .filter(|e| e.get("event").and_then(Value::as_str) == Some("progress"))
    {
        let done = ev.get("done_bytes").and_then(Value::as_u64).unwrap_or(0);
        let whole = ev
            .get("percent")
            .and_then(|p| p.get("whole"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        assert!(done >= prev);
        prev = done;
        if done < expected_total {
            assert!(
                whole <= 99,
                "100% appeared early at done={done}/{expected_total}"
            );
        }
    }

    // Verify BLAKE3 hashes & no-clobber.
    assert_eq!(std::fs::read(dest_dir.join("empty.txt"))?, b"");
    assert_eq!(
        blake3::hash(&std::fs::read(dest_dir.join("archive.bin"))?),
        blake3::hash(&archive_bytes)
    );
    assert_eq!(
        blake3::hash(&std::fs::read(
            dest_dir
                .join("photos")
                .join("2026")
                .join("köşe-ünicode.bin")
        )?),
        blake3::hash(&kose_bytes)
    );
    assert_eq!(
        std::fs::read(dest_dir.join("note.txt"))?,
        b"PRE-EXISTING-NOTE"
    );
    assert_eq!(std::fs::read(dest_dir.join("note (2).txt"))?, note_incoming);
    assert!(!has_part_files(&dest_dir)?);

    std::mem::forget(send);
    std::mem::forget(recv);
    assert_eq!(totaldrop_win_shutdown(1500), FFI_OK);
    Ok(())
}

#[test]
fn t4_02_plain_text_e2e_1mib_boundary_32kib_unicode_rlo_ansi() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let tmp = TempDirGuard::new("t4-02")?;
    let cfg = make_cfg_json(srv.url(), "", false, false);

    // 1. 1 MiB accepted vs 1 MiB + 1 B rejected (`sendTextTooLong`).
    {
        let exact = "M".repeat(1_048_576);
        let s = start_send_text(&cfg, &exact, "en-US", "en-US")?;
        let mut ev = Vec::new();
        let cr = wait_for_event(s.id(), &mut ev, "code_ready", Duration::from_secs(10))?;
        assert_eq!(
            cr.get("total_bytes").and_then(Value::as_u64),
            Some(1_048_576)
        );
    }
    {
        let over = "M".repeat(1_048_577);
        let s = start_send_text(&cfg, &over, "en-US", "en-US")?;
        let mut ev = Vec::new();
        let f = wait_for_event(s.id(), &mut ev, "failed", Duration::from_secs(5))?;
        assert_eq!(
            f.get("l10n_key").and_then(Value::as_str),
            Some("sendTextTooLong")
        );
    }

    // 2. 32 KiB UTF-8 message with emoji, Arabic + Latin, U+202E RLO, and ANSI `\x1b[31m`.
    let head = "\u{1F510}\u{1F680} مرحبا Hello \u{202E}spoof \x1b[31mred ";
    let mut payload = String::with_capacity(32 * 1024 + 64);
    payload.push_str(head);
    while payload.len() < 32 * 1024 {
        payload.push('T');
    }
    assert_eq!(payload.len(), 32 * 1024);

    let send = start_send_text(&cfg, &payload, "en-US", "en-US")?;
    let mut s_ev = Vec::new();
    let cr = wait_for_event(send.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
    let code = cr
        .get("code")
        .and_then(|c| c.get("display_english"))
        .and_then(Value::as_str)
        .ok_or("missing code")?
        .to_owned();

    let recv = start_receive_connect(&cfg, &code, "en-US", "en-US")?;
    let mut r_ev = Vec::new();
    let _ = wait_for_event(recv.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(totaldrop_win_receive_accept_text(recv.id()), FFI_OK);
    let r_done = wait_for_event(recv.id(), &mut r_ev, "done", Duration::from_secs(15))?;
    let _ = wait_for_event(send.id(), &mut s_ev, "done", Duration::from_secs(15))?;

    let received = r_done
        .get("received_text")
        .and_then(Value::as_str)
        .ok_or("missing received_text")?;
    assert_eq!(received.len(), 32 * 1024);
    assert_eq!(received, payload);
    assert_eq!(dir_entry_count(tmp.path())?, 0);

    let rec_c = c_str(received)?;
    // SAFETY: `rec_c` is a live NUL-terminated CString.
    let san = take_json(unsafe { totaldrop_win_sanitize_text_json(rec_c.as_ptr()) })?;
    assert_eq!(san.get("shortened").and_then(Value::as_bool), Some(true));
    assert_eq!(
        san.get("has_hidden_controls").and_then(Value::as_bool),
        Some(true)
    );
    let display = san
        .get("display_text")
        .and_then(Value::as_str)
        .ok_or("missing display_text")?;
    assert_eq!(display.chars().count(), 16_384);
    assert!(display.contains("<U+202E>") && display.contains("<U+001B>"));

    let recv_id = recv.id();
    std::mem::forget(recv);
    assert_eq!(totaldrop_win_session_destroy(recv_id), FFI_OK);
    Ok(())
}

#[test]
fn t4_03_wrong_code_decline_cancel_and_recovery_lifecycle() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = LoopbackRendezvous::start()?;
    let throttled_relay = MockRelay::start(RelayMode::Throttled(Duration::from_millis(2)))?;
    let tmp = TempDirGuard::new("t4-03")?;

    let small_file = tmp.path().join("small.bin");
    let small_bytes = pseudo_random_bytes(4031, 128 * 1024);
    std::fs::write(&small_file, &small_bytes)?;

    let large_file = tmp.path().join("large10m.bin");
    let large_bytes = pseudo_random_bytes(4032, 10 * 1024 * 1024);
    std::fs::write(&large_file, &large_bytes)?;

    let direct_cfg = make_cfg_json(srv.url(), "", false, false);
    let throttled_cfg = make_cfg_json(srv.url(), &throttled_relay.url, true, false);

    // Collect English errorWrongCode for unreviewed `de` verification.
    let en_c = c_str("en")?;
    let wc_key = c_str("errorWrongCode")?;
    let empty_args = c_str("{}")?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let en_wc = take_json(unsafe {
        totaldrop_win_format_message_json(
            wc_key.as_ptr(),
            empty_args.as_ptr(),
            en_c.as_ptr(),
            en_c.as_ptr(),
        )
    })?;
    let en_wc_str = en_wc
        .get("formatted")
        .and_then(Value::as_str)
        .ok_or("missing en errorWrongCode")?
        .to_owned();

    // Step 1: Wrong code (`de` unreviewed -> English-gated errorWrongCode) + nameplate retirement
    {
        let s = start_send_files(&direct_cfg, &[small_file.as_path()], "de-DE", "de-DE")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(s.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let np = cr
            .get("code")
            .and_then(|c| c.get("nameplate"))
            .and_then(Value::as_u64)
            .ok_or("missing nameplate")?;
        let real = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?
            .to_owned();
        let wrong = if format!("{np}-harbor-wrong") == real {
            format!("{np}-zoo-zone")
        } else {
            format!("{np}-harbor-wrong")
        };
        let r = start_receive_connect(&direct_cfg, &wrong, "de-DE", "de-DE")?;
        let mut r_ev = Vec::new();
        let rf = wait_for_event(r.id(), &mut r_ev, "failed", Duration::from_secs(15))?;
        let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(15))?;
        assert_eq!(
            rf.get("l10n_key").and_then(Value::as_str),
            Some("errorWrongCode")
        );
        assert_eq!(
            sf.get("l10n_key").and_then(Value::as_str),
            Some("errorWrongCode")
        );
        assert_eq!(
            rf.get("summary").and_then(Value::as_str),
            Some(en_wc_str.as_str())
        );

        // Verify nameplate retired
        let retry = start_receive_connect(&direct_cfg, &real, "en-US", "en-US")?;
        let mut rt_ev = Vec::new();
        let rtf = wait_for_event(retry.id(), &mut rt_ev, "failed", Duration::from_secs(10))?;
        assert_eq!(
            rtf.get("l10n_key").and_then(Value::as_str),
            Some("errorCodeNotInUse")
        );
    }

    // Step 2: Clean decline with 0 bytes written
    {
        let dest2 = tmp.path().join("dest2");
        std::fs::create_dir_all(&dest2)?;
        let s = start_send_files(&direct_cfg, &[small_file.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(s.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?
            .to_owned();
        let r = start_receive_connect(&direct_cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let _ = wait_for_event(r.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
        assert_eq!(totaldrop_win_receive_decline(r.id()), FFI_OK);
        let _ = wait_for_event(r.id(), &mut r_ev, "declined", Duration::from_secs(10))?;
        let sf = wait_for_event(s.id(), &mut s_ev, "failed", Duration::from_secs(15))?;
        assert_eq!(
            sf.get("l10n_key").and_then(Value::as_str),
            Some("errorDeclined")
        );
        assert_eq!(dir_entry_count(&dest2)?, 0);
    }

    // Step 3: 10 MiB throttled mid-stream cancel + zero .part leftovers
    {
        let dest3 = tmp.path().join("dest3");
        std::fs::create_dir_all(&dest3)?;
        let s = start_send_files(&throttled_cfg, &[large_file.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(s.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?
            .to_owned();
        let r = start_receive_connect(&throttled_cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let _ = wait_for_event(r.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
        assert_eq!(accept_files(r.id(), &dest3)?, FFI_OK);
        let _ = wait_for_event(s.id(), &mut s_ev, "progress", Duration::from_secs(20))?;
        assert_eq!(totaldrop_win_session_cancel(s.id()), FFI_OK);
        let _ = wait_for_any_terminal(s.id(), &mut s_ev, Duration::from_secs(20))?;
        let _ = wait_for_any_terminal(r.id(), &mut r_ev, Duration::from_secs(20))?;
        assert!(!has_part_files(&dest3)?);
        assert_eq!(dir_entry_count(&dest3)?, 0);
    }

    // Step 4: Clean 128 KiB recovery transfer on the same long-lived runtime
    {
        let dest4 = tmp.path().join("dest4");
        std::fs::create_dir_all(&dest4)?;
        let s = start_send_files(&direct_cfg, &[small_file.as_path()], "en-US", "en-US")?;
        let mut s_ev = Vec::new();
        let cr = wait_for_event(s.id(), &mut s_ev, "code_ready", Duration::from_secs(10))?;
        let code = cr
            .get("code")
            .and_then(|c| c.get("display_english"))
            .and_then(Value::as_str)
            .ok_or("missing code")?
            .to_owned();
        let r = start_receive_connect(&direct_cfg, &code, "en-US", "en-US")?;
        let mut r_ev = Vec::new();
        let _ = wait_for_event(r.id(), &mut r_ev, "offer_ready", Duration::from_secs(15))?;
        assert_eq!(accept_files(r.id(), &dest4)?, FFI_OK);
        let _ = wait_for_event(r.id(), &mut r_ev, "done", Duration::from_secs(20))?;
        let _ = wait_for_event(s.id(), &mut s_ev, "done", Duration::from_secs(20))?;
        assert_eq!(
            blake3::hash(&std::fs::read(dest4.join("small.bin"))?),
            blake3::hash(&small_bytes)
        );
        let s_id = s.id();
        let r_id = r.id();
        std::mem::forget(s);
        std::mem::forget(r);
        assert_eq!(totaldrop_win_session_destroy(s_id), FFI_OK);
        assert_eq!(totaldrop_win_session_destroy(r_id), FFI_OK);
        // Verify blank dest_dir returns FFI_ERR_INVALID_ARG cleanly (no leaked handle).
        let blank = c_str("   ")?;
        // SAFETY: `blank` is a live NUL-terminated CString.
        let rc_blank = unsafe { totaldrop_win_receive_accept_files(s_id, blank.as_ptr()) };
        assert_eq!(rc_blank, FFI_ERR_INVALID_ARG);
    }
    Ok(())
}
