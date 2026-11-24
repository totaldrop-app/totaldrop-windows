// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Static 2-thread Tokio runtime, monotonic `u64` transfer session registry,
//! and NDJSON event stream engine for `totaldrop-windows-ffi`.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use totaldrop_core::{Error as CoreError, Event, IncomingOffer, MAX_TEXT, TEXT_FILE};
use totaldrop_windows_bridge::{
    BridgeNetworkConfig, LocalizedTransferError, RegionalPercent, SanitizedPeerText,
    TransferViewEvent, ValidatedCode, WindowsCancellationToken, WindowsLocalizer,
    check_windows_destination, connect_windows_receive, prepare_windows_send,
    prepare_windows_text_send, sanitize_peer_filename, sanitize_peer_text,
};

use crate::quit::{self, STOPPING, TRANSFERS};
use crate::{FFI_ERR_INVALID_HANDLE, FFI_ERR_INVALID_STATE, FFI_OK};

/// Static 2-thread Tokio runtime driving all async network, QUIC, crypto, and
/// disk I/O off the WinUI 3 UI thread (ADR 0016, Linux `runtime.rs` parity).
static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("totaldrop-win")
        .build()
        .unwrap_or_else(|_| std::process::abort())
});

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

static SESSIONS: LazyLock<Mutex<HashMap<u64, Arc<SessionEntry>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// JSON-deserializable network config allowing omitted optional fields to fall
/// back to [`BridgeNetworkConfig::default`] while preserving explicit empty
/// strings (e.g. `"relay_server": ""`, `"stun_server": ""` in loopback tests).
#[derive(Debug, Deserialize)]
pub(crate) struct FfiNetworkConfig {
    rendezvous_server: Option<String>,
    relay_server: Option<String>,
    stun_server: Option<String>,
    #[serde(default)]
    privacy_relay_only: bool,
    #[serde(default)]
    stronger_three_word_code: bool,
}

impl FfiNetworkConfig {
    pub(crate) fn into_bridge_config(self) -> BridgeNetworkConfig {
        let defaults = BridgeNetworkConfig::default();
        BridgeNetworkConfig {
            rendezvous_server: self.rendezvous_server.unwrap_or(defaults.rendezvous_server),
            relay_server: self.relay_server.unwrap_or(defaults.relay_server),
            stun_server: self.stun_server.unwrap_or(defaults.stun_server),
            privacy_relay_only: self.privacy_relay_only,
            stronger_three_word_code: self.stronger_three_word_code,
        }
    }
}

/// NDJSON event emitted by `totaldrop_win_session_poll_events_ndjson`.
///
/// Tagged with `"event"` in `snake_case` and `is_text` uniformly across
/// `code_ready`, `offer_ready`, `done`, and `declined` for reflection-free
/// `.NET 10` source-generated deserialization.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(crate) enum SessionEvent {
    CodeReady {
        code: ValidatedCode,
        share_text: String,
        files: usize,
        dirs: usize,
        total_bytes: u64,
        formatted_total: String,
        skipped: usize,
        is_text: bool,
    },
    Waiting {
        caption: String,
    },
    Connected {
        verification_words: Vec<String>,
        joined_words_ltr: String,
    },
    OfferReady {
        files: usize,
        dirs: usize,
        total_bytes: u64,
        formatted_total: String,
        is_text: bool,
        top_level: Vec<String>,
        top_level_sanitized: Vec<String>,
        more_count: usize,
        verification_words: Vec<String>,
        joined_words_ltr: String,
    },
    Progress {
        done_bytes: u64,
        total_bytes: u64,
        formatted_done: String,
        formatted_total: String,
        percent: RegionalPercent,
    },
    Done {
        files_ok: usize,
        files_failed: usize,
        bytes: u64,
        formatted_bytes: String,
        is_text: bool,
        saved_to: Option<String>,
        placed: Vec<String>,
        received_text: Option<String>,
        sanitized_text: Option<SanitizedPeerText>,
    },
    Declined {
        is_text: bool,
        summary: String,
    },
    Failed {
        kind: String,
        l10n_key: String,
        cause: String,
        summary: String,
        cause_detail: Option<String>,
        technical_english: String,
    },
}

impl SessionEvent {
    fn from_localized_error(err: LocalizedTransferError) -> Self {
        Self::Failed {
            kind: err.kind,
            l10n_key: err.l10n_key,
            cause: err.cause,
            summary: err.summary,
            cause_detail: err.cause_detail,
            technical_english: err.technical_english,
        }
    }

    fn from_view_event(event: TransferViewEvent) -> Self {
        match event {
            TransferViewEvent::Waiting { caption } => Self::Waiting { caption },
            TransferViewEvent::Connected {
                verification_words,
                joined_words_ltr,
            } => Self::Connected {
                verification_words,
                joined_words_ltr,
            },
            TransferViewEvent::Progress {
                done_bytes,
                total_bytes,
                formatted_done,
                formatted_total,
                percent,
            } => Self::Progress {
                done_bytes,
                total_bytes,
                formatted_done,
                formatted_total,
                percent,
            },
        }
    }
}

struct SessionInner {
    events: VecDeque<SessionEvent>,
    pending_offer: Option<IncomingOffer>,
    terminal: bool,
    destroyed: bool,
}

struct SessionEntry {
    cancel: WindowsCancellationToken,
    localizer: Arc<WindowsLocalizer>,
    state: Mutex<SessionInner>,
}

impl SessionEntry {
    fn new(localizer: WindowsLocalizer) -> Arc<Self> {
        Arc::new(Self {
            cancel: WindowsCancellationToken::new(),
            localizer: Arc::new(localizer),
            state: Mutex::new(SessionInner {
                events: VecDeque::new(),
                pending_offer: None,
                terminal: false,
                destroyed: false,
            }),
        })
    }

    fn push_event(&self, event: SessionEvent) {
        if let Ok(mut inner) = self.state.lock()
            && !inner.destroyed
            && !inner.terminal
        {
            inner.events.push_back(event);
        }
    }

    fn finish_with(&self, event: SessionEvent) {
        if let Ok(mut inner) = self.state.lock()
            && !inner.destroyed
            && !inner.terminal
        {
            inner.terminal = true;
            inner.events.push_back(event);
        }
    }

    fn is_destroyed(&self) -> bool {
        self.state.lock().is_ok_and(|inner| inner.destroyed)
    }

    fn make_core_events(self: &Arc<Self>) -> totaldrop_core::Events {
        let weak = Arc::downgrade(self);
        Arc::new(move |core_event: Event| {
            if let Some(entry) = weak.upgrade() {
                let view = TransferViewEvent::from_core_event(core_event, &entry.localizer);
                entry.push_event(SessionEvent::from_view_event(view));
            }
        })
    }
}

fn alloc_session(localizer: WindowsLocalizer) -> Option<(u64, Arc<SessionEntry>)> {
    let mut sid = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    if sid == 0 {
        sid = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    }
    let entry = SessionEntry::new(localizer);
    let mut table = SESSIONS.lock().ok()?;
    table.insert(sid, Arc::clone(&entry));
    Some((sid, entry))
}

fn lookup_session(session_id: u64) -> Option<Arc<SessionEntry>> {
    if session_id == 0 {
        return None;
    }
    SESSIONS.lock().ok()?.get(&session_id).cloned()
}

fn clean_display_path(path: &Path) -> String {
    let raw = path.display().to_string();
    if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        raw
    }
}

fn resolve_send_paths(raw_paths: Vec<String>) -> Result<Vec<PathBuf>, String> {
    #[cfg(windows)]
    {
        let normalized = totaldrop_windows_bridge::validate_windows_paths(&raw_paths)
            .map_err(|e| e.to_string())?;
        Ok(normalized
            .into_iter()
            .map(|p| PathBuf::from(p.extended_path))
            .collect())
    }
    #[cfg(not(windows))]
    {
        let mut out = Vec::with_capacity(raw_paths.len());
        for raw in raw_paths {
            if raw.is_empty() {
                return Err("send path must not be empty".to_owned());
            }
            if raw.as_bytes().contains(&0) {
                return Err("send path must not contain a NUL byte".to_owned());
            }
            out.push(PathBuf::from(raw));
        }
        Ok(out)
    }
}

fn is_valid_uri_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn is_loopback_ws_authority(authority: &str) -> bool {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return false;
        };
        let port_ok = after.is_empty()
            || after.strip_prefix(':').is_some_and(|p| {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
            });
        host == "::1" && port_ok
    } else {
        let (host, port_opt) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        let port_ok = port_opt.is_none_or(|p| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
        });
        matches!(host, "localhost" | "127.0.0.1") && port_ok
    }
}

fn has_valid_authority_syntax(authority: &str) -> bool {
    if authority.is_empty() {
        return false;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        after.is_empty()
            || after.strip_prefix(':').is_some_and(|p| {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
            })
    } else {
        let (host, port_opt) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        !host.is_empty()
            && !host.contains('[')
            && !host.contains(']')
            && !host.contains(':')
            && port_opt.is_none_or(|p| {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
            })
    }
}

/// Maps a rendezvous URL already rejected by `totaldrop_core::relay::check_url`
/// into the exact `CoreError::Rendezvous` `BAD_ADDRESS` message from
/// `totaldrop_core::rendezvous::check_url` so invalid URLs fail offline before
/// scanning disk or generating ephemeral keys.
fn classify_bad_rendezvous_url(url: &str) -> CoreError {
    let msg = if url.is_empty() || !url.is_ascii() || url.bytes().any(|b| b <= 0x20 || b == 0x7F) {
        "invalid server address"
    } else if let Some((scheme, rest)) = url.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if !is_valid_uri_scheme(scheme) || authority.is_empty() {
            "invalid server address"
        } else if authority.contains('@') {
            "the server address must not contain a user name"
        } else if !has_valid_authority_syntax(authority) {
            "invalid server address"
        } else if scheme == "ws" {
            if is_loopback_ws_authority(authority) {
                "invalid server address"
            } else {
                "unencrypted ws:// is only allowed for a server on this machine"
            }
        } else if scheme == "wss" {
            "invalid server address"
        } else {
            "the server address must start with wss://"
        }
    } else if url.contains('@') {
        "the server address must not contain a user name"
    } else {
        "the server address must start with wss://"
    };
    CoreError::Rendezvous(msg.to_owned())
}

fn validate_session_server_urls(cfg: &BridgeNetworkConfig) -> Result<(), CoreError> {
    let rdv_trimmed = cfg.rendezvous_server.trim();
    if totaldrop_core::relay::check_url(rdv_trimmed).is_err() {
        return Err(classify_bad_rendezvous_url(rdv_trimmed));
    }
    if !BridgeNetworkConfig::is_valid_rendezvous_url(&cfg.rendezvous_server) {
        return Err(CoreError::Rendezvous("invalid server address".to_owned()));
    }

    let relay_trimmed = cfg.relay_server.trim();
    if !relay_trimmed.is_empty() && !BridgeNetworkConfig::is_valid_rendezvous_url(&cfg.relay_server)
    {
        return Err(CoreError::Rendezvous("invalid server address".to_owned()));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ManifestCounts {
    files: usize,
    dirs: usize,
}

/// Counts manifest `(files, dirs)` for `paths` using the exact same metadata
/// classification and limits as `totaldrop_core::transfer::scan` without
/// opening or hashing any file contents.
fn count_manifest_entries(
    paths: &[PathBuf],
    stop: &totaldrop_core::Stop,
) -> Option<ManifestCounts> {
    let mut counts = ManifestCounts { files: 0, dirs: 0 };
    for root in paths {
        if stop.is_stopped() {
            return None;
        }
        let meta = std::fs::symlink_metadata(root).ok()?;
        if meta.file_type().is_symlink() {
            return None;
        }
        walk_manifest_counts(root, 0, &mut counts, stop)?;
    }
    if counts.files == 0 && counts.dirs == 0 {
        return None;
    }
    Some(counts)
}

fn walk_manifest_counts(
    path: &Path,
    parent_depth: usize,
    counts: &mut ManifestCounts,
    stop: &totaldrop_core::Stop,
) -> Option<()> {
    if stop.is_stopped() {
        return None;
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    let _name = path.file_name().and_then(|n| n.to_str())?;
    let depth = parent_depth.saturating_add(1);
    if depth > totaldrop_proto::limits::MAX_PATH_DEPTH {
        return None;
    }
    if counts.files.saturating_add(counts.dirs) >= totaldrop_proto::limits::MAX_ENTRIES {
        return None;
    }
    let ft = meta.file_type();
    if ft.is_file() {
        counts.files = counts.files.saturating_add(1);
    } else if ft.is_dir() {
        counts.dirs = counts.dirs.saturating_add(1);
        let mut children: Vec<PathBuf> = std::fs::read_dir(path)
            .ok()?
            .map(|e| e.map(|entry| entry.path()))
            .collect::<std::io::Result<_>>()
            .ok()?;
        children.sort();
        for child in children {
            walk_manifest_counts(&child, depth, counts, stop)?;
        }
    }
    // Nested symbolic links, FIFOs, sockets, and special files are skipped
    // (never counted, never followed), matching `transfer::walk`.
    Some(())
}

/// Reconciles metadata-walk counts against the authoritative `(total_entries,
/// total_bytes)` frozen inside `PreparedSend`, always preserving
/// `files + dirs == total_entries` and `(total_bytes > 0) => (files >= 1)`.
fn reconcile_manifest_counts(
    walked: Option<ManifestCounts>,
    total_entries: usize,
    total_bytes: u64,
) -> (usize, usize) {
    match walked {
        Some(c)
            if c.files.saturating_add(c.dirs) == total_entries
                && (total_bytes == 0 || c.files > 0) =>
        {
            (c.files, c.dirs)
        }
        Some(c) => {
            let max_dirs = if total_bytes > 0 {
                total_entries.saturating_sub(1)
            } else {
                total_entries
            };
            let dirs = c.dirs.min(max_dirs);
            let files = total_entries.saturating_sub(dirs);
            (files, dirs)
        }
        None => (total_entries, 0),
    }
}

/// Starts an asynchronous file/folder send session and returns a non-zero
/// monotonic handle (`0` on internal registration failure).
pub(crate) fn start_send_files(
    cfg: BridgeNetworkConfig,
    raw_paths: Vec<String>,
    localizer: WindowsLocalizer,
) -> u64 {
    let Some((sid, entry)) = alloc_session(localizer) else {
        return 0;
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        let paths = match resolve_send_paths(raw_paths) {
            Ok(p) => p,
            Err(msg) => {
                entry.finish_with(SessionEvent::Failed {
                    kind: "storage".to_owned(),
                    l10n_key: "errorStorage".to_owned(),
                    cause: String::new(),
                    summary: entry.localizer.text("errorStorage"),
                    cause_detail: None,
                    technical_english: totaldrop_l10n::reveal_controls(&msg),
                });
                return;
            }
        };

        if let Err(err) = validate_session_server_urls(&cfg) {
            let localized = LocalizedTransferError::from_core_error(&err, &entry.localizer, true);
            entry.finish_with(SessionEvent::from_localized_error(localized));
            return;
        }

        let prepared = match prepare_windows_send(&cfg, &paths, &entry.cancel).await {
            Ok(p) => p,
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, true);
                entry.finish_with(SessionEvent::from_localized_error(localized));
                return;
            }
        };

        let (total_entries, total_bytes) = prepared.totals();
        let walk_stop = entry.cancel.as_core_stop().clone();
        let walked =
            tokio::task::spawn_blocking(move || count_manifest_entries(&paths, &walk_stop))
                .await
                .ok()
                .flatten();

        if entry.cancel.is_cancelled() || entry.is_destroyed() {
            let localized = LocalizedTransferError::from_core_error(
                &CoreError::Stopped,
                &entry.localizer,
                true,
            );
            entry.finish_with(SessionEvent::from_localized_error(localized));
            return;
        }

        let (files, dirs) = reconcile_manifest_counts(walked, total_entries, total_bytes);
        let code = ValidatedCode::from_proto(prepared.code());
        let skipped = prepared.skipped();
        let share_text = entry.localizer.format_share_text(&code.display_english);
        let formatted_total = entry.localizer.format_bytes(total_bytes);

        entry.push_event(SessionEvent::CodeReady {
            code,
            share_text,
            files,
            dirs,
            total_bytes,
            formatted_total,
            skipped,
            is_text: false,
        });

        let events = entry.make_core_events();
        let stop = entry.cancel.as_core_stop().clone();
        match prepared.run_with(events, stop).await {
            Ok(report) => {
                let formatted_bytes = entry.localizer.format_bytes(report.bytes);
                entry.finish_with(SessionEvent::Done {
                    files_ok: report.files_ok,
                    files_failed: report.files_failed,
                    bytes: report.bytes,
                    formatted_bytes,
                    is_text: false,
                    saved_to: None,
                    placed: Vec::new(),
                    received_text: None,
                    sanitized_text: None,
                });
            }
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, true);
                entry.finish_with(SessionEvent::from_localized_error(localized));
            }
        }
    });

    sid
}

/// Starts an asynchronous plain-text send session (`MAX_TEXT = 1_048_576` UTF-8
/// bytes) and returns a non-zero monotonic handle.
pub(crate) fn start_send_text(
    cfg: BridgeNetworkConfig,
    text: String,
    localizer: WindowsLocalizer,
) -> u64 {
    let Some((sid, entry)) = alloc_session(localizer) else {
        return 0;
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_TEXT {
            let localized = LocalizedTransferError::text_too_long(&entry.localizer);
            entry.finish_with(SessionEvent::from_localized_error(localized));
            return;
        }

        if let Err(err) = validate_session_server_urls(&cfg) {
            let localized = LocalizedTransferError::from_core_error(&err, &entry.localizer, true);
            entry.finish_with(SessionEvent::from_localized_error(localized));
            return;
        }

        let prepared = match prepare_windows_text_send(&cfg, &text, TEXT_FILE, &entry.cancel).await
        {
            Ok(p) => p,
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, true);
                entry.finish_with(SessionEvent::from_localized_error(localized));
                return;
            }
        };

        let code = ValidatedCode::from_proto(prepared.code());
        let (files, total_bytes) = prepared.totals();
        let share_text = entry.localizer.format_share_text(&code.display_english);
        let formatted_total = entry.localizer.format_bytes(total_bytes);

        entry.push_event(SessionEvent::CodeReady {
            code,
            share_text,
            files,
            dirs: 0,
            total_bytes,
            formatted_total,
            skipped: 0,
            is_text: true,
        });

        let events = entry.make_core_events();
        let stop = entry.cancel.as_core_stop().clone();
        match prepared.run_with(events, stop).await {
            Ok(report) => {
                if report.files_failed > 0 {
                    let localized = LocalizedTransferError::text_damaged(&entry.localizer);
                    entry.finish_with(SessionEvent::from_localized_error(localized));
                } else {
                    let formatted_bytes = entry.localizer.format_bytes(report.bytes);
                    entry.finish_with(SessionEvent::Done {
                        files_ok: report.files_ok,
                        files_failed: report.files_failed,
                        bytes: report.bytes,
                        formatted_bytes,
                        is_text: true,
                        saved_to: None,
                        placed: Vec::new(),
                        received_text: None,
                        sanitized_text: None,
                    });
                }
            }
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, true);
                entry.finish_with(SessionEvent::from_localized_error(localized));
            }
        }
    });

    sid
}

/// Starts an asynchronous receive connection and emits `offer_ready` or
/// `failed`.
pub(crate) fn start_receive_connect(
    cfg: BridgeNetworkConfig,
    code_or_uri: String,
    localizer: WindowsLocalizer,
) -> u64 {
    let Some((sid, entry)) = alloc_session(localizer) else {
        return 0;
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        if let Err(err) = validate_session_server_urls(&cfg) {
            let localized = LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
            entry.finish_with(SessionEvent::from_localized_error(localized));
            return;
        }

        let offer = match connect_windows_receive(&cfg, &code_or_uri, &entry.cancel).await {
            Ok(o) => o,
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
                entry.finish_with(SessionEvent::from_localized_error(localized));
                return;
            }
        };

        if entry.cancel.is_cancelled() || entry.is_destroyed() {
            let err = offer.stop().await;
            let localized = LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
            entry.finish_with(SessionEvent::from_localized_error(localized));
            return;
        }

        let summary = offer.summary();
        let top_level = summary.top_level.clone();
        let top_level_sanitized: Vec<String> = top_level
            .iter()
            .map(|name| sanitize_peer_filename(name))
            .collect();
        let more_count = top_level.len().saturating_sub(5);
        let verification_words = offer.words().to_vec();
        let joined_words_ltr = verification_words.join("  ");
        let formatted_total = entry.localizer.format_bytes(summary.total_size);
        let offer_event = SessionEvent::OfferReady {
            files: summary.files,
            dirs: summary.dirs,
            total_bytes: summary.total_size,
            formatted_total,
            is_text: summary.text,
            top_level,
            top_level_sanitized,
            more_count,
            verification_words,
            joined_words_ltr,
        };

        commit_or_stop_offer(&entry, offer, offer_event).await;
    });

    sid
}

async fn commit_or_stop_offer(
    entry: &SessionEntry,
    offer: IncomingOffer,
    offer_event: SessionEvent,
) {
    let mut should_stop = None;
    if let Ok(mut inner) = entry.state.lock() {
        if inner.destroyed || inner.terminal || entry.cancel.is_cancelled() {
            should_stop = Some(offer);
        } else {
            inner.pending_offer = Some(offer);
            inner.events.push_back(offer_event);
        }
    } else {
        should_stop = Some(offer);
    }

    if let Some(unwanted) = should_stop {
        let err = unwanted.stop().await;
        let localized = LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
        entry.finish_with(SessionEvent::from_localized_error(localized));
    }
}

/// Accepts a pending file/folder offer and writes verified files under
/// `dest_dir`.
pub(crate) fn accept_receive_files(session_id: u64, dest_dir: String) -> i32 {
    let Some(entry) = lookup_session(session_id) else {
        return FFI_ERR_INVALID_HANDLE;
    };

    let offer = {
        let Ok(mut inner) = entry.state.lock() else {
            return crate::FFI_ERR_INTERNAL;
        };
        if inner.destroyed || inner.terminal {
            return FFI_ERR_INVALID_STATE;
        }
        let Some(ref pending) = inner.pending_offer else {
            return FFI_ERR_INVALID_STATE;
        };
        if pending.summary().text {
            return FFI_ERR_INVALID_STATE;
        }
        inner.pending_offer.take()
    };

    let Some(offer) = offer else {
        return FFI_ERR_INVALID_STATE;
    };

    TRANSFERS.spawn(&RUNTIME, run_accept_receive_files(entry, offer, dest_dir));

    FFI_OK
}

async fn run_accept_receive_files(
    entry: Arc<SessionEntry>,
    offer: IncomingOffer,
    dest_dir: String,
) {
    if entry.cancel.is_cancelled() || entry.is_destroyed() {
        let err = offer.stop().await;
        let localized = LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
        entry.finish_with(SessionEvent::from_localized_error(localized));
        return;
    }

    let dest = PathBuf::from(&dest_dir);
    if std::fs::symlink_metadata(&dest).is_err()
        && let Err(io_err) = std::fs::create_dir_all(&dest)
    {
        let _ = offer.stop().await;
        let core_err = CoreError::Io(io_err);
        let localized = LocalizedTransferError::from_core_error(&core_err, &entry.localizer, false);
        entry.finish_with(SessionEvent::from_localized_error(localized));
        return;
    }

    let checked_dest = match check_windows_destination(&dest) {
        Ok(canonical) => canonical,
        Err(err) => {
            let _ = offer.stop().await;
            let localized = LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
            entry.finish_with(SessionEvent::from_localized_error(localized));
            return;
        }
    };

    let events = entry.make_core_events();
    let stop = entry.cancel.as_core_stop().clone();
    match offer.accept_with(&checked_dest, events, &stop).await {
        Ok(report) => {
            let formatted_bytes = entry.localizer.format_bytes(report.bytes);
            let placed = report
                .placed
                .iter()
                .map(|p| clean_display_path(p))
                .collect();
            entry.finish_with(SessionEvent::Done {
                files_ok: report.files_ok,
                files_failed: report.files_failed,
                bytes: report.bytes,
                formatted_bytes,
                is_text: false,
                saved_to: Some(clean_display_path(&checked_dest)),
                placed,
                received_text: None,
                sanitized_text: None,
            });
        }
        Err(err) => {
            let localized = LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
            entry.finish_with(SessionEvent::from_localized_error(localized));
        }
    }
}

/// Accepts a pending plain-text offer strictly in memory (zero disk writes),
/// mapping `report.text == None` to `TextDamaged` (`errorTextDamaged`).
pub(crate) fn accept_receive_text(session_id: u64) -> i32 {
    let Some(entry) = lookup_session(session_id) else {
        return FFI_ERR_INVALID_HANDLE;
    };

    let offer = {
        let Ok(mut inner) = entry.state.lock() else {
            return crate::FFI_ERR_INTERNAL;
        };
        if inner.destroyed || inner.terminal {
            return FFI_ERR_INVALID_STATE;
        }
        let Some(ref pending) = inner.pending_offer else {
            return FFI_ERR_INVALID_STATE;
        };
        if !pending.summary().text {
            return FFI_ERR_INVALID_STATE;
        }
        inner.pending_offer.take()
    };

    let Some(offer) = offer else {
        return FFI_ERR_INVALID_STATE;
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        let stop = entry.cancel.as_core_stop().clone();
        match offer.accept_text_with(&stop).await {
            Ok(report) => {
                if let Some(raw_text) = report.text {
                    let sanitized = sanitize_peer_text(&raw_text);
                    let formatted_bytes = entry.localizer.format_bytes(report.bytes);
                    entry.finish_with(SessionEvent::Done {
                        files_ok: report.files_ok,
                        files_failed: report.files_failed,
                        bytes: report.bytes,
                        formatted_bytes,
                        is_text: true,
                        saved_to: None,
                        placed: Vec::new(),
                        received_text: Some(raw_text),
                        sanitized_text: Some(sanitized),
                    });
                } else {
                    let localized = LocalizedTransferError::text_damaged(&entry.localizer);
                    entry.finish_with(SessionEvent::from_localized_error(localized));
                }
            }
            Err(err) => {
                let localized =
                    LocalizedTransferError::from_core_error(&err, &entry.localizer, false);
                entry.finish_with(SessionEvent::from_localized_error(localized));
            }
        }
    });

    FFI_OK
}

/// Declines a pending incoming offer cleanly and emits `declined`.
pub(crate) fn decline_receive(session_id: u64) -> i32 {
    let Some(entry) = lookup_session(session_id) else {
        return FFI_ERR_INVALID_HANDLE;
    };

    let offer = {
        let Ok(mut inner) = entry.state.lock() else {
            return crate::FFI_ERR_INTERNAL;
        };
        if inner.destroyed || inner.terminal {
            return FFI_ERR_INVALID_STATE;
        }
        let Some(offer) = inner.pending_offer.take() else {
            return FFI_ERR_INVALID_STATE;
        };
        let is_text = offer.summary().text;
        let summary_key = if is_text {
            "receiveTextDeclined"
        } else {
            "receiveDeclined"
        };
        inner.terminal = true;
        inner.events.push_back(SessionEvent::Declined {
            is_text,
            summary: entry.localizer.text(summary_key),
        });
        offer
    };

    TRANSFERS.spawn(&RUNTIME, async move {
        let _ = offer.decline().await;
    });

    FFI_OK
}

/// Drains queued events for `session_id` in FIFO order into `\n`-terminated
/// NDJSON. Returns `None` if `session_id` is unknown or destroyed.
pub(crate) fn poll_session_events_ndjson(session_id: u64) -> Option<String> {
    let entry = lookup_session(session_id)?;
    let drained: Vec<SessionEvent> = {
        let mut inner = entry.state.lock().ok()?;
        if inner.destroyed {
            return None;
        }
        inner.events.drain(..).collect()
    };

    let mut out = String::new();
    for ev in drained {
        if let Ok(line) = serde_json::to_string(&ev) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    Some(out)
}

/// Cancels an active session cooperatively. Idempotent (`0`) if the session
/// already reached a terminal state (`Done`, `Declined`, `Failed`).
pub(crate) fn cancel_session(session_id: u64) -> i32 {
    let Some(entry) = lookup_session(session_id) else {
        return FFI_ERR_INVALID_HANDLE;
    };

    let pending_offer = {
        let Ok(mut inner) = entry.state.lock() else {
            return crate::FFI_ERR_INTERNAL;
        };
        if inner.destroyed {
            return FFI_ERR_INVALID_HANDLE;
        }
        if inner.terminal {
            return FFI_OK;
        }
        entry.cancel.cancel();
        let taken = inner.pending_offer.take();
        if taken.is_some() {
            inner.terminal = true;
            let localized = LocalizedTransferError::from_core_error(
                &CoreError::Stopped,
                &entry.localizer,
                false,
            );
            inner
                .events
                .push_back(SessionEvent::from_localized_error(localized));
        }
        taken
    };

    if let Some(offer) = pending_offer {
        TRANSFERS.spawn(&RUNTIME, async move {
            let _ = offer.stop().await;
        });
    }

    FFI_OK
}

/// Removes a session from the handle table, cancels any active task, stops any
/// pending offer, and releases all queued events.
pub(crate) fn destroy_session(session_id: u64) -> i32 {
    if session_id == 0 {
        return FFI_ERR_INVALID_HANDLE;
    }
    let removed = match SESSIONS.lock() {
        Ok(mut table) => table.remove(&session_id),
        Err(_) => return crate::FFI_ERR_INTERNAL,
    };
    let Some(entry) = removed else {
        return FFI_ERR_INVALID_HANDLE;
    };

    entry.cancel.cancel();
    let pending_offer = if let Ok(mut inner) = entry.state.lock() {
        inner.destroyed = true;
        inner.terminal = true;
        inner.events.clear();
        inner.pending_offer.take()
    } else {
        None
    };

    if let Some(offer) = pending_offer {
        TRANSFERS.spawn(&RUNTIME, async move {
            let _ = offer.stop().await;
        });
    }

    FFI_OK
}

/// Executes Linux `quit.rs`-parity graceful shutdown across all live sessions
/// and tracked transfer tasks, awaiting `totaldrop_core::portmap::released()`.
///
/// Keeps the static 2-thread Tokio runtime reusable across subsequent calls.
pub(crate) fn shutdown_all(timeout_ms: u32) -> i32 {
    let entries: Vec<Arc<SessionEntry>> = match SESSIONS.lock() {
        Ok(mut table) => table.drain().map(|(_, entry)| entry).collect(),
        Err(_) => return crate::FFI_ERR_INTERNAL,
    };

    for entry in entries {
        entry.cancel.cancel();
        let pending_offer = if let Ok(mut inner) = entry.state.lock() {
            inner.destroyed = true;
            inner.terminal = true;
            inner.events.clear();
            inner.pending_offer.take()
        } else {
            None
        };
        if let Some(offer) = pending_offer {
            TRANSFERS.spawn(&RUNTIME, async move {
                let _ = offer.stop().await;
            });
        }
    }

    let stopping = if timeout_ms == 0 {
        STOPPING
    } else {
        Duration::from_millis(u64::from(timeout_ms))
    };

    let _ = RUNTIME.block_on(quit::finish(
        &TRANSFERS,
        totaldrop_core::portmap::released(),
        stopping,
    ));

    FFI_OK
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;
    use std::sync::atomic::AtomicU32;

    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio::sync::{Mutex as AsyncMutex, mpsc};
    use tokio_tungstenite::tungstenite::Message;
    use totaldrop_proto::wire::{ClientMessage, ServerMessage};

    use super::*;

    type TestResult = Result<(), Box<dyn StdError>>;

    struct Slot {
        mailbox_id: [u8; 16],
        peers: Vec<mpsc::UnboundedSender<ServerMessage>>,
        buffered: Vec<ServerMessage>,
    }

    async fn spawn_minimal_loopback_rendezvous()
    -> Result<(String, tokio::task::AbortHandle), std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local = listener.local_addr()?;
        let url = format!("ws://{local}");
        let next_np = Arc::new(AtomicU32::new(11));
        let slots: Arc<AsyncMutex<HashMap<u32, Slot>>> = Arc::new(AsyncMutex::new(HashMap::new()));

        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let next_np = Arc::clone(&next_np);
                let slots = Arc::clone(&slots);
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    let first = loop {
                        match ws.next().await {
                            Some(Ok(Message::Binary(b))) => {
                                if let Ok(cmd) = ClientMessage::decode(&b) {
                                    break cmd;
                                }
                                return;
                            }
                            Some(Ok(Message::Ping(p))) => {
                                let _ = ws.send(Message::Pong(p)).await;
                            }
                            _ => return,
                        }
                    };
                    match first {
                        ClientMessage::Allocate => {
                            let nameplate = next_np.fetch_add(1, Ordering::Relaxed);
                            let token = [0x33u8; 16];
                            let mailbox_id = [0x44u8; 16];
                            slots.lock().await.insert(
                                nameplate,
                                Slot {
                                    mailbox_id,
                                    peers: Vec::new(),
                                    buffered: Vec::new(),
                                },
                            );
                            let reply = ServerMessage::Allocated { nameplate, token };
                            let _ = ws.send(Message::Binary(reply.encode().into())).await;
                            let _ = ws.close(None).await;
                        }
                        ClientMessage::Claim { nameplate, .. } => {
                            let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
                            let (mailbox_id, peer_idx, replay) = {
                                let mut map = slots.lock().await;
                                let Some(slot) = map.get_mut(&nameplate) else {
                                    return;
                                };
                                let idx = slot.peers.len();
                                slot.peers.push(tx);
                                let replay = if idx == 1 {
                                    std::mem::take(&mut slot.buffered)
                                } else {
                                    Vec::new()
                                };
                                (slot.mailbox_id, idx, replay)
                            };
                            let claimed = ServerMessage::Claimed {
                                mailbox: mailbox_id,
                            };
                            if ws
                                .send(Message::Binary(claimed.encode().into()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            for msg in replay {
                                if ws.send(Message::Binary(msg.encode().into())).await.is_err() {
                                    return;
                                }
                            }
                            loop {
                                tokio::select! {
                                    out = rx.recv() => {
                                        let Some(msg) = out else { break; };
                                        if ws.send(Message::Binary(msg.encode().into())).await.is_err() {
                                            break;
                                        }
                                    }
                                    inc = ws.next() => {
                                        match inc {
                                            Some(Ok(Message::Binary(b))) => {
                                                let Ok(cmd) = ClientMessage::decode(&b) else { break; };
                                                match cmd {
                                                    ClientMessage::Add { phase, body } => {
                                                        let fwd = ServerMessage::Message { phase, body };
                                                        let mut map = slots.lock().await;
                                                        if let Some(slot) = map.get_mut(&nameplate) {
                                                            let other = 1usize.saturating_sub(peer_idx);
                                                            if let Some(peer_tx) = slot.peers.get(other) {
                                                                let _ = peer_tx.send(fwd);
                                                            } else if peer_idx == 0 {
                                                                slot.buffered.push(fwd);
                                                            }
                                                        }
                                                    }
                                                    ClientMessage::Close { mood } => {
                                                        let map = slots.lock().await;
                                                        if let Some(slot) = map.get(&nameplate) {
                                                            let other = 1usize.saturating_sub(peer_idx);
                                                            if let Some(peer_tx) = slot.peers.get(other) {
                                                                let _ = peer_tx.send(ServerMessage::PeerClosed { mood });
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
                                            _ => break,
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                });
            }
        });

        Ok((url, handle.abort_handle()))
    }

    async fn connect_loopback_offer(
        url: &str,
        file_path: Option<PathBuf>,
    ) -> Result<(IncomingOffer, tokio::task::JoinHandle<()>), Box<dyn StdError>> {
        let cfg = BridgeNetworkConfig {
            rendezvous_server: url.to_owned(),
            relay_server: String::new(),
            stun_server: String::new(),
            privacy_relay_only: false,
            stronger_three_word_code: false,
        };
        let send_cancel = WindowsCancellationToken::new();
        let prepared = match file_path {
            Some(path) => prepare_windows_send(&cfg, vec![path], &send_cancel).await?,
            None => prepare_windows_text_send(&cfg, "race-test", TEXT_FILE, &send_cancel).await?,
        };
        let code = ValidatedCode::from_proto(prepared.code()).display_english;
        let stop = send_cancel.as_core_stop().clone();
        let sender_task = tokio::spawn(async move {
            let noop_events: totaldrop_core::Events = Arc::new(|_| {});
            let _ = prepared.run_with(noop_events, stop).await;
        });

        let recv_cancel = WindowsCancellationToken::new();
        let offer = connect_windows_receive(&cfg, &code, &recv_cancel).await?;
        Ok((offer, sender_task))
    }

    fn dummy_offer_event() -> SessionEvent {
        SessionEvent::OfferReady {
            files: 1,
            dirs: 0,
            total_bytes: 9,
            formatted_total: "9 B".to_owned(),
            is_text: true,
            top_level: Vec::new(),
            top_level_sanitized: Vec::new(),
            more_count: 0,
            verification_words: Vec::new(),
            joined_words_ltr: String::new(),
        }
    }

    #[test]
    fn commit_or_stop_offer_emits_stopped_on_cancel_race_and_skips_when_destroyed() -> TestResult {
        RUNTIME.block_on(async {
            let (url, srv_abort) = spawn_minimal_loopback_rendezvous().await?;

            // Case 1: `cancel_session` fires in the TOCTOU window after `connect_windows_receive`
            // succeeded and before `commit_or_stop_offer` locks `entry.state`.
            let (offer1, sender1) = connect_loopback_offer(&url, None).await?;
            let entry = SessionEntry::new(WindowsLocalizer::new(["en-US"], Some("en-US")));
            entry.cancel.cancel();

            commit_or_stop_offer(&entry, offer1, dummy_offer_event()).await;
            {
                let inner = entry.state.lock().map_err(|_| "lock poisoned")?;
                assert!(
                    inner.terminal,
                    "session must reach terminal state on cancel race"
                );
                assert!(inner.pending_offer.is_none());
                assert_eq!(inner.events.len(), 1);
                match inner.events.front() {
                    Some(SessionEvent::Failed { kind, l10n_key, .. }) => {
                        assert_eq!(kind, "stopped");
                        assert_eq!(l10n_key, "errorStopped");
                    }
                    other => {
                        return Err(format!("expected Failed(stopped), got {other:?}").into());
                    }
                }
            }
            sender1.abort();

            // Case 2: session already destroyed -> `commit_or_stop_offer` stops the offer and
            // does not enqueue events onto the destroyed entry.
            let (offer2, sender2) = connect_loopback_offer(&url, None).await?;
            let destroyed_entry =
                SessionEntry::new(WindowsLocalizer::new(["en-US"], Some("en-US")));
            {
                let mut inner = destroyed_entry.state.lock().map_err(|_| "lock poisoned")?;
                inner.destroyed = true;
            }
            commit_or_stop_offer(&destroyed_entry, offer2, dummy_offer_event()).await;
            {
                let inner = destroyed_entry.state.lock().map_err(|_| "lock poisoned")?;
                assert!(inner.pending_offer.is_none());
                assert!(inner.events.is_empty());
            }
            sender2.abort();
            srv_abort.abort();
            Ok(())
        })
    }

    #[test]
    fn accept_receive_files_pre_start_cancel_skips_create_dir_all() -> TestResult {
        RUNTIME.block_on(async {
            let (url, srv_abort) = spawn_minimal_loopback_rendezvous().await?;
            let base = std::env::temp_dir().join(format!(
                "totaldrop-win-ffi-prestart-cancel-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base)?;
            let src = base.join("sample.txt");
            std::fs::write(&src, b"hello prestart cancel")?;
            let must_not_exist = base.join("never-create-me").join("nested");

            let (offer, sender) = connect_loopback_offer(&url, Some(src)).await?;
            let entry = SessionEntry::new(WindowsLocalizer::new(["en-US"], Some("en-US")));
            entry.cancel.cancel();

            run_accept_receive_files(
                Arc::clone(&entry),
                offer,
                must_not_exist.to_string_lossy().into_owned(),
            )
            .await;

            assert!(
                !must_not_exist.exists(),
                "pre-cancelled accept_receive_files must not create destination directory"
            );
            {
                let inner = entry.state.lock().map_err(|_| "lock poisoned")?;
                assert!(inner.terminal);
                match inner.events.front() {
                    Some(SessionEvent::Failed { kind, l10n_key, .. }) => {
                        assert_eq!(kind, "stopped");
                        assert_eq!(l10n_key, "errorStopped");
                    }
                    other => {
                        return Err(format!("expected Failed(stopped), got {other:?}").into());
                    }
                }
            }

            sender.abort();
            srv_abort.abort();
            let _ = std::fs::remove_dir_all(&base);
            Ok(())
        })
    }

    static UNIT_TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

    struct UnitTempDir {
        path: PathBuf,
    }

    impl UnitTempDir {
        fn new(prefix: &str) -> Result<Self, std::io::Error> {
            let id = UNIT_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("td-u-{prefix}-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for UnitTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn core_scan_counts(paths: &[PathBuf]) -> Result<ManifestCounts, Box<dyn StdError>> {
        let (entries, _skipped) = totaldrop_core::transfer::scan(paths)?;
        let files = entries
            .iter()
            .filter(|e| e.entry.kind == totaldrop_proto::wire::EntryKind::File)
            .count();
        let dirs = entries.len().saturating_sub(files);
        Ok(ManifestCounts { files, dirs })
    }

    #[test]
    fn count_manifest_entries_matches_core_scan_and_limits() -> TestResult {
        let tmp = UnitTempDir::new("cnt")?;
        let stop = totaldrop_core::Stop::new();

        // 1. Single non-empty file.
        let single_file = tmp.path().join("single.bin");
        std::fs::write(&single_file, b"payload-bytes")?;
        let single_paths = vec![single_file.clone()];
        let expected_single = ManifestCounts { files: 1, dirs: 0 };
        assert_eq!(
            count_manifest_entries(&single_paths, &stop),
            Some(expected_single)
        );
        assert_eq!(core_scan_counts(&single_paths)?, expected_single);

        // 2. Single 0-byte file.
        let zero_file = tmp.path().join("zero.txt");
        std::fs::write(&zero_file, b"")?;
        let zero_paths = vec![zero_file];
        assert_eq!(
            count_manifest_entries(&zero_paths, &stop),
            Some(expected_single)
        );
        assert_eq!(core_scan_counts(&zero_paths)?, expected_single);

        // 3. Single empty directory -> (0, 1).
        let empty_dir = tmp.path().join("empty_only");
        std::fs::create_dir_all(&empty_dir)?;
        let empty_dir_paths = vec![empty_dir.clone()];
        let expected_empty_dir = ManifestCounts { files: 0, dirs: 1 };
        assert_eq!(
            count_manifest_entries(&empty_dir_paths, &stop),
            Some(expected_empty_dir)
        );
        assert_eq!(core_scan_counts(&empty_dir_paths)?, expected_empty_dir);

        // 4. Nested directory with 2 dirs + 3 files (root + 1 subdir).
        let bundle = tmp.path().join("bundle");
        let bundle_sub = bundle.join("sub");
        std::fs::create_dir_all(&bundle_sub)?;
        std::fs::write(bundle.join("empty.txt"), b"")?;
        std::fs::write(bundle.join("report-2026.txt"), b"report body")?;
        std::fs::write(bundle_sub.join("third.bin"), b"binary-content")?;
        let bundle_paths = vec![bundle];
        let expected_3_2 = ManifestCounts { files: 3, dirs: 2 };
        assert_eq!(
            count_manifest_entries(&bundle_paths, &stop),
            Some(expected_3_2)
        );
        assert_eq!(core_scan_counts(&bundle_paths)?, expected_3_2);

        // 5. Nested directory with 2 subdirs + 3 files -> (3, 3).
        let pack = tmp.path().join("pack");
        std::fs::create_dir_all(pack.join("sub1"))?;
        std::fs::create_dir_all(pack.join("sub2"))?;
        std::fs::write(pack.join("a.txt"), b"a")?;
        std::fs::write(pack.join("sub1").join("b.txt"), b"bb")?;
        std::fs::write(pack.join("sub2").join("c.bin"), b"ccc")?;
        let pack_paths = vec![pack];
        let expected_3_3 = ManifestCounts { files: 3, dirs: 3 };
        assert_eq!(
            count_manifest_entries(&pack_paths, &stop),
            Some(expected_3_3)
        );
        assert_eq!(core_scan_counts(&pack_paths)?, expected_3_3);

        // 6. Empty subdir + sibling files -> (2, 2).
        let with_empty_sub = tmp.path().join("with_empty_sub");
        std::fs::create_dir_all(with_empty_sub.join("empty_sub"))?;
        std::fs::write(with_empty_sub.join("one.txt"), b"1")?;
        std::fs::write(with_empty_sub.join("two.txt"), b"22")?;
        let with_empty_paths = vec![with_empty_sub];
        let expected_2_2 = ManifestCounts { files: 2, dirs: 2 };
        assert_eq!(
            count_manifest_entries(&with_empty_paths, &stop),
            Some(expected_2_2)
        );
        assert_eq!(core_scan_counts(&with_empty_paths)?, expected_2_2);

        // 7. Mixed roots: [empty_dir, file] -> (1, 1).
        let mixed_paths = vec![empty_dir, single_file];
        let expected_mixed = ManifestCounts { files: 1, dirs: 1 };
        assert_eq!(
            count_manifest_entries(&mixed_paths, &stop),
            Some(expected_mixed)
        );
        assert_eq!(core_scan_counts(&mixed_paths)?, expected_mixed);

        // 8. Pre-stopped Stop -> None.
        let stopped = totaldrop_core::Stop::new();
        stopped.stop();
        assert_eq!(count_manifest_entries(&mixed_paths, &stopped), None);

        // 9. Depth boundary: MAX_PATH_DEPTH succeeds, MAX_PATH_DEPTH + 1 -> None.
        let depth_tmp = UnitTempDir::new("d")?;
        let mut cursor = depth_tmp.path().join("a");
        for _ in 1..totaldrop_proto::limits::MAX_PATH_DEPTH {
            cursor = cursor.join("a");
        }
        std::fs::create_dir_all(&cursor)?;
        let depth_root = vec![depth_tmp.path().join("a")];
        assert_eq!(
            count_manifest_entries(&depth_root, &stop),
            Some(ManifestCounts {
                files: 0,
                dirs: totaldrop_proto::limits::MAX_PATH_DEPTH,
            })
        );
        assert_eq!(
            core_scan_counts(&depth_root)?,
            ManifestCounts {
                files: 0,
                dirs: totaldrop_proto::limits::MAX_PATH_DEPTH,
            }
        );

        let too_deep = cursor.join("a");
        std::fs::create_dir_all(&too_deep)?;
        assert_eq!(count_manifest_entries(&depth_root, &stop), None);
        assert!(totaldrop_core::transfer::scan(&depth_root).is_err());

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn count_manifest_entries_matches_core_scan_with_symlinks_on_unix() -> TestResult {
        use std::os::unix::fs::symlink;

        let tmp = UnitTempDir::new("sym")?;
        let stop = totaldrop_core::Stop::new();

        let ext_file = tmp.path().join("ext.txt");
        std::fs::write(&ext_file, b"external target")?;
        let ext_dir = tmp.path().join("ext_dir");
        std::fs::create_dir_all(ext_dir.join("deep"))?;
        std::fs::write(ext_dir.join("deep").join("hidden.txt"), b"must not follow")?;

        // Nested symlinks (to file, to populated dir, dangling) are skipped and not descended.
        let bundle = tmp.path().join("bundle");
        let sub = bundle.join("sub");
        std::fs::create_dir_all(&sub)?;
        std::fs::write(bundle.join("keep.txt"), b"keep")?;
        std::fs::write(sub.join("inner.bin"), b"inner")?;
        symlink(&ext_file, bundle.join("link_file"))?;
        symlink(&ext_dir, bundle.join("link_dir"))?;
        symlink(tmp.path().join("nonexistent-target"), sub.join("dangling"))?;

        let bundle_paths = vec![bundle];
        let expected = ManifestCounts { files: 2, dirs: 2 };
        assert_eq!(count_manifest_entries(&bundle_paths, &stop), Some(expected));
        assert_eq!(core_scan_counts(&bundle_paths)?, expected);

        // Directory containing ONLY symlinks -> (0, 1).
        let only_links = tmp.path().join("only_links");
        std::fs::create_dir_all(&only_links)?;
        symlink(&ext_file, only_links.join("a"))?;
        symlink(tmp.path().join("missing"), only_links.join("b"))?;
        let only_links_paths = vec![only_links];
        let expected_only_links = ManifestCounts { files: 0, dirs: 1 };
        assert_eq!(
            count_manifest_entries(&only_links_paths, &stop),
            Some(expected_only_links)
        );
        assert_eq!(core_scan_counts(&only_links_paths)?, expected_only_links);

        // Top-level symlink -> None (parity with transfer::scan returning Err).
        let top_link = tmp.path().join("top_link");
        symlink(&ext_file, &top_link)?;
        let top_link_paths = vec![top_link];
        assert_eq!(count_manifest_entries(&top_link_paths, &stop), None);
        assert!(totaldrop_core::transfer::scan(&top_link_paths).is_err());

        Ok(())
    }

    #[test]
    fn reconcile_manifest_counts_enforces_invariants_and_recovers_from_toctou() {
        // Exact match for nested directory.
        assert_eq!(
            reconcile_manifest_counts(Some(ManifestCounts { files: 3, dirs: 2 }), 5, 4133),
            (3, 2)
        );
        // Exact match for single empty directory (total_bytes == 0, files == 0).
        assert_eq!(
            reconcile_manifest_counts(Some(ManifestCounts { files: 0, dirs: 1 }), 1, 0),
            (0, 1)
        );
        // TOCTOU file added during rendezvous RTT -> recovers exact original (3, 2).
        assert_eq!(
            reconcile_manifest_counts(Some(ManifestCounts { files: 4, dirs: 2 }), 5, 4133),
            (3, 2)
        );
        // TOCTOU file removed during rendezvous RTT -> recovers exact original (3, 2).
        assert_eq!(
            reconcile_manifest_counts(Some(ManifestCounts { files: 2, dirs: 2 }), 5, 4133),
            (3, 2)
        );
        // TOCTOU 1-for-1 file replaced with empty dir while total_bytes > 0 -> preserves files >= 1.
        assert_eq!(
            reconcile_manifest_counts(Some(ManifestCounts { files: 0, dirs: 1 }), 1, 42),
            (1, 0)
        );
        // TOCTOU dirs burst exceeding total_entries -> clamps dirs while keeping files >= 1 when total_bytes > 0.
        assert_eq!(
            reconcile_manifest_counts(Some(ManifestCounts { files: 1, dirs: 9 }), 3, 100),
            (1, 2)
        );
        // TOCTOU dirs burst with total_bytes == 0 -> clamps dirs to total_entries.
        assert_eq!(
            reconcile_manifest_counts(Some(ManifestCounts { files: 0, dirs: 9 }), 3, 0),
            (0, 3)
        );
        // Walk unavailable (None) -> safe fallback preserving files + dirs == total_entries.
        assert_eq!(reconcile_manifest_counts(None, 5, 4133), (5, 0));
        assert_eq!(reconcile_manifest_counts(None, 1, 0), (1, 0));
    }
}
