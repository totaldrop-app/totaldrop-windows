// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bridge over [`totaldrop_core`] options, async send/receive session
//! preparation, cancellation tokens, progress projections, error mapping, and
//! TotalDrop's platform-invariant brand mark motion (`Kose`, ADR 0016 &
//! `docs/design.md`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use totaldrop_core::{
    Cause, Error as CoreError, Event, IncomingOffer, PathOptions, PreparedSend, ReceiveOptions,
    SendOptions, Stop,
};
use totaldrop_proto::CodeError;

use crate::l10n::{RegionalPercent, WindowsLocalizer};
use crate::uri::{UriValidationError, ValidatedCode};

/// TotalDrop brand mark (`Kose`) SVG path on its 112x112 unit canvas
/// (`docs/design.md`). Never mirrored in right-to-left layouts.
pub const MARK_SVG_PATH: &str = "M55 15H97V57A42 42 0 1 1 55 15Z";

/// TotalDrop brand mark color on light backgrounds (`#6D4AE0`).
pub const MARK_HEX_LIGHT: &str = "#6D4AE0";

/// TotalDrop brand mark color on dark backgrounds (`#A68BFF`).
pub const MARK_HEX_DARK: &str = "#A68BFF";

/// Full 4-quarter rotation cycle duration of the `Kose` mark during an active
/// transfer (`3200 ms`, `docs/design.md`).
pub const MARK_CYCLE_MS: u32 = 3200;

/// Duration of each 90-degree quarter step (`600 ms` turn + `200 ms` dwell =
/// `800 ms`).
pub const MARK_QUARTER_MS: u32 = 800;

/// Validated settings snapshot shared between WinUI 3 Settings and
/// [`totaldrop_core::SendOptions`] / [`totaldrop_core::ReceiveOptions`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeNetworkConfig {
    /// Rendezvous WebSocket URL (`wss://…`).
    pub rendezvous_server: String,
    /// Relay WebSocket URL (`wss://…`), or empty to disable relay fallback.
    pub relay_server: String,
    /// STUN endpoint (`host:port`), or empty to disable STUN discovery.
    pub stun_server: String,
    /// Privacy mode: route exclusively over the relay so the peer never sees
    /// this PC's IP address.
    pub privacy_relay_only: bool,
    /// Stronger 3-word transfer code toggle (`true` -> 3 words, `false` -> 2
    /// words).
    pub stronger_three_word_code: bool,
}

impl Default for BridgeNetworkConfig {
    fn default() -> Self {
        let send_defaults = SendOptions::default();
        Self {
            rendezvous_server: send_defaults.server,
            relay_server: send_defaults.paths.relay,
            stun_server: send_defaults.paths.stun,
            privacy_relay_only: send_defaults.paths.relay_only,
            stronger_three_word_code: false,
        }
    }
}

impl BridgeNetworkConfig {
    /// Checks that user-configured rendezvous and relay URLs start with
    /// `wss://` (or `ws://127.0.0.1` / `ws://[::1]` for local loopback testing).
    #[must_use]
    pub fn is_valid_rendezvous_url(url: &str) -> bool {
        let trimmed = url.trim();
        trimmed.starts_with("wss://")
            || trimmed.starts_with("ws://127.0.0.1:")
            || trimmed.starts_with("ws://[::1]:")
            || trimmed.starts_with("ws://localhost:")
    }

    /// Converts this configuration into [`totaldrop_core::SendOptions`].
    #[must_use]
    pub fn to_send_options(&self) -> SendOptions {
        SendOptions {
            server: self.rendezvous_server.clone(),
            words: if self.stronger_three_word_code { 3 } else { 2 },
            paths: self.to_path_options(),
        }
    }

    /// Converts this configuration into [`totaldrop_core::ReceiveOptions`].
    #[must_use]
    pub fn to_receive_options(&self) -> ReceiveOptions {
        ReceiveOptions {
            server: self.rendezvous_server.clone(),
            paths: self.to_path_options(),
        }
    }

    /// Converts this configuration into [`totaldrop_core::PathOptions`].
    #[must_use]
    pub fn to_path_options(&self) -> PathOptions {
        PathOptions {
            relay: self.relay_server.clone(),
            stun: self.stun_server.clone(),
            relay_only: self.privacy_relay_only,
            gateway: totaldrop_core::portmap::Gateway::Auto,
        }
    }
}

/// Read-only view-model projection of a [`totaldrop_core::Event`] formatted for
/// WinUI 3 `x:Bind` and Windows Narrator UI Automation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TransferViewEvent {
    /// Waiting in the rendezvous mailbox for the receiver to enter the code.
    Waiting {
        /// Localized status caption (`sendWaiting`).
        caption: String,
    },
    /// CPace + QUIC + Noise XXpsk3 + ML-KEM-768 session established.
    Connected {
        /// Four English verification words (`FlowDirection.LeftToRight`, spoken
        /// with an `en` locale voice by Windows Narrator).
        verification_words: Vec<String>,
        /// Space-joined English verification words.
        joined_words_ltr: String,
    },
    /// Chunked STREAM transfer progress update (`#483`).
    Progress {
        /// Raw bytes completed.
        done_bytes: u64,
        /// Total bytes in transfer.
        total_bytes: u64,
        /// Region-formatted completed size (`"12 MB"`, `"1,5 MB"`).
        formatted_done: String,
        /// Region-formatted total size.
        formatted_total: String,
        /// Rounded-down regional percentage (`whole` + `formatted`).
        percent: RegionalPercent,
    },
}

impl TransferViewEvent {
    /// Projects a [`totaldrop_core::Event`] using `localizer`'s display
    /// language and Windows regional number/percent rules.
    #[must_use]
    pub fn from_core_event(event: Event, localizer: &WindowsLocalizer) -> Self {
        match event {
            Event::Waiting => Self::Waiting {
                caption: localizer.text("sendWaiting"),
            },
            Event::Connected { words } => {
                let joined_words_ltr = words.join("  ");
                Self::Connected {
                    verification_words: words,
                    joined_words_ltr,
                }
            }
            Event::Progress { done, total } => Self::Progress {
                done_bytes: done,
                total_bytes: total,
                formatted_done: localizer.format_bytes(done),
                formatted_total: localizer.format_bytes(total),
                percent: localizer.format_percent(done, total),
            },
        }
    }
}

/// Localized failure summary for WinUI 3 error banners, keeping the underlying
/// technical detail in English for bug reports (`technicalDetail`, ADR 0019).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizedTransferError {
    /// Primary localized message shown to the user.
    pub summary: String,
    /// Optional localized plain-language explanation (`causeTimedOut`, …).
    pub cause_detail: Option<String>,
    /// Unmodified English technical string for problem reports.
    pub technical_english: String,
}

impl LocalizedTransferError {
    /// Maps a [`totaldrop_core::Error`] and its [`Cause`] into localized user
    /// text while preserving `err.to_string()` in English.
    #[must_use]
    pub fn from_core_error(err: &CoreError, localizer: &WindowsLocalizer) -> Self {
        let primary_key = match err {
            CoreError::WrongCode => "errorWrongCode",
            CoreError::PeerLeft => "errorPeerLeft",
            CoreError::Rendezvous(_) => "errorServer",
            CoreError::Connect(_) => "errorConnect",
            CoreError::Protocol(_) => "errorOther",
            CoreError::InvalidOffer(_) => "errorInvalidOffer",
            CoreError::Rejected(_) => "errorDeclined",
            CoreError::Cancelled(_) => "errorCancelled",
            CoreError::Stopped => "errorStopped",
            CoreError::Io(_) => "errorStorage",
            CoreError::Code(_) => "errorInvalidCode",
            CoreError::Random => "errorOther",
        };
        let cause = err.cause();
        let cause_detail = if cause == Cause::Unknown {
            None
        } else {
            let cause_key = format!("cause{}", cause.as_str());
            Some(localizer.text(&cause_key))
        };
        Self {
            summary: localizer.text(primary_key),
            cause_detail,
            technical_english: err.to_string(),
        }
    }
}

/// Determines whether the TotalDrop `Kose` mark should play its 3.2-second
/// quarter-turn animation given transfer state and Windows'
/// `UISettings.AnimationsEnabled` accessibility setting (ADR 0016).
#[must_use]
pub const fn should_animate_mark(transfer_running: bool, windows_animations_enabled: bool) -> bool {
    transfer_running && windows_animations_enabled
}

/// Thread-safe cooperative cancellation handle wrapping [`totaldrop_core::Stop`]
/// for WinUI 3 commands, window-close handlers, and background Tokio tasks.
///
/// Cloning shares the same underlying cancellation state; invoking
/// [`Self::cancel`] wakes all pending tasks and causes both pre-cancelled and
/// in-flight session helpers to resolve immediately with
/// [`totaldrop_core::Error::Stopped`].
#[derive(Clone, Default)]
pub struct WindowsCancellationToken {
    inner: Stop,
}

impl core::fmt::Debug for WindowsCancellationToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowsCancellationToken")
            .field("cancelled", &self.inner.is_stopped())
            .finish()
    }
}

impl WindowsCancellationToken {
    /// Creates an active, uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self { inner: Stop::new() }
    }

    /// Creates a token that is already cancelled prior to starting any I/O.
    #[must_use]
    pub fn cancelled() -> Self {
        let stop = Stop::new();
        stop.stop();
        Self { inner: stop }
    }

    /// Signals cancellation across all clones of this token. Idempotent and
    /// safe to call from any thread (including the WinUI 3 UI thread).
    pub fn cancel(&self) {
        self.inner.stop();
    }

    /// Returns `true` once [`Self::cancel`] has been invoked.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_stopped()
    }

    /// Resolves when cancellation is requested, or immediately if already
    /// cancelled.
    pub async fn wait_cancelled(&self) {
        self.inner.stopped().await;
    }

    /// Borrows the underlying [`totaldrop_core::Stop`] handle for passing into
    /// [`PreparedSend::run_with`] or [`IncomingOffer::accept_with`].
    #[must_use]
    pub const fn as_core_stop(&self) -> &Stop {
        &self.inner
    }

    /// Consumes this wrapper and returns the inner [`totaldrop_core::Stop`].
    #[must_use]
    pub fn into_core_stop(self) -> Stop {
        self.inner
    }
}

fn map_uri_error_to_core(err: UriValidationError) -> CoreError {
    let code_err = match err {
        UriValidationError::WrongWordCount => CodeError::WrongWordCount,
        UriValidationError::UnknownWord { word } => CodeError::UnknownWord(word),
        UriValidationError::Empty
        | UriValidationError::LinkTooLong { .. }
        | UriValidationError::InvalidActivationLink
        | UriValidationError::BadNameplate
        | UriValidationError::NoCodeFoundInText => CodeError::BadNameplate,
    };
    CoreError::Code(code_err)
}

/// Scans `files`, allocates a rendezvous nameplate, and prepares an encrypted
/// send session via [`totaldrop_core::PreparedSend::new`], racing against
/// `cancel`.
///
/// Accepts [`PathBuf`], [`Path`], `&str`, or validated
/// [`crate::activation::WindowsSelectionPath`] items. If `cancel` is already
/// cancelled before invocation, returns `Err(CoreError::Stopped)` immediately
/// without touching the filesystem or network.
///
/// # Errors
///
/// Returns [`totaldrop_core::Error::Stopped`] if cancelled before or during
/// preparation, or the underlying filesystem/rendezvous error from
/// [`totaldrop_core::PreparedSend::new`].
pub async fn prepare_windows_send<I, P>(
    config: &BridgeNetworkConfig,
    files: I,
    cancel: &WindowsCancellationToken,
) -> totaldrop_core::Result<PreparedSend>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    if cancel.is_cancelled() {
        return Err(CoreError::Stopped);
    }
    let opts = config.to_send_options();
    let paths: Vec<PathBuf> = files
        .into_iter()
        .map(|item| item.as_ref().to_path_buf())
        .collect();
    tokio::select! {
        biased;
        () = cancel.wait_cancelled() => Err(CoreError::Stopped),
        res = PreparedSend::new(&opts, paths) => res,
    }
}

/// Prepares a plain-text send session (`#313`) via
/// [`totaldrop_core::PreparedSend::text`], racing against `cancel`.
///
/// If `cancel` is already cancelled before invocation, returns
/// `Err(CoreError::Stopped)` immediately without contacting the rendezvous
/// server.
///
/// # Errors
///
/// Returns [`totaldrop_core::Error::Stopped`] if cancelled, or the underlying
/// validation/rendezvous error from [`totaldrop_core::PreparedSend::text`].
pub async fn prepare_windows_text_send(
    config: &BridgeNetworkConfig,
    text: &str,
    fallback_filename: &str,
    cancel: &WindowsCancellationToken,
) -> totaldrop_core::Result<PreparedSend> {
    if cancel.is_cancelled() {
        return Err(CoreError::Stopped);
    }
    let opts = config.to_send_options();
    tokio::select! {
        biased;
        () = cancel.wait_cancelled() => Err(CoreError::Stopped),
        res = PreparedSend::text(&opts, text, fallback_filename) => res,
    }
}

/// Validates `code_or_uri` (accepting `totaldrop://r/…` URIs,
/// `https://totaldrop.app/r#…` links, Arabic-Indic digits, or human-entered
/// codes) and connects to the sender's mailbox via
/// [`totaldrop_core::IncomingOffer::connect_with`], racing against `cancel`.
///
/// If `cancel` is already cancelled before invocation, returns
/// `Err(CoreError::Stopped)` immediately without generating ephemeral device
/// identities or opening sockets.
///
/// # Errors
///
/// Returns [`totaldrop_core::Error::Stopped`] if cancelled,
/// [`totaldrop_core::Error::Code`] if `code_or_uri` is invalid, or the
/// underlying rendezvous/transport/handshake error.
pub async fn connect_windows_receive(
    config: &BridgeNetworkConfig,
    code_or_uri: &str,
    cancel: &WindowsCancellationToken,
) -> totaldrop_core::Result<IncomingOffer> {
    if cancel.is_cancelled() {
        return Err(CoreError::Stopped);
    }
    let validated = ValidatedCode::from_user_input(code_or_uri).map_err(map_uri_error_to_core)?;
    let opts = config.to_receive_options();
    tokio::select! {
        biased;
        () = cancel.wait_cancelled() => Err(CoreError::Stopped),
        res = IncomingOffer::connect_with(&opts, &validated.display_english, cancel.as_core_stop()) => res,
    }
}
