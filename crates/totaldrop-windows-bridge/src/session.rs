// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bridge over [`totaldrop_core`] options, async send/receive session
//! preparation, cancellation tokens, progress projections, error mapping, and
//! TotalDrop's platform-invariant brand mark motion (`Kose`, ADR 0016 &
//! `docs/tasarim.md`).

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
/// (`docs/tasarim.md`). Never mirrored in right-to-left layouts.
pub const MARK_SVG_PATH: &str = "M55 15H97V57A42 42 0 1 1 55 15Z";

/// TotalDrop brand mark color on light backgrounds (`#6D4AE0`).
pub const MARK_HEX_LIGHT: &str = "#6D4AE0";

/// TotalDrop brand mark color on dark backgrounds (`#A68BFF`).
pub const MARK_HEX_DARK: &str = "#A68BFF";

/// Full 4-quarter rotation cycle duration of the `Kose` mark during an active
/// transfer (`3200 ms`, `docs/tasarim.md`).
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
    /// Checks that user-configured rendezvous and relay URLs are accepted by
    /// [`totaldrop_core::relay::check_url`] (`wss://` with a non-empty host, or
    /// `ws://` strictly on localhost / `127.0.0.1` / `[::1]`, rejecting control
    /// characters, non-ASCII / Bidi format characters, and `@` userinfo) and
    /// carry a strictly well-formed authority (non-empty host or valid
    /// bracketed IPv6 literal, optional port in `1..=65535`, and no `#`
    /// fragment per RFC 6455 §3).
    #[must_use]
    pub fn is_valid_rendezvous_url(url: &str) -> bool {
        if !url.is_ascii() || url.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return false;
        }
        let trimmed = url.trim_matches(' ');
        if trimmed.is_empty()
            || trimmed.bytes().any(|b| !(0x21..=0x7E).contains(&b))
            || totaldrop_core::relay::check_url(trimmed).is_err()
        {
            return false;
        }
        if trimmed.contains('#') {
            return false;
        }

        let Some(rest) = strip_ws_scheme(trimmed) else {
            return false;
        };
        let authority = rest.split(['/', '?']).next().unwrap_or("");
        if authority.is_empty()
            || authority.contains('@')
            || authority.chars().any(char::is_whitespace)
        {
            return false;
        }

        if authority.starts_with('[') {
            let Some(end_bracket) = authority.find(']') else {
                return false;
            };
            let Some(ipv6_str) = authority.get(1..end_bracket) else {
                return false;
            };
            if ipv6_str.parse::<std::net::Ipv6Addr>().is_err() {
                return false;
            }
            let after_bracket = authority.get(end_bracket.saturating_add(1)..).unwrap_or("");
            if after_bracket.is_empty() {
                true
            } else if let Some(port_str) = after_bracket.strip_prefix(':') {
                is_valid_port(port_str)
            } else {
                false
            }
        } else {
            let (host, port_opt) = match authority.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            };
            if host.is_empty() || host.contains('[') || host.contains(']') || host.contains(':') {
                return false;
            }
            port_opt.is_none_or(is_valid_port)
        }
    }

    /// Converts this configuration into [`totaldrop_core::SendOptions`].
    #[must_use]
    pub fn to_send_options(&self) -> SendOptions {
        SendOptions {
            server: self.rendezvous_server.trim().to_owned(),
            words: if self.stronger_three_word_code { 3 } else { 2 },
            paths: self.to_path_options(),
        }
    }

    /// Converts this configuration into [`totaldrop_core::ReceiveOptions`].
    #[must_use]
    pub fn to_receive_options(&self) -> ReceiveOptions {
        ReceiveOptions {
            server: self.rendezvous_server.trim().to_owned(),
            paths: self.to_path_options(),
        }
    }

    /// Converts this configuration into [`totaldrop_core::PathOptions`].
    #[must_use]
    pub fn to_path_options(&self) -> PathOptions {
        PathOptions {
            relay: self.relay_server.trim().to_owned(),
            stun: self.stun_server.trim().to_owned(),
            relay_only: self.privacy_relay_only,
            gateway: totaldrop_core::portmap::Gateway::Auto,
        }
    }
}

fn strip_ws_scheme(url: &str) -> Option<&str> {
    if url
        .get(..6)
        .is_some_and(|s| s.eq_ignore_ascii_case("wss://"))
    {
        url.get(6..)
    } else if url
        .get(..5)
        .is_some_and(|s| s.eq_ignore_ascii_case("ws://"))
    {
        url.get(5..)
    } else {
        None
    }
}

fn is_valid_port(port_str: &str) -> bool {
    !port_str.is_empty()
        && port_str.bytes().all(|b| b.is_ascii_digit())
        && port_str.parse::<u16>().is_ok_and(|port| port >= 1)
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
    /// Stable snake_case error category (`"wrong_code"`, `"bad_server"`, ...).
    #[serde(default)]
    pub kind: String,
    /// Canonical `l10n/app` ARB key (`"errorWrongCode"`, `"errorBadServer"`, ...).
    #[serde(default)]
    pub l10n_key: String,
    /// Canonical `cause*` key (`"causeTimedOut"`, ...) or `""` when unknown.
    #[serde(default)]
    pub cause: String,
    /// Primary localized message shown to the user.
    pub summary: String,
    /// Optional localized plain-language explanation (`causeTimedOut`, …).
    pub cause_detail: Option<String>,
    /// Sanitized English technical string for problem reports (hidden
    /// control/bidi characters revealed as `<U+XXXX>`).
    pub technical_english: String,
}

const MAX_ERROR_WORD_PREVIEW_CHARS: usize = 64;

impl LocalizedTransferError {
    /// Maps a [`totaldrop_core::Error`] and its [`Cause`] into localized user
    /// text while preserving `err.to_string()` in English.
    ///
    /// `is_sender` distinguishes expired sender codes (`errorCodeExpired`) from
    /// receiver lookups of codes not in use (`errorCodeNotInUse`), matching
    /// Linux and Android parity.
    #[must_use]
    pub fn from_core_error(err: &CoreError, localizer: &WindowsLocalizer, is_sender: bool) -> Self {
        let (kind, primary_key) = if err.is_bad_server_address() {
            ("bad_server", "errorBadServer")
        } else if err.is_code_not_in_use() {
            if is_sender {
                ("code_expired", "errorCodeExpired")
            } else {
                ("code_not_in_use", "errorCodeNotInUse")
            }
        } else {
            match err {
                CoreError::WrongCode => ("wrong_code", "errorWrongCode"),
                CoreError::PeerLeft => ("peer_left", "errorPeerLeft"),
                CoreError::Rendezvous(_) => ("server", "errorServer"),
                CoreError::Connect(_) => ("connect", "errorConnect"),
                CoreError::Protocol(_) => ("protocol", "errorOther"),
                CoreError::InvalidOffer(_) => ("invalid_offer", "errorInvalidOffer"),
                CoreError::Rejected(_) => ("declined", "errorDeclined"),
                CoreError::Cancelled(_) => ("cancelled", "errorCancelled"),
                CoreError::Stopped => ("stopped", "errorStopped"),
                CoreError::Io(_) => ("storage", "errorStorage"),
                CoreError::Code(_) => ("invalid_code", "errorInvalidCode"),
                CoreError::Random => ("internal", "errorOther"),
            }
        };
        let core_cause = err.cause();
        let (cause, cause_detail) = if core_cause == Cause::Unknown {
            (String::new(), None)
        } else {
            let cause_key = format!("cause{}", core_cause.as_str());
            let detail = localizer.text(&cause_key);
            (cause_key, Some(detail))
        };
        let raw_technical = match err {
            CoreError::Code(CodeError::UnknownWord(word))
                if word.chars().nth(MAX_ERROR_WORD_PREVIEW_CHARS).is_some() =>
            {
                let preview: String = word.chars().take(MAX_ERROR_WORD_PREVIEW_CHARS).collect();
                format!("{preview:?}... is not a code word")
            }
            _ => err.to_string(),
        };
        let technical_english = totaldrop_l10n::reveal_controls(&raw_technical);
        Self {
            kind: kind.to_owned(),
            l10n_key: primary_key.to_owned(),
            cause,
            summary: localizer.text(primary_key),
            cause_detail,
            technical_english,
        }
    }

    /// Creates a localized `TextDamaged` error when a plain-text transfer fails
    /// its integrity check or UTF-8 validation (`errorTextDamaged`).
    #[must_use]
    pub fn text_damaged(localizer: &WindowsLocalizer) -> Self {
        Self {
            kind: "text_damaged".to_owned(),
            l10n_key: "errorTextDamaged".to_owned(),
            cause: String::new(),
            summary: localizer.text("errorTextDamaged"),
            cause_detail: None,
            technical_english: "the text failed its check".to_owned(),
        }
    }

    /// Creates a localized `TextTooLong` error when outgoing text exceeds
    /// [`totaldrop_core::MAX_TEXT`] (`1_048_576` UTF-8 bytes, `sendTextTooLong`).
    #[must_use]
    pub fn text_too_long(localizer: &WindowsLocalizer) -> Self {
        let limit_str = localizer.format_bytes(totaldrop_core::MAX_TEXT);
        let summary = localizer
            .format_message(
                "sendTextTooLong",
                &[("size", totaldrop_l10n::Arg::Text(&limit_str))],
            )
            .unwrap_or_else(|| localizer.text("sendTextTooLong"));
        Self {
            kind: "text_too_long".to_owned(),
            l10n_key: "sendTextTooLong".to_owned(),
            cause: String::new(),
            summary,
            cause_detail: None,
            technical_english: format!(
                "the text is longer than {} bytes; send it as a file",
                totaldrop_core::MAX_TEXT
            ),
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

/// Verifies that `dest` exists, is a directory (not a regular file), and is
/// writable by delegating to [`totaldrop_core::check_destination`].
///
/// # Errors
///
/// Returns [`totaldrop_core::Error::Io`] if `dest` does not exist, is not a
/// directory, or cannot be written to.
pub fn check_windows_destination(dest: &Path) -> totaldrop_core::Result<PathBuf> {
    totaldrop_core::check_destination(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localized_transfer_error_sanitizes_untrusted_remote_reasons() {
        let localizer = WindowsLocalizer::new(["en-US"], Some("en-US"));
        let malicious = concat!(
            "remote\u{202E}evil\u{2069}",
            "\x1b[31m\u{009B}31m\u{0085}",
            "\u{2028}\u{2029}\u{FDD0}\u{FFFF}\u{E0041}"
        );

        for err in [
            CoreError::Rendezvous(malicious.to_owned()),
            CoreError::Cancelled(malicious.to_owned()),
        ] {
            let localized = LocalizedTransferError::from_core_error(&err, &localizer, false);
            assert!(
                !localized
                    .technical_english
                    .chars()
                    .any(totaldrop_l10n::is_hidden),
                "leaked hidden char in technical_english: {:?}",
                localized.technical_english
            );
            for expected_escape in [
                "<U+202E>",
                "<U+2069>",
                "<U+001B>",
                "<U+009B>",
                "<U+0085>",
                "<U+2028>",
                "<U+2029>",
                "<U+FDD0>",
                "<U+FFFF>",
                "<U+E0041>",
            ] {
                assert!(
                    localized.technical_english.contains(expected_escape),
                    "expected {expected_escape} in {:?}",
                    localized.technical_english
                );
            }
        }
    }

    #[test]
    fn localized_transfer_error_bounds_unknown_word_preview_at_64_scalars() {
        let localizer = WindowsLocalizer::new(["en-US"], Some("en-US"));

        let word64 = "a".repeat(MAX_ERROR_WORD_PREVIEW_CHARS);
        let exact = LocalizedTransferError::from_core_error(
            &CoreError::Code(CodeError::UnknownWord(word64.clone())),
            &localizer,
            false,
        );
        assert!(!exact.technical_english.contains("..."));
        assert!(exact.technical_english.contains(&word64));

        let word65 = "é".repeat(MAX_ERROR_WORD_PREVIEW_CHARS + 1);
        let over = LocalizedTransferError::from_core_error(
            &CoreError::Code(CodeError::UnknownWord(word65)),
            &localizer,
            false,
        );
        assert!(over.technical_english.contains("..."));
        assert!(over.technical_english.len() < 256);

        let huge = LocalizedTransferError::from_core_error(
            &CoreError::Code(CodeError::UnknownWord("x".repeat(20_000))),
            &localizer,
            false,
        );
        assert!(huge.technical_english.contains("..."));
        assert!(huge.technical_english.len() < 256);
        assert!(
            !huge
                .technical_english
                .chars()
                .any(totaldrop_l10n::is_hidden)
        );
    }

    #[test]
    fn tier5_is_valid_rendezvous_url_rejects_bidi_non_ascii_and_control_chars() {
        let valid = [
            "wss://example.test",
            "wss://example.test:443/v0/relay",
            "  wss://example.test/v0  ",
            "ws://127.0.0.1:4400",
            "ws://localhost:4400/ws",
            "ws://[::1]:4400",
        ];
        for url in valid {
            assert!(
                BridgeNetworkConfig::is_valid_rendezvous_url(url),
                "valid URL unexpectedly rejected: {url:?}"
            );
        }

        let hostile = [
            "wss://example.test/\u{202E}evil",
            "wss://example.test/\u{2066}spoof",
            "wss://example.test/\u{2067}spoof",
            "wss://example.test/\u{2068}spoof",
            "wss://example.test/\u{2069}spoof",
            "wss://example.test/\u{2028}line",
            "wss://example.test/\u{2029}para",
            "wss://example.test/\u{FDD0}nonchar",
            "wss://example.test/\u{FDEF}nonchar",
            "wss://example.test/\u{FFFF}nonchar",
            "wss://example.test/\u{E0041}tag",
            "wss://example.test\u{00A0}",
            "wss://example.test/a\u{00A0}b",
            "\u{00A0}wss://example.test",
            "wss://example.test/a b",
            "wss://example.test\t",
            "wss://example.test\r\n",
            "wss://example.test/\0",
            "wss://example.test/\u{007F}",
            "wss://example.test/caf\u{00E9}",
        ];
        for url in hostile {
            assert!(
                !BridgeNetworkConfig::is_valid_rendezvous_url(url),
                "hostile URL must be rejected: {url:?}"
            );
        }
    }
}
