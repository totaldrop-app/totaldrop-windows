// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Single-window WinUI 3 state machine, streaming Named Pipe IPC frame decoder,
//! and newline-delimited JSON (`ndjson`) view-model bridge (ADR 0016).
//!
//! ### Single-window coordination on Windows 11
//!
//! The primary `totaldrop-winui.exe` process listens on the session-scoped local
//! Named Pipe `\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.<SessionId>`. Secondary
//! launches—whether triggered by File Explorer's **"Send with TotalDrop"**
//! (`IExplorerCommand`) verb, a `totaldrop://r/<code>` protocol URI, Windows
//! Share Target, or `--screen=<target>`—stream 4-byte little-endian
//! length-prefixed [`ActivationEnvelope`] frames over that pipe.
//!
//! [`WinUiWindowRouter`] pairs [`IpcFrameDecoder`] with [`WindowsActivityState`]
//! and [`WindowsLocalizer`]:
//! - Partial reads and coalesced multi-frame pipe bursts decode deterministically,
//!   while any frame header declaring `> MAX_IPC_FRAME_BYTES` is refused on the
//!   4-byte prefix **before** allocating heap memory.
//! - When an active transfer, offer prompt, or received text note already owns
//!   the window, incoming activations resolve to
//!   [`RouterDecision::RejectBusy`] with a localized `InfoBar` banner rather
//!   than clobbering the running session.
//! - Outbound state transitions, regional floor-rounded progress updates
//!   (`#483`), localized errors, and `Kose` mark animation states serialize as
//!   newline-delimited JSON ([`WinUiBridgeMessage`]) for `.NET Native AOT`
//!   `MainWindow` consumption without runtime reflection.

use serde::{Deserialize, Serialize};
use totaldrop_core::{Error as CoreError, Event};

use crate::activation::{
    ActivationEnvelope, ActivationError, ActivationPayload, MAX_ENVELOPE_BYTES, ScreenTarget,
    WindowsSelectionPath, session_named_pipe_path,
};
use crate::l10n::{SanitizedPeerText, WindowsLocalizer, WindowsUiBundle, sanitize_peer_text};
use crate::session::{
    LocalizedTransferError, MARK_CYCLE_MS, MARK_HEX_DARK, MARK_HEX_LIGHT, TransferViewEvent,
    should_animate_mark,
};
use crate::uri::ValidatedCode;

/// Maximum serialized payload size (`4 MiB`) accepted by [`IpcFrameDecoder`] on
/// the session-local Named Pipe.
///
/// Any 4-byte little-endian length prefix exceeding this ceiling is rejected
/// immediately before allocating a payload buffer.
pub const MAX_IPC_FRAME_BYTES: usize = MAX_ENVELOPE_BYTES;

/// High-level lifecycle state of the single WinUI 3 `MainWindow`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WindowsActivityState {
    /// Window is idle and ready to accept files, shared text, or a receive code.
    #[default]
    Idle,
    /// Scanning local files and reserving a nameplate on the rendezvous server.
    PreparingSend,
    /// Waiting in the rendezvous mailbox for the receiver to enter `code`.
    WaitingForPeer {
        /// Human-readable English transfer code (`"7-harbor-rocket"`).
        code: String,
    },
    /// Connecting to the sender's mailbox using `code`.
    ConnectingReceive {
        /// Human-readable English transfer code (`"7-harbor-rocket"`).
        code: String,
    },
    /// Incoming offer card is displayed and awaiting user Accept or Decline.
    OfferPromptPending,
    /// Encrypted chunked transfer is actively moving bytes.
    Transferring {
        /// Bytes completed so far.
        done_bytes: u64,
        /// Total bytes in the transfer manifest.
        total_bytes: u64,
    },
    /// A verified incoming plain-text note is currently shown on screen.
    ShowingTextNote,
}

impl WindowsActivityState {
    /// Returns `true` when no transfer, offer prompt, or unsaved text note owns
    /// the window.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    /// Returns `true` when replacing the active view would interrupt an
    /// in-progress session, pending offer decision, or displayed text note.
    #[must_use]
    pub const fn is_busy(&self) -> bool {
        !self.is_idle()
    }

    /// Returns `true` while transfer payload bytes are actively streaming
    /// (`Transferring`), which drives the `Kose` mark rotation when Windows
    /// animations are enabled.
    #[must_use]
    pub const fn is_transferring(&self) -> bool {
        matches!(self, Self::Transferring { .. })
    }
}

/// Incremental decoder for 4-byte little-endian length-prefixed
/// [`ActivationEnvelope`] frames read from
/// `\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.<SessionId>`.
///
/// Handles arbitrary stream chunking—from 1-byte-at-a-time partial reads up to
/// multi-frame coalesced pipe buffers—while enforcing [`MAX_IPC_FRAME_BYTES`]
/// strictly on the 4-byte stack header before growing `payload_buf`.
#[derive(Debug, Default)]
pub struct IpcFrameDecoder {
    header_buf: [u8; 4],
    header_filled: usize,
    payload_buf: Vec<u8>,
    expected_payload_len: Option<usize>,
}

impl IpcFrameDecoder {
    /// Creates an empty frame decoder with zero heap allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            header_buf: [0u8; 4],
            header_filled: 0,
            payload_buf: Vec::new(),
            expected_payload_len: None,
        }
    }

    /// Returns `true` when a partial header or partial frame payload is waiting
    /// for more bytes from the pipe.
    #[must_use]
    pub const fn has_partial_frame(&self) -> bool {
        self.header_filled > 0 || self.expected_payload_len.is_some()
    }

    /// Total header plus payload bytes currently buffered for an in-flight
    /// frame.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        if self.expected_payload_len.is_some() {
            self.payload_buf.len().saturating_add(4)
        } else {
            self.header_filled
        }
    }

    /// Current heap capacity (in bytes) of the internal payload buffer.
    ///
    /// Remains `0` when an oversized length header is rejected on the 4-byte
    /// prefix.
    #[must_use]
    pub fn payload_capacity(&self) -> usize {
        self.payload_buf.capacity()
    }

    /// Clears any buffered partial frame state and releases excess heap
    /// capacity.
    pub fn reset(&mut self) {
        self.header_buf = [0u8; 4];
        self.header_filled = 0;
        self.payload_buf.clear();
        self.payload_buf.shrink_to_fit();
        self.expected_payload_len = None;
    }

    /// Validates clean stream termination when a Named Pipe client disconnects.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError::MalformedIpcFrame`] (and resets the decoder)
    /// if the peer closed the pipe mid-header or mid-payload.
    pub fn finish_eof(&mut self) -> Result<(), ActivationError> {
        if self.has_partial_frame() {
            self.reset();
            return Err(ActivationError::MalformedIpcFrame);
        }
        Ok(())
    }

    /// Feeds raw bytes read from the Named Pipe into the decoder, returning zero
    /// or more validated [`ActivationEnvelope`] frames in arrival order.
    ///
    /// # Errors
    ///
    /// - [`ActivationError::EnvelopeTooLarge`] immediately upon completing a
    ///   4-byte header whose declared length exceeds [`MAX_IPC_FRAME_BYTES`],
    ///   without allocating heap memory.
    /// - [`ActivationError::MalformedIpcFrame`] on a zero-length frame header.
    /// - Any [`ActivationError`] returned by
    ///   [`ActivationEnvelope::from_json_bytes`] when a completed frame fails
    ///   JSON parsing, schema version checks, or path/URI validation.
    pub fn push_bytes(
        &mut self,
        mut chunk: &[u8],
    ) -> Result<Vec<ActivationEnvelope>, ActivationError> {
        let mut completed = Vec::new();

        while !chunk.is_empty() {
            if let Some(target_len) = self.expected_payload_len {
                let remaining = target_len.saturating_sub(self.payload_buf.len());
                let take = remaining.min(chunk.len());
                let Some((part, rest)) = chunk.split_at_checked(take) else {
                    self.reset();
                    return Err(ActivationError::MalformedIpcFrame);
                };
                self.payload_buf.extend_from_slice(part);
                chunk = rest;

                if self.payload_buf.len() == target_len {
                    let parsed = ActivationEnvelope::from_json_bytes(&self.payload_buf);
                    self.header_buf = [0u8; 4];
                    self.header_filled = 0;
                    self.payload_buf.clear();
                    self.expected_payload_len = None;

                    match parsed {
                        Ok(envelope) => completed.push(envelope),
                        Err(err) => {
                            self.payload_buf.shrink_to_fit();
                            return Err(err);
                        }
                    }
                }
            } else {
                let needed = 4usize.saturating_sub(self.header_filled);
                let take = needed.min(chunk.len());
                let end = self.header_filled.saturating_add(take);
                let (Some((part, rest)), Some(dest)) = (
                    chunk.split_at_checked(take),
                    self.header_buf.get_mut(self.header_filled..end),
                ) else {
                    self.reset();
                    return Err(ActivationError::MalformedIpcFrame);
                };
                dest.copy_from_slice(part);
                self.header_filled = end;
                chunk = rest;

                if self.header_filled < 4 {
                    break;
                }

                let declared_len =
                    usize::try_from(u32::from_le_bytes(self.header_buf)).map_err(|_| {
                        self.reset();
                        ActivationError::MalformedIpcFrame
                    })?;

                if declared_len > MAX_IPC_FRAME_BYTES {
                    self.reset();
                    return Err(ActivationError::EnvelopeTooLarge {
                        byte_len: declared_len,
                    });
                }
                if declared_len == 0 {
                    self.reset();
                    return Err(ActivationError::MalformedIpcFrame);
                }

                self.expected_payload_len = Some(declared_len);
            }
        }

        Ok(completed)
    }
}

/// Routing outcome computed by [`WinUiWindowRouter`] for a validated
/// [`ActivationEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum RouterDecision {
    /// Bring `MainWindow` forward, navigate to `SendPage`, and populate the
    /// selection with validated extended-length Windows paths.
    NavigateSendFiles {
        /// Validated, deduplicated extended-length Win32 paths (`\\?\C:\…` or
        /// `\\?\UNC\…`).
        paths: Vec<WindowsSelectionPath>,
        /// Optional Win32 process ID of the initiating caller.
        initiator_pid: Option<u32>,
    },
    /// Bring `MainWindow` forward, navigate to `SendPage` in plain-text mode
    /// (`#313`), and populate the shared text.
    NavigateSendText {
        /// Complete UTF-8 text to transmit when sending starts.
        raw_text: String,
        /// Display-safe preview with hidden bidi/control characters revealed as
        /// `<U+XXXX>` and capped at [`crate::l10n::MAX_SHOWN_TEXT_CHARS`].
        sanitized_preview: SanitizedPeerText,
        /// Optional Win32 process ID of the initiating caller.
        initiator_pid: Option<u32>,
    },
    /// Bring `MainWindow` forward, navigate to `ReceivePage`, and pre-populate
    /// the validated transfer code.
    NavigateReceiveCode {
        /// Validated transfer code (`display_english`, `canonical`, and
        /// `ltr_isolated`).
        code: ValidatedCode,
        /// Optional Win32 process ID of the initiating caller.
        initiator_pid: Option<u32>,
    },
    /// Bring `MainWindow` forward and switch to the requested top-level screen.
    SwitchScreen {
        /// Target WinUI 3 navigation page (`send`, `clipboard`, `receive`, or
        /// `settings`).
        screen: ScreenTarget,
        /// Optional Win32 process ID of the initiating caller.
        initiator_pid: Option<u32>,
    },
    /// Preserve the active window state untouched and display a non-destructive
    /// localized `InfoBar` notice explaining that TotalDrop is busy.
    RejectBusy {
        /// Localized notice (`shareBusy` or `linkBusy`) formatted in the
        /// window's negotiated display language.
        localized_banner: String,
    },
}

/// Outbound view-model message serialized as newline-delimited JSON (`ndjson`)
/// for `.NET Native AOT` `MainWindow` consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum WinUiBridgeMessage {
    /// Initial or locale-updated 35-language UI string bundle and
    /// `FlowDirection`.
    UiBundleReady(Box<WindowsUiBundle>),
    /// Single-window routing outcome for an incoming launch or Named Pipe IPC
    /// activation.
    RouteDecision(RouterDecision),
    /// Core transfer progress or verification-words update projected with
    /// regional formatting (`#483`).
    TransferEvent(TransferViewEvent),
    /// Localized transfer error banner preserving English technical diagnostics
    /// (`ADR 0019`).
    TransferFailed(LocalizedTransferError),
    /// TotalDrop `Kose` brand mark motion and theme color snapshot gated by
    /// `UISettings.AnimationsEnabled` (`ADR 0016`, `docs/tasarim.md`).
    MarkAnimationState {
        /// Whether the 3.2-second 4-quarter rotation animation should run.
        animate: bool,
        /// Brand mark fill hex on light surfaces (`#6D4AE0`).
        hex_light: String,
        /// Brand mark fill hex on dark surfaces (`#A68BFF`).
        hex_dark: String,
        /// Full 4-quarter cycle duration in milliseconds (`3200`).
        cycle_ms: u32,
    },
}

impl WinUiBridgeMessage {
    /// Builds a [`Self::MarkAnimationState`] snapshot from transfer activity
    /// and Windows' `UISettings.AnimationsEnabled` setting.
    #[must_use]
    pub fn mark_animation_state(transfer_running: bool, windows_animations_enabled: bool) -> Self {
        Self::MarkAnimationState {
            animate: should_animate_mark(transfer_running, windows_animations_enabled),
            hex_light: MARK_HEX_LIGHT.to_owned(),
            hex_dark: MARK_HEX_DARK.to_owned(),
            cycle_ms: MARK_CYCLE_MS,
        }
    }

    /// Serializes this message as a single compact JSON line terminated by `\n`
    /// (`ndjson`).
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError::InvalidJson`] if serialization fails.
    pub fn to_ndjson_line(&self) -> Result<String, ActivationError> {
        let mut line =
            serde_json::to_string(self).map_err(|e| ActivationError::InvalidJson(e.to_string()))?;
        line.push('\n');
        Ok(line)
    }

    /// Parses a single `ndjson` line back into a [`WinUiBridgeMessage`].
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError::InvalidJson`] if the line is empty, contains
    /// multiple unescaped lines, or fails JSON deserialization.
    pub fn from_ndjson_line(line: &str) -> Result<Self, ActivationError> {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() || trimmed.contains('\n') || trimmed.contains('\r') {
            return Err(ActivationError::InvalidJson(
                "expected a single non-empty NDJSON line".to_owned(),
            ));
        }
        serde_json::from_str(trimmed).map_err(|e| ActivationError::InvalidJson(e.to_string()))
    }
}

/// Encodes a slice of [`WinUiBridgeMessage`] values into a newline-delimited
/// JSON (`ndjson`) string.
///
/// # Errors
///
/// Returns [`ActivationError::InvalidJson`] if any item fails serialization.
pub fn encode_ndjson_batch(messages: &[WinUiBridgeMessage]) -> Result<String, ActivationError> {
    let mut out = String::new();
    for msg in messages {
        let line = msg.to_ndjson_line()?;
        out.push_str(&line);
    }
    Ok(out)
}

/// Decodes a newline-delimited JSON (`ndjson`) stream into ordered
/// [`WinUiBridgeMessage`] snapshots.
///
/// Blank lines (such as the trailing newline at the end of a batch) are
/// skipped cleanly.
///
/// # Errors
///
/// Returns [`ActivationError::InvalidJson`] if any non-empty line fails JSON
/// deserialization.
pub fn decode_ndjson_stream(stream: &str) -> Result<Vec<WinUiBridgeMessage>, ActivationError> {
    let mut out = Vec::new();
    for raw_line in stream.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(WinUiBridgeMessage::from_ndjson_line(trimmed)?);
    }
    Ok(out)
}

/// Stateful single-window coordinator and Named Pipe IPC router for WinUI 3
/// (`MainWindow`).
#[derive(Debug)]
pub struct WinUiWindowRouter {
    windows_session_id: u32,
    pipe_path: String,
    app_version: String,
    localizer: WindowsLocalizer,
    activity: WindowsActivityState,
    windows_animations_enabled: bool,
    decoder: IpcFrameDecoder,
    outbox: Vec<WinUiBridgeMessage>,
}

impl WinUiWindowRouter {
    /// Creates a new [`WinUiWindowRouter`] bound to `windows_session_id`
    /// (`\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.<SessionId>`) and queues the
    /// initial [`WinUiBridgeMessage::UiBundleReady`] and
    /// [`WinUiBridgeMessage::MarkAnimationState`] snapshots.
    #[must_use]
    pub fn new(
        windows_session_id: u32,
        localizer: WindowsLocalizer,
        app_version: impl Into<String>,
        windows_animations_enabled: bool,
    ) -> Self {
        let app_version = app_version.into();
        let pipe_path = session_named_pipe_path(windows_session_id);
        let initial_bundle =
            WinUiBridgeMessage::UiBundleReady(Box::new(localizer.ui_bundle(&app_version)));
        let initial_mark =
            WinUiBridgeMessage::mark_animation_state(false, windows_animations_enabled);
        Self {
            windows_session_id,
            pipe_path,
            app_version,
            localizer,
            activity: WindowsActivityState::Idle,
            windows_animations_enabled,
            decoder: IpcFrameDecoder::new(),
            outbox: vec![initial_bundle, initial_mark],
        }
    }

    /// Windows Terminal Services session ID owning this router's Named Pipe.
    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.windows_session_id
    }

    /// Full session-local Named Pipe path
    /// (`\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.<SessionId>`).
    #[must_use]
    pub fn pipe_path(&self) -> &str {
        &self.pipe_path
    }

    /// Current window activity state.
    #[must_use]
    pub const fn activity(&self) -> &WindowsActivityState {
        &self.activity
    }

    /// Active localization and regional-formatting context.
    #[must_use]
    pub const fn localizer(&self) -> &WindowsLocalizer {
        &self.localizer
    }

    /// Last reported value of Windows `UISettings.AnimationsEnabled`.
    #[must_use]
    pub const fn animations_enabled(&self) -> bool {
        self.windows_animations_enabled
    }

    /// Inspects the underlying [`IpcFrameDecoder`] state.
    #[must_use]
    pub const fn decoder(&self) -> &IpcFrameDecoder {
        &self.decoder
    }

    /// Number of [`WinUiBridgeMessage`] items waiting in the NDJSON outbox.
    #[must_use]
    pub fn pending_message_count(&self) -> usize {
        self.outbox.len()
    }

    /// Transitions [`Self::activity`] to `next` and queues an updated
    /// [`WinUiBridgeMessage::MarkAnimationState`] snapshot.
    pub fn set_activity(&mut self, next: WindowsActivityState) -> WinUiBridgeMessage {
        self.activity = next;
        let mark = WinUiBridgeMessage::mark_animation_state(
            self.activity.is_transferring(),
            self.windows_animations_enabled,
        );
        self.outbox.push(mark.clone());
        mark
    }

    /// Updates Windows' `UISettings.AnimationsEnabled` accessibility flag and
    /// emits a fresh [`WinUiBridgeMessage::MarkAnimationState`] snapshot so
    /// reduced-motion changes take effect live without restarting TotalDrop.
    pub fn set_animations_enabled(&mut self, enabled: bool) -> WinUiBridgeMessage {
        self.windows_animations_enabled = enabled;
        let mark = WinUiBridgeMessage::mark_animation_state(
            self.activity.is_transferring(),
            self.windows_animations_enabled,
        );
        self.outbox.push(mark.clone());
        mark
    }

    /// Replaces the active [`WindowsLocalizer`] when Windows display language or
    /// regional format preferences change and queues a fresh
    /// [`WinUiBridgeMessage::UiBundleReady`] snapshot.
    pub fn update_locale(&mut self, localizer: WindowsLocalizer) -> WinUiBridgeMessage {
        self.localizer = localizer;
        let msg = WinUiBridgeMessage::UiBundleReady(Box::new(
            self.localizer.ui_bundle(&self.app_version),
        ));
        self.outbox.push(msg.clone());
        msg
    }

    /// Routes a decoded [`ActivationEnvelope`] against the current
    /// [`WindowsActivityState`], queueing a
    /// [`WinUiBridgeMessage::RouteDecision`] snapshot into the outbox.
    ///
    /// When [`WindowsActivityState::is_busy`] is `true`, the active session or
    /// offer prompt is preserved untouched and [`RouterDecision::RejectBusy`]
    /// is returned with a localized `shareBusy` or `linkBusy` banner.
    pub fn route_envelope(&mut self, envelope: ActivationEnvelope) -> RouterDecision {
        let initiator_pid = envelope.initiator_pid;
        let decision = if self.activity.is_busy() {
            let key =
                match &envelope.payload {
                    ActivationPayload::ExplorerSend { .. }
                    | ActivationPayload::ShareTarget { .. } => "shareBusy",
                    ActivationPayload::OpenScreen {
                        screen: ScreenTarget::Clipboard,
                    } => "shareBusy",
                    ActivationPayload::ProtocolUri { .. }
                    | ActivationPayload::OpenScreen { .. } => "linkBusy",
                };
            RouterDecision::RejectBusy {
                localized_banner: self.localizer.text(key),
            }
        } else {
            match envelope.payload {
                ActivationPayload::ExplorerSend { paths } => RouterDecision::NavigateSendFiles {
                    paths,
                    initiator_pid,
                },
                ActivationPayload::ProtocolUri { code } => RouterDecision::NavigateReceiveCode {
                    code,
                    initiator_pid,
                },
                ActivationPayload::ShareTarget { paths, text } => {
                    if !paths.is_empty() {
                        RouterDecision::NavigateSendFiles {
                            paths,
                            initiator_pid,
                        }
                    } else if let Some(raw_text) = text
                        && !raw_text.is_empty()
                    {
                        let sanitized_preview = sanitize_peer_text(&raw_text);
                        RouterDecision::NavigateSendText {
                            raw_text,
                            sanitized_preview,
                            initiator_pid,
                        }
                    } else {
                        RouterDecision::SwitchScreen {
                            screen: ScreenTarget::Send,
                            initiator_pid,
                        }
                    }
                }
                ActivationPayload::OpenScreen { screen } => RouterDecision::SwitchScreen {
                    screen,
                    initiator_pid,
                },
            }
        };

        self.outbox
            .push(WinUiBridgeMessage::RouteDecision(decision.clone()));
        decision
    }

    /// Feeds a raw byte slice read from the session Named Pipe through
    /// [`IpcFrameDecoder`] and routes every completed [`ActivationEnvelope`] in
    /// order.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError`] if the stream contains an oversized header
    /// (`> MAX_IPC_FRAME_BYTES`) or a malformed/invalid envelope frame.
    pub fn ingest_ipc_bytes(
        &mut self,
        chunk: &[u8],
    ) -> Result<Vec<RouterDecision>, ActivationError> {
        let envelopes = self.decoder.push_bytes(chunk)?;
        let mut decisions = Vec::with_capacity(envelopes.len());
        for envelope in envelopes {
            decisions.push(self.route_envelope(envelope));
        }
        Ok(decisions)
    }

    /// Projects a [`totaldrop_core::Event`] using regional formatting rules
    /// (`#483`), updating [`Self::activity`] and queueing the resulting
    /// [`WinUiBridgeMessage`] snapshots.
    pub fn on_core_event(&mut self, event: Event) -> WinUiBridgeMessage {
        if let Event::Progress { done, total } = &event {
            let was_transferring = self.activity.is_transferring();
            self.activity = WindowsActivityState::Transferring {
                done_bytes: *done,
                total_bytes: *total,
            };
            if !was_transferring {
                self.outbox.push(WinUiBridgeMessage::mark_animation_state(
                    true,
                    self.windows_animations_enabled,
                ));
            }
        }

        let view_event = TransferViewEvent::from_core_event(event, &self.localizer);
        let msg = WinUiBridgeMessage::TransferEvent(view_event);
        self.outbox.push(msg.clone());
        msg
    }

    /// Resets [`Self::activity`] to [`WindowsActivityState::Idle`], stops the
    /// `Kose` mark animation, and queues a localized
    /// [`WinUiBridgeMessage::TransferFailed`] snapshot.
    ///
    /// Infers the transfer role (`is_sender`) from the active state prior to
    /// resetting to idle.
    pub fn on_core_error(&mut self, err: &CoreError) -> WinUiBridgeMessage {
        let is_sender = matches!(
            self.activity,
            WindowsActivityState::PreparingSend | WindowsActivityState::WaitingForPeer { .. }
        );
        self.on_core_error_for_role(err, is_sender)
    }

    /// Resets [`Self::activity`] to [`WindowsActivityState::Idle`], stops the
    /// `Kose` mark animation, and queues a localized
    /// [`WinUiBridgeMessage::TransferFailed`] snapshot using an explicit
    /// `is_sender` role for `errorCodeExpired` vs `errorCodeNotInUse`.
    pub fn on_core_error_for_role(
        &mut self,
        err: &CoreError,
        is_sender: bool,
    ) -> WinUiBridgeMessage {
        let was_transferring = self.activity.is_transferring();
        self.activity = WindowsActivityState::Idle;
        if was_transferring {
            self.outbox.push(WinUiBridgeMessage::mark_animation_state(
                false,
                self.windows_animations_enabled,
            ));
        }
        let localized = LocalizedTransferError::from_core_error(err, &self.localizer, is_sender);
        let msg = WinUiBridgeMessage::TransferFailed(localized);
        self.outbox.push(msg.clone());
        msg
    }

    /// Drains all queued [`WinUiBridgeMessage`] snapshots in FIFO order.
    pub fn drain_messages(&mut self) -> Vec<WinUiBridgeMessage> {
        std::mem::take(&mut self.outbox)
    }

    /// Drains all queued [`WinUiBridgeMessage`] snapshots as a newline-delimited
    /// JSON (`ndjson`) payload ready for `.NET Native AOT` consumption.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError::InvalidJson`] if serialization fails.
    pub fn drain_ndjson(&mut self) -> Result<String, ActivationError> {
        let encoded = encode_ndjson_batch(&self.outbox)?;
        self.outbox.clear();
        Ok(encoded)
    }
}
