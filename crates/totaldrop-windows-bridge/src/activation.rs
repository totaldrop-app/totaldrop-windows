// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Windows 11 Explorer (`IExplorerCommand`) activation command-line and
//! single-instance Named Pipe IPC envelope parser and serializer.
//!
//! ### Why this layer exists (ADR 0016)
//!
//! When a person selects files in Windows 11 File Explorer and clicks
//! **"Send with TotalDrop"**, an architecture-matched native COM server
//! (`totaldrop_explorer_ext.dll`) receives an `IShellItemArray` inside
//! `explorer.exe` (or `dllhost.exe`). Handing that selection to
//! `totaldrop-winui.exe` has three classic Windows pitfalls:
//!
//! 1. **Shell injection:** passing file names containing `&`, `|`, `"`, or
//!    `%TEMP%` through `cmd.exe` or `ShellExecute` string concatenation executes
//!    attacker-chosen commands. TotalDrop never invokes `cmd.exe`; direct
//!    launches pass `lpApplicationName` explicitly to `CreateProcessW` and
//!    encode `lpCommandLine` with exact `CommandLineToArgvW` backslash/quote
//!    escaping.
//! 2. **Legacy `MAX_PATH` (260 UTF-16 code units):** deep folder hierarchies on
//!    NTFS/ReFS exceed 260 characters. Every validated [`WindowsSelectionPath`]
//!    normalizes to an extended-length verbatim path (`\\?\C:\…` or
//!    `\\?\UNC\server\share\…`) up to 32,767 UTF-16 code units.
//! 3. **`CreateProcessW` 32,767-character command-line limit & single-window
//!    handoff:** selecting hundreds of files overflows `lpCommandLine`, and a
//!    second launch while TotalDrop is already open must forward the selection
//!    to the existing window rather than opening a second one. Both cases use
//!    [`ActivationEnvelope`] framed over the per-session local Named Pipe
//!    `\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.<SessionId>`.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::uri::{UriValidationError, ValidatedCode};

/// Current wire schema version for [`ActivationEnvelope`].
pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;

/// Maximum UTF-16 code units permitted in a Win32 extended-length path
/// (`32,767` including the `\\?\` prefix, minus the terminating NUL).
pub const MAX_WINDOWS_PATH_UTF16: usize = 32_766;

/// Legacy Win32 directory/file `MAX_PATH` threshold (`248` UTF-16 code units,
/// `260 - 12`) at or above which Win32 APIs without `\\?\` or `longPathAware`
/// begin failing.
pub const LEGACY_MAX_PATH_THRESHOLD_UTF16: usize = 248;

/// Maximum UTF-16 code units accepted by Win32 `CreateProcessW` in
/// `lpCommandLine` (32,767 minus 1 for the terminating NUL, with safety
/// headroom reserved for the executable path).
pub const MAX_COMMAND_LINE_UTF16: usize = 30_000;

/// Maximum number of files or folders accepted in one Explorer or Share Target
/// activation envelope.
pub const MAX_SELECTION_ITEMS: usize = 10_000;

/// Maximum serialized byte size of an [`ActivationEnvelope`] frame over the
/// single-instance Named Pipe (`4 MiB`).
pub const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;

/// Prefix of the session-local Windows Named Pipe (`PIPE_REJECT_REMOTE_CLIENTS`
/// + `LOCAL\` namespace so remote SMB callers can never open it).
pub const LOCAL_PIPE_PREFIX: &str = r"\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.";

/// Reserved DOS / Win32 device stems rejected in every path segment.
const RESERVED_DOS_STEMS: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Characters forbidden inside a Windows path component (after peeling the
/// drive or `\\?\` prefix).
const FORBIDDEN_SEGMENT_CHARS: [char; 9] = ['/', '\\', ':', '<', '>', '"', '|', '?', '*'];

/// Top-level WinUI 3 navigation targets addressable via `--screen=<target>` or
/// an [`ActivationEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScreenTarget {
    /// Send files or folders (`SendPage`).
    Send,
    /// Open `SendPage` pre-populated with clipboard text (`#326`).
    Clipboard,
    /// Receive files or text (`ReceivePage`).
    Receive,
    /// Application settings (`Settings`).
    Settings,
}

impl ScreenTarget {
    /// Parses a `--screen=` value (`send`, `clipboard`, `receive`, `settings`).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "send" => Some(Self::Send),
            "clipboard" => Some(Self::Clipboard),
            "receive" => Some(Self::Receive),
            "settings" => Some(Self::Settings),
            _ => None,
        }
    }

    /// Canonical flag value used on the command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Clipboard => "clipboard",
            Self::Receive => "receive",
            Self::Settings => "settings",
        }
    }
}

/// Reason a Windows path or activation envelope was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationError {
    /// A path string was empty.
    EmptyPath,
    /// A path or argument contained a NUL or C0/C1 control character.
    ControlCharacter,
    /// A path exceeded [`MAX_WINDOWS_PATH_UTF16`] UTF-16 code units.
    PathTooLong {
        /// Measured UTF-16 code-unit length.
        utf16_len: usize,
    },
    /// The path is relative (`report.pdf`), drive-relative (`C:report.pdf`), or
    /// lacks a drive letter or `\\server\share` root.
    NotAbsoluteWindowsPath,
    /// The path targets the Win32 raw device namespace (`\\.\…`,
    /// `\\?\GLOBALROOT\…`, or a reserved DOS device like `CON` or `NUL`).
    DeviceNamespaceForbidden,
    /// A path component is `.` or `..`, which an `IExplorerCommand` selection
    /// from `SIGDN_FILESYSPATH` never legitimately produces.
    DotTraversalSegment,
    /// A path component contains a forbidden Win32 character or NTFS Alternate
    /// Data Stream (`file.txt:stream`).
    ForbiddenSegmentCharacter(char),
    /// A path component ends in an ASCII dot or space (unsafe outside verbatim
    /// mode and ambiguous in Explorer).
    TrailingDotOrSpace,
    /// More than [`MAX_SELECTION_ITEMS`] paths were supplied in one activation.
    TooManyItems {
        /// Number of items supplied.
        count: usize,
    },
    /// Explorer's `Send with TotalDrop` verb requires at least one item.
    EmptyExplorerSelection,
    /// The IPC frame or JSON payload exceeded [`MAX_ENVELOPE_BYTES`].
    EnvelopeTooLarge {
        /// Measured byte length.
        byte_len: usize,
    },
    /// The IPC frame had fewer than 4 header bytes or its length header did not
    /// match the payload slice.
    MalformedIpcFrame,
    /// Unsupported [`ActivationEnvelope::version`].
    UnsupportedSchemaVersion(u32),
    /// JSON serialization or deserialization failed.
    InvalidJson(String),
    /// An embedded protocol URI failed [`ValidatedCode`] checks.
    InvalidUri(UriValidationError),
    /// Unmatched double quote or control character in a raw Win32 command line.
    MalformedCommandLine,
}

impl core::fmt::Display for ActivationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("Windows selection path is empty"),
            Self::ControlCharacter => {
                f.write_str("Windows path or command-line argument contains a control character")
            }
            Self::PathTooLong { utf16_len } => {
                write!(
                    f,
                    "Windows path of {utf16_len} UTF-16 code units exceeds limit of {MAX_WINDOWS_PATH_UTF16}"
                )
            }
            Self::NotAbsoluteWindowsPath => {
                f.write_str("Windows selection path must be an absolute drive or UNC path")
            }
            Self::DeviceNamespaceForbidden => {
                f.write_str("Win32 device namespace and reserved DOS device names are forbidden")
            }
            Self::DotTraversalSegment => {
                f.write_str("dot and parent-directory traversal segments are forbidden")
            }
            Self::ForbiddenSegmentCharacter(ch) => {
                write!(f, "path segment contains forbidden character {ch:?}")
            }
            Self::TrailingDotOrSpace => {
                f.write_str("Windows path segment must not end with a dot or space")
            }
            Self::TooManyItems { count } => {
                write!(
                    f,
                    "selection of {count} items exceeds limit of {MAX_SELECTION_ITEMS}"
                )
            }
            Self::EmptyExplorerSelection => {
                f.write_str("Explorer Send activation must contain at least one path")
            }
            Self::EnvelopeTooLarge { byte_len } => {
                write!(
                    f,
                    "activation envelope of {byte_len} bytes exceeds limit of {MAX_ENVELOPE_BYTES}"
                )
            }
            Self::MalformedIpcFrame => {
                f.write_str("malformed Named Pipe IPC length-prefixed frame")
            }
            Self::UnsupportedSchemaVersion(v) => {
                write!(f, "unsupported activation envelope schema version {v}")
            }
            Self::InvalidJson(msg) => write!(f, "invalid activation envelope JSON: {msg}"),
            Self::InvalidUri(err) => write!(f, "invalid activation URI: {err}"),
            Self::MalformedCommandLine => {
                f.write_str("malformed Win32 command line (unclosed quote or control character)")
            }
        }
    }
}

impl std::error::Error for ActivationError {}

impl From<UriValidationError> for ActivationError {
    fn from(err: UriValidationError) -> Self {
        Self::InvalidUri(err)
    }
}

/// Kind of root a validated Windows filesystem path starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsRootKind {
    /// Local or mapped drive letter (`C:\…` / `\\?\C:\…`).
    Drive,
    /// Network share (`\\server\share\…` / `\\?\UNC\server\share\…`).
    Unc,
}

/// A validated, absolute Windows filesystem path from File Explorer, Share
/// Target, drag-and-drop, or the command line.
///
/// Internally normalized to an extended-length verbatim Win32 path
/// (`\\?\C:\…` or `\\?\UNC\server\share\…`) so paths longer than 260 UTF-16
/// code units work reliably across Windows 11 regardless of the machine's
/// `LongPathsEnabled` policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WindowsSelectionPath {
    extended: String,
    display: String,
    root_kind: WindowsRootKind,
    utf16_units: usize,
}

impl WindowsSelectionPath {
    /// Parses, validates, and normalizes a raw Windows path (`C:\…`,
    /// `\\server\share\…`, `\\?\C:\…`, or `\\?\UNC\server\share\…`).
    ///
    /// Forward slashes outside a verbatim `\\?\` prefix are normalized to `\`
    /// before segment validation; inside a `\\?\` verbatim path, `/` is
    /// rejected as a forbidden segment character because Win32 verbatim mode
    /// does not treat `/` as a separator.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError`] if the path is relative, targets a Win32
    /// device namespace, contains `..` traversal or NTFS Alternate Data
    /// Streams, or exceeds [`MAX_WINDOWS_PATH_UTF16`].
    pub fn parse(raw: &str) -> Result<Self, ActivationError> {
        if raw.is_empty() {
            return Err(ActivationError::EmptyPath);
        }
        if raw.chars().any(is_disallowed_control) {
            return Err(ActivationError::ControlCharacter);
        }

        // Reject raw Win32 device namespace (`\\.\` or `//./`) immediately.
        if raw.starts_with(r"\\.\") || raw.starts_with("//./") || raw == r"\\." {
            return Err(ActivationError::DeviceNamespaceForbidden);
        }

        let (is_verbatim, body) = if let Some(rest) = raw.strip_prefix(r"\\?\") {
            (true, rest.to_owned())
        } else {
            (false, raw.replace('/', r"\"))
        };

        // Parse either `UNC\server\share\…`, `\\server\share\…`, or `X:\…`.
        let (root_kind, extended, display) = if is_verbatim {
            if let Some(unc_rest) = body.strip_prefix(r"UNC\") {
                build_unc_paths(unc_rest)?
            } else {
                build_drive_paths(&body, true)?
            }
        } else if let Some(unc_rest) = body.strip_prefix(r"\\") {
            build_unc_paths(unc_rest)?
        } else {
            build_drive_paths(&body, false)?
        };

        let utf16_units = extended.encode_utf16().count();
        if utf16_units > MAX_WINDOWS_PATH_UTF16 {
            return Err(ActivationError::PathTooLong {
                utf16_len: utf16_units,
            });
        }

        Ok(Self {
            extended,
            display,
            root_kind,
            utf16_units,
        })
    }

    /// Extended-length verbatim Win32 path (`\\?\C:\…` or
    /// `\\?\UNC\server\share\…`) suitable for `CreateFileW` and `std::fs` on
    /// Windows without `MAX_PATH` 260-character truncation.
    #[must_use]
    pub fn extended_path(&self) -> &str {
        &self.extended
    }

    /// Clean Win32 path without the `\\?\` prefix (`C:\…` or
    /// `\\server\share\…`), with invisible/bidi control characters revealed as
    /// `<U+XXXX>` for safe UI rendering in WinUI 3.
    #[must_use]
    pub fn safe_display_path(&self) -> String {
        totaldrop_l10n::reveal_controls(&self.display)
    }

    /// Unprefixed Win32 path (`C:\…` or `\\server\share\…`).
    #[must_use]
    pub fn unprefixed_path(&self) -> &str {
        &self.display
    }

    /// Root classification (`Drive` or `Unc`).
    #[must_use]
    pub const fn root_kind(&self) -> WindowsRootKind {
        self.root_kind
    }

    /// Length of [`Self::extended_path`] in UTF-16 code units.
    #[must_use]
    pub const fn utf16_len(&self) -> usize {
        self.utf16_units
    }

    /// Returns `true` when the unprefixed path meets or exceeds the legacy
    /// Win32 `MAX_PATH` threshold (`248` UTF-16 code units) and therefore
    /// strictly requires `\\?\` extended-length handling.
    #[must_use]
    pub fn exceeds_legacy_max_path(&self) -> bool {
        self.display.encode_utf16().count() >= LEGACY_MAX_PATH_THRESHOLD_UTF16
    }

    /// Case-folded deduplication key on Windows NTFS/ReFS.
    #[must_use]
    pub fn deduplication_key(&self) -> String {
        self.extended.to_lowercase()
    }
}

impl TryFrom<String> for WindowsSelectionPath {
    type Error = ActivationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<WindowsSelectionPath> for String {
    fn from(value: WindowsSelectionPath) -> Self {
        value.extended
    }
}

impl AsRef<std::path::Path> for WindowsSelectionPath {
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.extended)
    }
}

/// Normalized Windows path projection returned over C ABI JSON for WinUI 3
/// file/folder selection and display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedWindowsPath {
    /// Extended-length verbatim Win32 path (`\\?\C:\…` or `\\?\UNC\…`).
    pub extended_path: String,
    /// Unprefixed Win32 path (`C:\…` or `\\server\share\…`).
    pub unprefixed_path: String,
    /// Unprefixed display path with hidden control/bidi characters revealed as
    /// `<U+XXXX>`.
    pub safe_display_path: String,
    /// Root classification (`drive` or `unc`).
    pub root_kind: WindowsRootKind,
    /// UTF-16 code-unit length of `extended_path`.
    pub utf16_len: usize,
    /// Whether `unprefixed_path` meets or exceeds the legacy `248`-unit
    /// `MAX_PATH` threshold.
    pub exceeds_legacy_max_path: bool,
}

impl From<&WindowsSelectionPath> for NormalizedWindowsPath {
    fn from(path: &WindowsSelectionPath) -> Self {
        Self {
            extended_path: path.extended_path().to_owned(),
            unprefixed_path: path.unprefixed_path().to_owned(),
            safe_display_path: path.safe_display_path(),
            root_kind: path.root_kind(),
            utf16_len: path.utf16_len(),
            exceeds_legacy_max_path: path.exceeds_legacy_max_path(),
        }
    }
}

/// Validates and normalizes an iterator of raw Windows paths via
/// [`WindowsSelectionPath::parse`], deduplicating case-insensitively while
/// preserving first-seen order and enforcing [`MAX_SELECTION_ITEMS`].
///
/// # Errors
///
/// Returns [`ActivationError`] if more than [`MAX_SELECTION_ITEMS`] paths are
/// provided or if any path fails Windows path security checks.
pub fn validate_windows_paths<I, S>(
    raw_paths: I,
) -> Result<Vec<NormalizedWindowsPath>, ActivationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for (idx, raw) in raw_paths.into_iter().enumerate() {
        if idx >= MAX_SELECTION_ITEMS {
            return Err(ActivationError::TooManyItems {
                count: idx.saturating_add(1),
            });
        }
        let parsed = WindowsSelectionPath::parse(raw.as_ref())?;
        if seen.insert(parsed.deduplication_key()) {
            normalized.push(NormalizedWindowsPath::from(&parsed));
        }
    }
    Ok(normalized)
}

fn is_disallowed_control(c: char) -> bool {
    let code = u32::from(c);
    code <= 0x1F || (0x7F..=0x9F).contains(&code)
}

fn is_reserved_dos_segment(segment: &str) -> bool {
    // Windows treats `CON`, `CON.txt`, `CON.tar.gz`, and `LPT¹` as device
    // names. Check the stem before the first `.`, trimmed of spaces.
    let stem = segment.split('.').next().unwrap_or("").trim_end();
    let upper = stem.to_ascii_uppercase();
    if RESERVED_DOS_STEMS.contains(&upper.as_str()) {
        return true;
    }
    // Superscript digits U+00B9 (`¹`), U+00B2 (`²`), U+00B3 (`³`) on COM/LPT.
    matches!(
        upper.as_str(),
        "COM\u{00B9}"
            | "COM\u{00B2}"
            | "COM\u{00B3}"
            | "LPT\u{00B9}"
            | "LPT\u{00B2}"
            | "LPT\u{00B3}"
    )
}

fn validate_segment(segment: &str) -> Result<(), ActivationError> {
    if segment == "." || segment == ".." {
        return Err(ActivationError::DotTraversalSegment);
    }
    for ch in segment.chars() {
        if FORBIDDEN_SEGMENT_CHARS.contains(&ch) {
            return Err(ActivationError::ForbiddenSegmentCharacter(ch));
        }
    }
    if segment.ends_with('.') || segment.ends_with(' ') {
        return Err(ActivationError::TrailingDotOrSpace);
    }
    if is_reserved_dos_segment(segment) {
        return Err(ActivationError::DeviceNamespaceForbidden);
    }
    Ok(())
}

fn build_drive_paths(
    body: &str,
    is_verbatim: bool,
) -> Result<(WindowsRootKind, String, String), ActivationError> {
    // Reject non-drive verbatim targets such as `\\?\GLOBALROOT\…`,
    // `\\?\Volume{guid}\…`, or `\\?\PIPE\…`.
    let mut chars = body.chars();
    let Some(drive_letter) = chars.next() else {
        return Err(ActivationError::EmptyPath);
    };
    if !drive_letter.is_ascii_alphabetic() {
        return Err(ActivationError::NotAbsoluteWindowsPath);
    }
    if chars.next() != Some(':') {
        // E.g. `GLOBALROOT\…`, `Volume{…}`, or `PIPE\…` inside `\\?\` (case-insensitive).
        let upper = body.to_ascii_uppercase();
        if upper.starts_with("GLOBALROOT")
            || upper.starts_with("VOLUME{")
            || (is_verbatim && (upper.starts_with(r"PIPE\") || upper == "PIPE"))
        {
            return Err(ActivationError::DeviceNamespaceForbidden);
        }
        return Err(ActivationError::NotAbsoluteWindowsPath);
    }
    if chars.next() != Some('\\') {
        // Drive-relative `C:report.pdf` is rejected.
        return Err(ActivationError::NotAbsoluteWindowsPath);
    }

    let rest = chars.as_str();
    let upper_drive = drive_letter.to_ascii_uppercase();
    let mut segments = Vec::new();
    for part in rest.split('\\') {
        if part.is_empty() {
            continue;
        }
        validate_segment(part)?;
        segments.push(part);
    }

    let joined = segments.join(r"\");
    let display = if joined.is_empty() {
        format!(r"{upper_drive}:\")
    } else {
        format!(r"{upper_drive}:\{joined}")
    };
    let extended = format!(r"\\?\{display}");
    Ok((WindowsRootKind::Drive, extended, display))
}

fn build_unc_paths(unc_rest: &str) -> Result<(WindowsRootKind, String, String), ActivationError> {
    // `unc_rest` must start with `<server>\<share>` (neither empty, nor `.` or
    // `?` which would alias the local device namespace `\\.\` / `\\?\`).
    let mut parts = unc_rest.split('\\');
    let Some(server) = parts.next() else {
        return Err(ActivationError::NotAbsoluteWindowsPath);
    };
    let Some(share) = parts.next() else {
        return Err(ActivationError::NotAbsoluteWindowsPath);
    };
    if server.is_empty() || share.is_empty() {
        return Err(ActivationError::NotAbsoluteWindowsPath);
    }
    if server == "." || server == "?" {
        return Err(ActivationError::DeviceNamespaceForbidden);
    }
    validate_segment(server)?;
    validate_segment(share)?;

    let mut segments = Vec::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        validate_segment(part)?;
        segments.push(part);
    }

    let tail = if segments.is_empty() {
        String::new()
    } else {
        format!(r"\{}", segments.join(r"\"))
    };
    let display = format!(r"\\{server}\{share}{tail}");
    let extended = format!(r"\\?\UNC\{server}\{share}{tail}");
    Ok((WindowsRootKind::Unc, extended, display))
}

/// Payload carried inside an [`ActivationEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActivationPayload {
    /// Files and/or folders invoked from Windows 11 File Explorer's right-click
    /// **"Send with TotalDrop"** (`IExplorerCommand`) verb or desktop
    /// drag-and-drop.
    ExplorerSend {
        /// Validated, deduplicated extended-length Win32 paths in selection
        /// order.
        paths: Vec<WindowsSelectionPath>,
    },
    /// Protocol URI handoff (`totaldrop://r/<code>` or
    /// `https://totaldrop.app/r#<code>`).
    ProtocolUri {
        /// Validated transfer code extracted from the URI.
        code: ValidatedCode,
    },
    /// Windows Share Target activation (`DataPackageView` containing files
    /// and/or shared plain text).
    ShareTarget {
        /// Shared filesystem items, if any.
        paths: Vec<WindowsSelectionPath>,
        /// Shared plain text, if any.
        text: Option<String>,
    },
    /// Explicit navigation request (`--screen=send|clipboard|receive|settings`).
    OpenScreen {
        /// Target WinUI 3 page.
        screen: ScreenTarget,
    },
}

/// Versioned activation envelope exchanged between `totaldrop_explorer_ext.dll`
/// (or a secondary `totaldrop-winui.exe` launch) and the primary single-window
/// WinUI 3 process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationEnvelope {
    /// Wire format version (must equal [`ENVELOPE_SCHEMA_VERSION`]).
    pub version: u32,
    /// Optional Win32 foreground activation window message / allowance token
    /// (`CoAllowSetForegroundWindow` / process ID hint, informational only).
    pub initiator_pid: Option<u32>,
    /// Typed activation payload.
    pub payload: ActivationPayload,
}

impl ActivationEnvelope {
    /// Constructs a validated `ExplorerSend` envelope from raw paths returned
    /// by `IShellItem::GetDisplayName(SIGDN_FILESYSPATH)`, preserving selection
    /// order while deduplicating case-insensitively.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError`] if `raw_paths` is empty, exceeds
    /// [`MAX_SELECTION_ITEMS`], or contains any invalid path.
    pub fn explorer_send<I, S>(
        raw_paths: I,
        initiator_pid: Option<u32>,
    ) -> Result<Self, ActivationError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = HashSet::new();
        let mut paths = Vec::new();
        for raw in raw_paths {
            if paths.len() >= MAX_SELECTION_ITEMS {
                return Err(ActivationError::TooManyItems {
                    count: paths.len().saturating_add(1),
                });
            }
            let validated = WindowsSelectionPath::parse(raw.as_ref())?;
            if seen.insert(validated.deduplication_key()) {
                paths.push(validated);
            }
        }
        if paths.is_empty() {
            return Err(ActivationError::EmptyExplorerSelection);
        }
        Ok(Self {
            version: ENVELOPE_SCHEMA_VERSION,
            initiator_pid,
            payload: ActivationPayload::ExplorerSend { paths },
        })
    }

    /// Constructs a `ProtocolUri` activation envelope after validating `uri`.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError::InvalidUri`] when `uri` is not a valid
    /// TotalDrop link.
    pub fn protocol_uri(uri: &str, initiator_pid: Option<u32>) -> Result<Self, ActivationError> {
        let code = ValidatedCode::from_activation_uri(uri)?;
        Ok(Self {
            version: ENVELOPE_SCHEMA_VERSION,
            initiator_pid,
            payload: ActivationPayload::ProtocolUri { code },
        })
    }

    /// Constructs a `ShareTarget` activation envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError`] if any shared path fails validation or the
    /// selection exceeds [`MAX_SELECTION_ITEMS`].
    pub fn share_target<I, S>(
        raw_paths: I,
        text: Option<String>,
        initiator_pid: Option<u32>,
    ) -> Result<Self, ActivationError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = HashSet::new();
        let mut paths = Vec::new();
        for raw in raw_paths {
            if paths.len() >= MAX_SELECTION_ITEMS {
                return Err(ActivationError::TooManyItems {
                    count: paths.len().saturating_add(1),
                });
            }
            let validated = WindowsSelectionPath::parse(raw.as_ref())?;
            if seen.insert(validated.deduplication_key()) {
                paths.push(validated);
            }
        }
        Ok(Self {
            version: ENVELOPE_SCHEMA_VERSION,
            initiator_pid,
            payload: ActivationPayload::ShareTarget { paths, text },
        })
    }

    /// Constructs an `OpenScreen` envelope.
    #[must_use]
    pub const fn open_screen(screen: ScreenTarget, initiator_pid: Option<u32>) -> Self {
        Self {
            version: ENVELOPE_SCHEMA_VERSION,
            initiator_pid,
            payload: ActivationPayload::OpenScreen { screen },
        }
    }

    /// Serializes this envelope to compact UTF-8 JSON, enforcing
    /// [`MAX_ENVELOPE_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError`] if serialization fails or the output exceeds
    /// [`MAX_ENVELOPE_BYTES`].
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ActivationError> {
        let bytes =
            serde_json::to_vec(self).map_err(|e| ActivationError::InvalidJson(e.to_string()))?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(ActivationError::EnvelopeTooLarge {
                byte_len: bytes.len(),
            });
        }
        Ok(bytes)
    }

    /// Parses and validates an [`ActivationEnvelope`] from UTF-8 JSON bytes.
    ///
    /// Re-runs schema version, item count, and path/URI invariants so an
    /// untrusted same-session caller cannot bypass constructor checks.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError`] if the payload is oversized, malformed, has
    /// an unknown schema version, or violates selection invariants.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ActivationError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(ActivationError::EnvelopeTooLarge {
                byte_len: bytes.len(),
            });
        }
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|e| ActivationError::InvalidJson(e.to_string()))?;
        envelope.validate_invariants()?;
        Ok(envelope)
    }

    /// Encodes this envelope into a 4-byte little-endian length-prefixed frame
    /// for transmission over TotalDrop's session-local Windows Named Pipe.
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError`] if JSON serialization fails or exceeds
    /// [`MAX_ENVELOPE_BYTES`].
    pub fn encode_ipc_frame(&self) -> Result<Vec<u8>, ActivationError> {
        let payload = self.to_json_bytes()?;
        let len_u32 =
            u32::try_from(payload.len()).map_err(|_| ActivationError::EnvelopeTooLarge {
                byte_len: payload.len(),
            })?;
        let mut frame = Vec::with_capacity(payload.len().saturating_add(4));
        frame.extend_from_slice(&len_u32.to_le_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// Decodes a 4-byte little-endian length-prefixed Named Pipe frame back
    /// into a validated [`ActivationEnvelope`].
    ///
    /// # Errors
    ///
    /// Returns [`ActivationError`] if the frame header is truncated, exceeds
    /// [`MAX_ENVELOPE_BYTES`], does not match the payload length, or contains
    /// invalid envelope data.
    pub fn decode_ipc_frame(frame: &[u8]) -> Result<Self, ActivationError> {
        let Some((header, payload)) = frame.split_at_checked(4) else {
            return Err(ActivationError::MalformedIpcFrame);
        };
        let mut header_bytes = [0u8; 4];
        header_bytes.copy_from_slice(header);
        let declared_len = usize::try_from(u32::from_le_bytes(header_bytes))
            .map_err(|_| ActivationError::MalformedIpcFrame)?;
        if declared_len > MAX_ENVELOPE_BYTES {
            return Err(ActivationError::EnvelopeTooLarge {
                byte_len: declared_len,
            });
        }
        if payload.len() != declared_len {
            return Err(ActivationError::MalformedIpcFrame);
        }
        Self::from_json_bytes(payload)
    }

    fn validate_invariants(&self) -> Result<(), ActivationError> {
        if self.version != ENVELOPE_SCHEMA_VERSION {
            return Err(ActivationError::UnsupportedSchemaVersion(self.version));
        }
        match &self.payload {
            ActivationPayload::ExplorerSend { paths } => {
                if paths.is_empty() {
                    return Err(ActivationError::EmptyExplorerSelection);
                }
                if paths.len() > MAX_SELECTION_ITEMS {
                    return Err(ActivationError::TooManyItems { count: paths.len() });
                }
            }
            ActivationPayload::ProtocolUri { code } => {
                // Re-verify all derived ValidatedCode fields through totaldrop-proto so
                // raw Named Pipe IPC frames cannot tamper with canonical, nameplate,
                // word_count, ltr_isolated, protocol_uri, or web_uri.
                let parsed = ValidatedCode::from_user_input(&code.display_english)?;
                if parsed != *code {
                    return Err(ActivationError::InvalidUri(
                        UriValidationError::InvalidActivationLink,
                    ));
                }
            }
            ActivationPayload::ShareTarget { paths, .. } => {
                if paths.len() > MAX_SELECTION_ITEMS {
                    return Err(ActivationError::TooManyItems { count: paths.len() });
                }
            }
            ActivationPayload::OpenScreen { .. } => {}
        }
        Ok(())
    }
}

/// Builds the session-scoped local Named Pipe path
/// (`\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.<session_id>`) used by the
/// primary WinUI 3 window and `IExplorerCommand` COM handler.
#[must_use]
pub fn session_named_pipe_path(windows_session_id: u32) -> String {
    format!("{LOCAL_PIPE_PREFIX}{windows_session_id}")
}

/// Escapes a single argument according to Microsoft's `CommandLineToArgvW`
/// C/C++ startup rules so `CreateProcessW(lpApplicationName, lpCommandLine, …)`
/// delivers the exact string without ever invoking `cmd.exe`.
///
/// # Errors
///
/// Returns [`ActivationError::ControlCharacter`] if `arg` contains `\0`, `\r`,
/// or `\n` (which could confuse legacy argument loggers or truncate Win32
/// wide strings).
pub fn quote_win32_arg(arg: &str) -> Result<String, ActivationError> {
    if arg.chars().any(|c| matches!(c, '\0' | '\r' | '\n')) {
        return Err(ActivationError::ControlCharacter);
    }
    let needs_quotes = arg.is_empty()
        || arg.chars().any(|c| {
            matches!(
                c,
                ' ' | '\t' | '"' | '&' | '|' | '<' | '>' | '^' | '(' | ')' | '%'
            )
        });
    if !needs_quotes {
        return Ok(arg.to_owned());
    }

    let mut out = String::with_capacity(arg.len().saturating_add(4));
    out.push('"');
    let mut backslashes: usize = 0;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes = backslashes.saturating_add(1);
        } else if ch == '"' {
            // Double all preceding backslashes, then escape the quote itself.
            for _ in 0..backslashes.saturating_mul(2).saturating_add(1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(ch);
        }
    }
    // Double trailing backslashes before the closing quote so `C:\Dir\` does
    // not escape the closing `"`.
    for _ in 0..backslashes.saturating_mul(2) {
        out.push('\\');
    }
    out.push('"');
    Ok(out)
}

/// Splits a raw Win32 command line (excluding `argv[0]`, or full command line
/// when `skip_executable` is `true`) using `CommandLineToArgvW` quoting rules.
///
/// # Errors
///
/// Returns [`ActivationError::MalformedCommandLine`] on an unclosed `"` or
/// embedded NUL character.
pub fn split_win32_command_line(
    command_line: &str,
    skip_executable: bool,
) -> Result<Vec<String>, ActivationError> {
    if command_line.contains('\0') {
        return Err(ActivationError::MalformedCommandLine);
    }
    let mut tokens = Vec::new();
    let mut chars = command_line.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch == ' ' || ch == '\t' {
            chars.next();
            continue;
        }
        let mut current = String::new();
        let mut in_quotes = false;
        let mut backslashes: usize = 0;

        while let Some(next) = chars.next() {
            if next == '\\' {
                backslashes = backslashes.saturating_add(1);
                continue;
            }
            if next == '"' {
                let half = backslashes.checked_div(2).unwrap_or(0);
                for _ in 0..half {
                    current.push('\\');
                }
                if backslashes.checked_rem(2) == Some(0) {
                    // Check for `""` inside a quoted span, which emits a literal `"`.
                    if in_quotes && chars.peek() == Some(&'"') {
                        chars.next();
                        current.push('"');
                    } else {
                        in_quotes = !in_quotes;
                    }
                } else {
                    current.push('"');
                }
                backslashes = 0;
                continue;
            }
            for _ in 0..backslashes {
                current.push('\\');
            }
            backslashes = 0;
            if !in_quotes && (next == ' ' || next == '\t') {
                break;
            }
            current.push(next);
        }

        for _ in 0..backslashes {
            current.push('\\');
        }
        if in_quotes {
            return Err(ActivationError::MalformedCommandLine);
        }
        tokens.push(current);
    }

    if skip_executable {
        Ok(tokens.into_iter().skip(1).collect())
    } else {
        Ok(tokens)
    }
}

/// Transport mechanism selected for handing an `IExplorerCommand` selection
/// from `explorer.exe` to `totaldrop-winui.exe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplorerLaunchTransport {
    /// Selection fits safely inside `CreateProcessW`'s 32,767-UTF-16 limit when
    /// cold-starting the first window (`totaldrop-winui.exe --explorer-send -- <paths>`).
    DirectCommandLine {
        /// Complete `lpCommandLine` string (starting with quoted `exe_path`),
        /// safe ONLY with explicit `lpApplicationName` in `CreateProcessW`.
        command_line: String,
        ///Length of `command_line` in UTF-16 code units.
        utf16_len: usize,
    },
    /// Selection exceeds safe Win32 `lpCommandLine` bounds (or an existing
    /// window is listening): cold-start `totaldrop-winui.exe --ipc-pipe=<name>`
    /// and stream the [`ActivationEnvelope`] frame over the session Named Pipe.
    NamedPipeIpc {
        /// Session-scoped Named Pipe path.
        pipe_path: String,
        /// Minimal cold-start command line (`"<exe>" --ipc-await`).
        cold_start_command_line: String,
        /// Framed IPC bytes (`encode_ipc_frame`).
        ipc_frame: Vec<u8>,
    },
}

/// Plans how `totaldrop_explorer_ext.dll` launches or messages
/// `totaldrop-winui.exe` for an Explorer right-click selection.
///
/// # Errors
///
/// Returns [`ActivationError`] if `exe_path` or any selected path fails
/// validation.
pub fn plan_explorer_invocation(
    exe_path: &str,
    envelope: &ActivationEnvelope,
    windows_session_id: u32,
    window_already_open: bool,
) -> Result<ExplorerLaunchTransport, ActivationError> {
    let validated_exe = WindowsSelectionPath::parse(exe_path)?;
    let quoted_exe = quote_win32_arg(validated_exe.unprefixed_path())?;

    if !window_already_open && let ActivationPayload::ExplorerSend { paths } = &envelope.payload {
        let mut parts = Vec::with_capacity(paths.len().saturating_add(3));
        parts.push(quoted_exe.clone());
        parts.push("--explorer-send".to_owned());
        parts.push("--".to_owned());
        for path in paths {
            parts.push(quote_win32_arg(path.extended_path())?);
        }
        let command_line = parts.join(" ");
        let utf16_len = command_line.encode_utf16().count();
        if utf16_len <= MAX_COMMAND_LINE_UTF16 {
            return Ok(ExplorerLaunchTransport::DirectCommandLine {
                command_line,
                utf16_len,
            });
        }
    }

    let pipe_path = session_named_pipe_path(windows_session_id);
    let cold_start_command_line = format!("{quoted_exe} --ipc-await");
    let ipc_frame = envelope.encode_ipc_frame()?;
    Ok(ExplorerLaunchTransport::NamedPipeIpc {
        pipe_path,
        cold_start_command_line,
        ipc_frame,
    })
}

/// Parses command-line arguments received by `totaldrop-winui.exe` (excluding
/// `argv[0]`) into a typed [`ActivationEnvelope`], or `None` when launched
/// cleanly from the Start Menu with no arguments.
///
/// Supports:
/// - `--explorer-send -- <path1> <path2> …`
/// - `--screen=<send|clipboard|receive|settings>`
/// - `totaldrop://r/<code>` or `https://totaldrop.app/r#<code>`
/// - bare absolute Windows paths (`C:\…`, `\\server\share\…`, `\\?\C:\…`)
///
/// # Errors
///
/// Returns [`ActivationError`] when arguments request an invalid URI, malformed
/// path, or empty `--explorer-send` selection.
pub fn parse_launch_args<I, S>(args: I) -> Result<Option<ActivationEnvelope>, ActivationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let collected: Vec<String> = args.into_iter().map(|s| s.as_ref().to_owned()).collect();
    // Wait-for-pipe cold-start sentinel: payload arrives over Named Pipe IPC.
    if collected.len() == 1 && collected.first().map(String::as_str) == Some("--ipc-await") {
        return Ok(None);
    }
    if collected.is_empty() {
        return Ok(None);
    }

    let mut explorer_mode = false;
    let mut options_active = true;
    let mut screen: Option<ScreenTarget> = None;
    let mut raw_items: Vec<&str> = Vec::new();

    for arg in &collected {
        let arg = arg.as_str();
        if options_active {
            if arg == "--" {
                options_active = false;
                continue;
            }
            if arg == "--explorer-send" {
                explorer_mode = true;
                continue;
            }
            if let Some(target_str) = arg.strip_prefix("--screen=") {
                if let Some(parsed) = ScreenTarget::parse(target_str) {
                    screen = Some(parsed);
                }
                continue;
            }
            if arg.starts_with('-') && arg.len() > 1 {
                // Ignore Windows App SDK / system switches while never treating
                // them as filenames prior to `--`.
                continue;
            }
        }
        raw_items.push(arg);
    }

    if explorer_mode {
        return ActivationEnvelope::explorer_send(raw_items, None).map(Some);
    }

    if let [single] = raw_items.as_slice()
        && (single.starts_with("totaldrop:")
            || single.starts_with("https://")
            || single.starts_with("http://"))
    {
        return ActivationEnvelope::protocol_uri(single, None).map(Some);
    }

    if !raw_items.is_empty() {
        return ActivationEnvelope::explorer_send(raw_items, None).map(Some);
    }

    if let Some(screen) = screen {
        return Ok(Some(ActivationEnvelope::open_screen(screen, None)));
    }

    Ok(None)
}
