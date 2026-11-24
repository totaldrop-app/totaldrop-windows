// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transfer code and Windows protocol activation URI validation.
//!
//! Windows 11 activates `totaldrop-winui.exe` for `totaldrop://r/<code>` links
//! registered via `<uap:Protocol Name="totaldrop">` in `Package.appxmanifest`,
//! and users may also paste web handoff links (`https://totaldrop.app/r#<code>`)
//! or full share messages into `ReceivePage`.
//!
//! All parsing delegates to [`totaldrop_proto::TransferCode`] so Windows
//! enforces the exact same single-pass `%XX` decoding, `MAX_LINK_BYTES` bound,
//! invisible-format stripping, and Arabic-Indic digit normalization as Linux,
//! Android, and the CLI.

use serde::{Deserialize, Serialize};
use totaldrop_proto::{CodeError, MAX_LINK_BYTES, TransferCode};

/// First Strong Isolate (`U+2068`), keeping an English transfer code ordered
/// left-to-right when embedded inside a right-to-left sentence.
const FSI: char = '\u{2068}';

/// Pop Directional Isolate (`U+2069`), closing [`FSI`].
const PDI: char = '\u{2069}';

/// Structured failure returned when a URI or user-typed transfer code is
/// rejected before opening a rendezvous mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UriValidationError {
    /// The input was empty or whitespace-only after stripping invisible format
    /// characters.
    Empty,
    /// The activation URI exceeded [`totaldrop_proto::MAX_LINK_BYTES`] (1024
    /// bytes) and was refused unread.
    LinkTooLong {
        /// Byte length of the rejected link.
        byte_len: usize,
        /// Maximum allowed byte length.
        limit: usize,
    },
    /// The activation link did not match a valid TotalDrop URI or bare transfer
    /// code (for example, an untrusted host, extra query string, or file path).
    InvalidActivationLink,
    /// The code did not begin with a non-zero nameplate integer.
    BadNameplate,
    /// The code did not contain 2 or 3 secret words after the nameplate.
    WrongWordCount,
    /// One of the words was neither in the 2048-word English BIP-39 wordlist
    /// nor a valid list index (`0..2048`).
    UnknownWord {
        /// The unrecognized token, normalized to lower case.
        word: String,
    },
    /// No valid transfer code was found inside clipboard or share text.
    NoCodeFoundInText,
}

impl UriValidationError {
    /// Returns the `l10n/app` message key used by WinUI 3 to explain the
    /// validation failure in the user's display language.
    #[must_use]
    pub const fn l10n_key(&self) -> &'static str {
        match self {
            Self::Empty | Self::BadNameplate | Self::WrongWordCount | Self::UnknownWord { .. } => {
                "receiveCodeInvalid"
            }
            Self::LinkTooLong { .. } | Self::InvalidActivationLink | Self::NoCodeFoundInText => {
                "errorInvalidCode"
            }
        }
    }
}

impl core::fmt::Display for UriValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("transfer code input is empty"),
            Self::LinkTooLong { byte_len, limit } => {
                write!(
                    f,
                    "activation link of {byte_len} bytes exceeds limit of {limit} bytes"
                )
            }
            Self::InvalidActivationLink => {
                f.write_str("input is not a valid TotalDrop activation link or transfer code")
            }
            Self::BadNameplate => {
                f.write_str("the code must start with a positive number, like 7-harbor-rocket")
            }
            Self::WrongWordCount => {
                f.write_str("the code must have two or three words after the number")
            }
            Self::UnknownWord { word } => write!(f, "{word:?} is not a valid TotalDrop code word"),
            Self::NoCodeFoundInText => f.write_str("no TotalDrop transfer code found in text"),
        }
    }
}

impl std::error::Error for UriValidationError {}

impl From<CodeError> for UriValidationError {
    fn from(err: CodeError) -> Self {
        match err {
            CodeError::BadNameplate => Self::BadNameplate,
            CodeError::WrongWordCount => Self::WrongWordCount,
            CodeError::UnknownWord(word) => Self::UnknownWord { word },
            CodeError::Random => Self::InvalidActivationLink,
        }
    }
}

/// A validated TotalDrop transfer code ready for WinUI 3 display, Narrator
/// screen-reader output, and `totaldrop-core` rendezvous connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedCode {
    /// Mailbox nameplate integer (`> 0`).
    pub nameplate: u32,
    /// Number of secret words (`2` for standard, `3` for stronger code).
    pub word_count: u8,
    /// Human-readable English form (`"7-harbor-rocket"`), always ASCII and
    /// left-to-right in every language (ADR 0008).
    pub display_english: String,
    /// Canonical index form (`"7-840-1499"`) passed into CPace.
    pub canonical: String,
    /// Bidirectional-isolated form (`"\u{2068}7-harbor-rocket\u{2069}"`) safe
    /// to interpolate into right-to-left sentences.
    pub ltr_isolated: String,
    /// Canonical Windows protocol URI (`"totaldrop://r/7-harbor-rocket"`).
    pub protocol_uri: String,
    /// Canonical web handoff URI (`"https://totaldrop.app/r#7-harbor-rocket"`).
    pub web_uri: String,
}

impl ValidatedCode {
    /// Wraps an already-validated [`TransferCode`].
    #[must_use]
    pub fn from_proto(code: &TransferCode) -> Self {
        let display_english = code.to_english();
        let canonical = code.canonical();
        // `canonical` is `<nameplate>-<w1>-<w2>[-<w3>]`; count the words after
        // the nameplate without indexing or panicking.
        let word_count = u8::try_from(canonical.split('-').skip(1).count()).unwrap_or(2);
        let ltr_isolated = format!("{FSI}{display_english}{PDI}");
        let protocol_uri = format!("totaldrop://r/{display_english}");
        let web_uri = format!("https://totaldrop.app/r#{display_english}");
        Self {
            nameplate: code.nameplate(),
            word_count,
            display_english,
            canonical,
            ltr_isolated,
            protocol_uri,
            web_uri,
        }
    }

    /// Validates a strict Windows protocol activation URI
    /// (`totaldrop://r/7-harbor-rocket`, `totaldrop:7-harbor-rocket`,
    /// `https://totaldrop.app/r#7-harbor-rocket`, or `http://totaldrop.app/r#…`)
    /// or a bare code passed on the command line via [`TransferCode::from_link`].
    ///
    /// Note that Windows Shell sometimes appends a single trailing slash to a
    /// custom scheme URI when launched from certain browsers
    /// (`totaldrop://r/7-harbor-rocket/` -> rejected unless clean, or we trim
    /// nothing that `TransferCode::from_link` refuses except we delegate
    /// strictly to `TransferCode::from_link` so untrusted paths or query
    /// parameters like `?x=1` never slip through).
    ///
    /// # Errors
    ///
    /// Returns [`UriValidationError`] if `uri` is empty, longer than
    /// [`MAX_LINK_BYTES`], or rejected by [`TransferCode::from_link`].
    pub fn from_activation_uri(uri: &str) -> Result<Self, UriValidationError> {
        if uri.len() > MAX_LINK_BYTES {
            return Err(UriValidationError::LinkTooLong {
                byte_len: uri.len(),
                limit: MAX_LINK_BYTES,
            });
        }
        let normalized = normalize_activation_prefix(uri);
        if normalized.is_empty() {
            return Err(UriValidationError::Empty);
        }
        let code = TransferCode::from_link(&normalized)
            .ok_or(UriValidationError::InvalidActivationLink)?;
        Ok(Self::from_proto(&code))
    }

    /// Validates interactive input typed into WinUI 3's `ReceivePage` code box.
    ///
    /// Accepts either a link (`https://totaldrop.app/r#…`, `totaldrop://r/…`)
    /// or a human-entered code (`"7 harbor rocket"`, `"7-harbor-rocket"`,
    /// Arabic-Indic digits `"\u{0667}-harbor-rocket"`, or list indices
    /// `"7-840-1499"`), returning a specific [`UriValidationError`] reason when
    /// invalid.
    ///
    /// # Errors
    ///
    /// Returns [`UriValidationError`] describing why the typed code is not
    /// valid.
    pub fn from_user_input(input: &str) -> Result<Self, UriValidationError> {
        let normalized = normalize_activation_prefix(input);
        if input.len() <= MAX_LINK_BYTES
            && !normalized.is_empty()
            && let Some(code) = TransferCode::from_link(&normalized)
        {
            return Ok(Self::from_proto(&code));
        }
        if normalized.is_empty() {
            return Err(UriValidationError::Empty);
        }
        // If the person pasted a link with a recognized scheme, reject it as a
        // bad link rather than reporting "the code must start with a number".
        if has_activation_scheme_prefix(&normalized) {
            return Err(UriValidationError::InvalidActivationLink);
        }
        let code = TransferCode::parse(&normalized)?;
        Ok(Self::from_proto(&code))
    }

    /// Extracts a transfer code from pasted clipboard or Windows Share Target
    /// text (for example `"Get my files with TotalDrop. Code: 7-harbor-rocket"`
    /// or an isolated RTL share sentence).
    ///
    /// Checks [`TransferCode::from_link`] first (in case the clipboard holds a
    /// full URL), then falls back to [`TransferCode::find`].
    ///
    /// # Errors
    ///
    /// Returns [`UriValidationError::NoCodeFoundInText`] if no unambiguous
    /// transfer code or link is present.
    pub fn from_clipboard_text(text: &str) -> Result<Self, UriValidationError> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(UriValidationError::Empty);
        }
        if trimmed.len() <= MAX_LINK_BYTES {
            let normalized = normalize_activation_prefix(trimmed);
            if !normalized.is_empty()
                && let Some(code) = TransferCode::from_link(&normalized)
            {
                return Ok(Self::from_proto(&code));
            }
        }
        // Scan whitespace-delimited tokens for a standalone TotalDrop link inside
        // a longer message before falling back to `TransferCode::find`.
        for token in trimmed.split_whitespace() {
            let clean =
                token.trim_matches(|c: char| matches!(c, '(' | ')' | '<' | '>' | '"' | '.'));
            let normalized = normalize_activation_prefix(clean);
            if (normalized.starts_with("https://totaldrop.app/r#")
                || normalized.starts_with("http://totaldrop.app/r#")
                || normalized.starts_with("totaldrop://r/"))
                && let Some(code) = TransferCode::from_link(&normalized)
            {
                return Ok(Self::from_proto(&code));
            }
        }
        let code = TransferCode::find(trimmed).ok_or(UriValidationError::NoCodeFoundInText)?;
        Ok(Self::from_proto(&code))
    }

    /// Returns `true` when this code uses the 3-word stronger mode (~33 bits
    /// of secret entropy instead of ~22 bits).
    #[must_use]
    pub const fn is_strong(&self) -> bool {
        self.word_count >= 3
    }
}

/// Returns up to `limit` BIP-39 English transfer code words starting with
/// `prefix` (case-insensitive ASCII letters only), matching Linux desktop
/// autocomplete behavior.
///
/// Empty, non-ASCII-letter, or zero-limit inputs return an empty vector.
#[must_use]
pub fn code_word_completions(prefix: &str, limit: usize) -> Vec<&'static str> {
    if limit == 0 {
        return Vec::new();
    }
    let normalized = prefix.trim().to_lowercase();
    if normalized.is_empty() || normalized.chars().any(|c| !c.is_ascii_lowercase()) {
        return Vec::new();
    }
    (0..2048u16)
        .filter_map(totaldrop_proto::english_word)
        .filter(|word| word.starts_with(&normalized))
        .take(limit)
        .collect()
}

fn starts_with_ascii_ignore_case(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn has_activation_scheme_prefix(trimmed: &str) -> bool {
    starts_with_ascii_ignore_case(trimmed, "totaldrop:")
        || starts_with_ascii_ignore_case(trimmed, "https://")
        || starts_with_ascii_ignore_case(trimmed, "http://")
}

/// Returns `true` when `raw` starts with a recognized activation URI scheme
/// (`totaldrop:`, `https://`, or `http://`, ASCII case-insensitive) after
/// stripping invisible Unicode format characters and outer whitespace.
pub(crate) fn looks_like_activation_uri(raw: &str) -> bool {
    let stripped = totaldrop_proto::strip_invisible_format(raw);
    has_activation_scheme_prefix(stripped.trim())
}

/// Strips invisible Unicode format characters and outer whitespace, then
/// normalizes the ASCII casing of known TotalDrop URI scheme/host prefixes
/// (`totaldrop://r/`, `totaldrop:`, `https://totaldrop.app/r#`,
/// `http://totaldrop.app/r#`) before delegating to `TransferCode::from_link`.
fn normalize_activation_prefix(raw: &str) -> String {
    let stripped = totaldrop_proto::strip_invisible_format(raw);
    let trimmed = stripped.trim();

    if let Some(rest) = strip_ascii_prefix_ignore_case(trimmed, "https://totaldrop.app")
        && let Some(after_r) = rest.strip_prefix("/r#")
    {
        return format!("https://totaldrop.app/r#{after_r}");
    }
    if let Some(rest) = strip_ascii_prefix_ignore_case(trimmed, "http://totaldrop.app")
        && let Some(after_r) = rest.strip_prefix("/r#")
    {
        return format!("http://totaldrop.app/r#{after_r}");
    }
    if let Some(rest) = strip_ascii_prefix_ignore_case(trimmed, "totaldrop://r/") {
        return format!("totaldrop://r/{rest}");
    }
    if let Some(rest) = strip_ascii_prefix_ignore_case(trimmed, "totaldrop:") {
        return format!("totaldrop:{rest}");
    }

    trimmed.to_owned()
}

fn strip_ascii_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        text.get(prefix.len()..)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier5_activation_uri_normalizes_ascii_scheme_and_host_casing() {
        let valid_cases = [
            "TOTALDROP://r/7-harbor-rocket",
            "TOTALDROP://R/7-harbor-rocket",
            "TotalDrop:7-harbor-rocket",
            "HTTPS://TOTALDROP.APP/r#7-harbor-rocket",
            "HTTP://TOTALDROP.APP/r#7-harbor-rocket",
            "\u{2068}TOTALDROP://r/7-harbor-rocket\u{2069}",
            "  \u{2068}HTTP://TotalDrop.App/r#7-harbor-rocket\u{2069}  ",
        ];
        for raw in valid_cases {
            let from_uri = ValidatedCode::from_activation_uri(raw);
            assert!(
                from_uri.is_ok(),
                "from_activation_uri rejected valid cased URI {raw:?}: {from_uri:?}"
            );
            assert_eq!(
                from_uri.as_ref().map(|c| c.display_english.as_str()),
                Ok("7-harbor-rocket")
            );

            let from_user = ValidatedCode::from_user_input(raw);
            assert!(
                from_user.is_ok(),
                "from_user_input rejected valid cased URI {raw:?}: {from_user:?}"
            );
            assert_eq!(
                from_user.as_ref().map(|c| c.display_english.as_str()),
                Ok("7-harbor-rocket")
            );
        }

        // Uppercase scheme with invalid payload must report InvalidActivationLink (not BadNameplate).
        assert_eq!(
            ValidatedCode::from_user_input("TOTALDROP://r/not-valid"),
            Err(UriValidationError::InvalidActivationLink)
        );
        assert_eq!(
            ValidatedCode::from_activation_uri("TOTALDROP://r/not-valid"),
            Err(UriValidationError::InvalidActivationLink)
        );
        // Untrusted host or wrong case path `/R#` remains rejected.
        assert_eq!(
            ValidatedCode::from_activation_uri("HTTPS://EVIL.EXAMPLE/r#7-harbor-rocket"),
            Err(UriValidationError::InvalidActivationLink)
        );
        assert_eq!(
            ValidatedCode::from_activation_uri("HTTPS://TOTALDROP.APP/R#7-harbor-rocket"),
            Err(UriValidationError::InvalidActivationLink)
        );

        // Clipboard extraction also handles uppercase scheme/host links.
        let clip = ValidatedCode::from_clipboard_text(
            "Download via HTTP://TOTALDROP.APP/r#7-harbor-rocket now.",
        );
        assert_eq!(
            clip.as_ref().map(|c| c.display_english.as_str()),
            Ok("7-harbor-rocket")
        );
    }
}
