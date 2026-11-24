// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Windows 11 localization bridge over [`totaldrop_l10n`] (ADR 0008, ADR 0016,
//! and `#483`).
//!
//! Provides:
//! - Language negotiation across all **35 supported TotalDrop languages** (plus
//!   `en-XA` and `ar-XB` layout pseudo-locales) from Windows
//!   `GlobalizationPreferences.Languages`.
//! - Localized Windows 11 File Explorer **"Send with TotalDrop"**
//!   (`desktopSendWith`) context-menu verb titles across all 35 languages.
//! - Regional transfer percentage rounding and formatting matching `#483`:
//!   percentages round **down** (`999,999 / 1,000,000` -> `99%`, never `100%`
//!   until finished), follow the user's **Windows region** (`"%50"` in a
//!   Turkish region, `"50 %"` in a German one, `"50%"` in an US English one),
//!   and expose the exact same integer to Windows Narrator's UI Automation
//!   `RangeValuePattern`.
//! - Bidirectional text safety (`FlowDirection`, `U+2068`…`U+2069` FSI/PDI
//!   isolation, left-to-right English lock for transfer codes and verification
//!   words, and `reveal_controls` against `U+202E` extension-spoofing).

use icu_locale::{Locale, LocaleExpander};
use serde::{Deserialize, Serialize};
use totaldrop_l10n::{Arg, Domain, PSEUDO, Strings};

/// Maximum characters of an incoming plain-text transfer rendered directly in
/// a WinUI 3 `TextBlock` (`16 Ki` characters, matching `#326`); copying still
/// copies the complete verified UTF-8 text.
pub const MAX_SHOWN_TEXT_CHARS: usize = 16 * 1024;

/// First Strong Isolate (`U+2068`).
pub const BIDI_FSI: char = '\u{2068}';

/// Pop Directional Isolate (`U+2069`).
pub const BIDI_PDI: char = '\u{2069}';

/// All 35 canonical user-facing languages supported by TotalDrop (ADR 0008).
///
/// Note that `l10n/app/` contains 37 ARB files because `pt` and `zh` serve as
/// base fallback layers alongside `pt-BR`/`pt-PT` and `zh-Hans`/`zh-Hant`.
pub const SUPPORTED_LANGUAGES: [&str; 35] = [
    "ar", "bn", "cs", "da", "de", "el", "en", "es", "fa", "fi", "fr", "he", "hi", "hu", "id", "it",
    "ja", "ko", "ms", "nb", "nl", "pl", "pt-BR", "pt-PT", "ro", "ru", "sv", "sw", "th", "tr", "uk",
    "ur", "vi", "zh-Hans", "zh-Hant",
];

/// Layout flow direction mapped directly to `Microsoft.UI.Xaml.FlowDirection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WinUiFlowDirection {
    /// Standard left-to-right layout (`FlowDirection.LeftToRight`).
    LeftToRight,
    /// Mirrored right-to-left layout (`FlowDirection.RightToLeft`) for Arabic,
    /// Persian, Hebrew, Urdu, and `ar-XB`. The TotalDrop mark (`Kose`),
    /// transfer codes, and verification words explicitly stay `LeftToRight`.
    RightToLeft,
}

impl WinUiFlowDirection {
    /// Returns `true` when the window layout mirrors right-to-left.
    #[must_use]
    pub const fn is_rtl(self) -> bool {
        matches!(self, Self::RightToLeft)
    }
}

/// Localized entry for the Windows 11 File Explorer right-click verb
/// (`IExplorerCommand::GetTitle`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplorerVerbEntry {
    /// Canonical BCP 47 language tag (`"en"`, `"tr"`, `"zh-Hant"`, …).
    pub language_tag: String,
    /// Localized `"Send with TotalDrop"` menu caption (`desktopSendWith`).
    pub title: String,
    /// Reading direction of `title`.
    pub flow_direction: WinUiFlowDirection,
}

/// Rounded-down transfer progress percentage formatted for the user's Windows
/// regional format (`#483`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionalPercent {
    /// Whole percentage in `0..=100`, rounded **down** (`floor(done * 100 / total)`),
    /// so `100` exclusively means all bytes have arrived.
    pub whole: u8,
    /// Region-formatted string (`"50%"`, `"%50"`, `"50 %"`, `"50\u{00A0}%"`, …).
    pub formatted: String,
}

/// Sanitized representation of a plain-text message received from another
/// device (`#313`, `#326`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedPeerText {
    /// Text safe to display in WinUI 3 (hidden control/bidi characters named as
    /// `<U+XXXX>` and capped at [`MAX_SHOWN_TEXT_CHARS`] characters).
    pub display_text: String,
    /// `true` when the message exceeded [`MAX_SHOWN_TEXT_CHARS`] and was
    /// shortened on screen (`receiveTextShortened`).
    pub shortened: bool,
    /// `true` when invisible control or directional characters were revealed
    /// (`receiveTextHidden`).
    pub has_hidden_controls: bool,
}

/// Snapshot of localized WinUI 3 shell labels for `MainWindow`, `SendPage`,
/// `ReceivePage`, and Windows Narrator `AutomationProperties`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsUiBundle {
    /// Resolved BCP 47 display language tag (`"en"`, `"tr"`, `"pt-BR"`, …).
    pub language_tag: String,
    /// Regional formatting locale tag (`"tr-TR"`, `"de-DE"`, …).
    pub region_tag: String,
    /// Window `FlowDirection`.
    pub flow_direction: WinUiFlowDirection,
    /// Whether any string in this language layer comes from an unreviewed draft
    /// (`draftTranslation` banner in Settings).
    pub has_draft_translations: bool,
    /// Explorer context-menu verb (`"Send with TotalDrop"`).
    pub explorer_send_with: String,
    /// Tagline under the brand mark (`appTagline`).
    pub app_tagline: String,
    /// Navigation item & heading for Send (`sendTitle`).
    pub send_title: String,
    /// Add files button (`sendAddFiles`).
    pub send_add_files: String,
    /// Drag-and-drop card heading (`sendDropHere`).
    pub send_drop_here: String,
    /// Drag-and-drop card subtitle (`sendDropHint`).
    pub send_drop_hint: String,
    /// Stronger 3-word code toggle label (`sendStrongCode`).
    pub send_strong_code: String,
    /// Stronger 3-word code explanation (`sendStrongCodeHint`).
    pub send_strong_code_hint: String,
    /// Primary action button to allocate a code (`sendCreateCode`).
    pub send_create_code: String,
    /// Heading above generated code (`sendYourCode`).
    pub send_your_code: String,
    /// Copy code button (`sendCopy`).
    pub send_copy: String,
    /// Share code button (`sendShare`).
    pub send_share: String,
    /// Navigation item & heading for Receive (`receiveTitle`).
    pub receive_title: String,
    /// Transfer code input label (`receiveCodeLabel`).
    pub receive_code_label: String,
    /// Example placeholder (`receiveCodeHint`, always LTR English).
    pub receive_code_hint: String,
    /// Paste code button (`receivePaste`).
    pub receive_paste: String,
    /// Connect button (`receiveConnect`).
    pub receive_connect: String,
    /// Safety-critical accept button (`receiveAccept`, English until reviewed).
    pub receive_accept: String,
    /// Safety-critical decline button (`receiveDecline`, English until reviewed).
    pub receive_decline: String,
    /// Safety-critical verification words title (`verificationTitle`).
    pub verification_title: String,
    /// Safety-critical verification words hint (`verificationHint`).
    pub verification_hint: String,
    /// Settings navigation label (`settings`).
    pub settings_title: String,
    /// Cancel button (`cancel`).
    pub cancel: String,
    /// Power-request reason string (`keepAwakeReason`).
    pub keep_awake_reason: String,
    /// Formatted version label (`settingsVersion`).
    pub version_label: String,
    /// App generic description (`desktopGenericName`).
    pub desktop_generic_name: String,
    /// Home send card title (`homeSendTitle`).
    pub home_send_title: String,
    /// Home send card body (`homeSendBody`).
    pub home_send_body: String,
    /// Home receive card title (`homeReceiveTitle`).
    pub home_receive_title: String,
    /// Home receive card body (`homeReceiveBody`).
    pub home_receive_body: String,
    /// Home privacy footer (`homeFooter`).
    pub home_footer: String,
    /// Relay/network note (`sameNetworkNote`).
    pub same_network_note: String,
    /// Done button (`done`).
    pub done: String,
    /// Try again button (`tryAgain`).
    pub try_again: String,
    /// Back button (`back`).
    pub back: String,
    /// Stop button (`stop`).
    pub stop: String,
    /// Keep going button (`keepGoing`).
    pub keep_going: String,
    /// Expandable details toggle (`moreInfo`).
    pub more_info: String,
    /// Open destination folder button (`openFolder`).
    pub open_folder: String,
    /// Cancel confirmation dialog title (`cancelTransferTitle`).
    pub cancel_transfer_title: String,
    /// Cancel confirmation dialog body (`cancelTransferBody`).
    pub cancel_transfer_body: String,
    /// Technical English message caption (`technicalDetail`).
    pub technical_detail: String,
    /// Empty selection heading (`sendEmpty`).
    pub send_empty: String,
    /// Empty selection hint (`sendEmptyHint`).
    pub send_empty_hint: String,
    /// Counting selected files caption (`sendCounting`).
    pub send_counting: String,
    /// Remove item button (`sendRemove`).
    pub send_remove: String,
    /// Preparing transfer status (`sendPreparing`).
    pub send_preparing: String,
    /// Failed to add files error (`sendAddFailed`).
    pub send_add_failed: String,
    /// Transfer code sharing instructions (`sendCodeHint`).
    pub send_code_hint: String,
    /// Waiting for receiver caption (`sendWaiting`).
    pub send_waiting: String,
    /// Waiting for receiver to accept caption (`sendWaitingAccept`).
    pub send_waiting_accept: String,
    /// Copied code feedback (`sendCopied`).
    pub send_copied: String,
    /// Active send progress label (`sendSending`).
    pub send_sending: String,
    /// Send complete heading (`sendDone`).
    pub send_done: String,
    /// File/folder picker title (`pickTitle`).
    pub pick_title: String,
    /// Send text mode title/button (`sendText`).
    pub send_text: String,
    /// Send text box placeholder (`sendTextHint`).
    pub send_text_hint: String,
    /// Text sent confirmation (`sendTextDone`).
    pub send_text_done: String,
    /// Long outgoing text preview notice (`sendTextShortened`).
    pub send_text_shortened: String,
    /// Outgoing text hidden-characters notice (`sendTextHidden`).
    pub send_text_hidden: String,
    /// Send clipboard action (`sendClipboard`).
    pub send_clipboard: String,
    /// Clipboard empty notice (`sendClipboardEmpty`).
    pub send_clipboard_empty: String,
    /// Existing text kept notice (`sendClipboardKept`).
    pub send_clipboard_kept: String,
    /// Receive code helper text (`receiveCodeHelp`).
    pub receive_code_help: String,
    /// Invalid typed code hint (`receiveCodeInvalid`).
    pub receive_code_invalid: String,
    /// Connecting status (`receiveConnecting`).
    pub receive_connecting: String,
    /// Incoming files offer title (`receiveOffer`).
    pub receive_offer: String,
    /// Incoming text offer title (`receiveOfferText`).
    pub receive_offer_text: String,
    /// In-memory received text note (`receiveOfferTextNote`).
    pub receive_offer_text_note: String,
    /// Files declined confirmation (`receiveDeclined`).
    pub receive_declined: String,
    /// Text declined confirmation (`receiveTextDeclined`).
    pub receive_text_declined: String,
    /// Active receive progress label (`receiveReceiving`).
    pub receive_receiving: String,
    /// Receive complete heading (`receiveDone`).
    pub receive_done: String,
    /// Receive text complete heading (`receiveTextDone`).
    pub receive_text_done: String,
    /// Long received text preview notice (`receiveTextShortened`).
    pub receive_text_shortened: String,
    /// Received text hidden-characters notice (`receiveTextHidden`).
    pub receive_text_hidden: String,
    /// Copy received text button (`copyText`).
    pub copy_text: String,
    /// Received text copied feedback (`textCopied`).
    pub text_copied: String,
    /// Autocomplete suggestions label (`codeSuggestions`).
    pub code_suggestions: String,
    /// Settings server heading (`settingsServer`).
    pub settings_server: String,
    /// Settings server help (`settingsServerHelp`).
    pub settings_server_help: String,
    /// Settings server reset button (`settingsServerReset`).
    pub settings_server_reset: String,
    /// Settings invalid server hint (`settingsServerInvalid`).
    pub settings_server_invalid: String,
    /// Settings save button (`settingsSave`).
    pub settings_save: String,
    /// Settings about heading (`settingsAbout`).
    pub settings_about: String,
    /// Settings about body (`settingsAboutBody`).
    pub settings_about_body: String,
    /// Settings privacy heading (`settingsPrivacy`).
    pub settings_privacy: String,
    /// Settings privacy body (`settingsPrivacyBody`).
    pub settings_privacy_body: String,
    /// Privacy mode toggle label (`privacyMode`).
    pub privacy_mode: String,
    /// Privacy mode explanation (`privacyModeHint`).
    pub privacy_mode_hint: String,
    /// Privacy mode dialog title (`privacyModeConfirmTitle`).
    pub privacy_mode_confirm_title: String,
    /// Privacy mode dialog body (`privacyModeConfirmBody`).
    pub privacy_mode_confirm_body: String,
    /// Privacy mode confirm button (`privacyModeTurnOn`).
    pub privacy_mode_turn_on: String,
    /// Draft translation notice (`draftTranslation`).
    pub draft_translation: String,
    /// English wordlist explanation (`settingsWordsEnglish`).
    pub settings_words_english: String,
    /// Invalid activation link/code error (`errorInvalidCode`).
    pub error_invalid_code: String,
    /// Safety-critical wrong code error (`errorWrongCode`, English until reviewed).
    pub error_wrong_code: String,
    /// Safety-critical invalid offer error (`errorInvalidOffer`, English until reviewed).
    pub error_invalid_offer: String,
    /// Damaged incoming text error (`errorTextDamaged`).
    pub error_text_damaged: String,
    /// Invalid server URL error (`errorBadServer`).
    pub error_bad_server: String,
    /// Expired sender code error (`errorCodeExpired`).
    pub error_code_expired: String,
    /// Unknown/used receiver code error (`errorCodeNotInUse`).
    pub error_code_not_in_use: String,
    /// Generic fallback error (`errorOther`).
    pub error_other: String,
    /// Busy window share notice (`shareBusy`).
    pub share_busy: String,
    /// Busy window link notice (`linkBusy`).
    pub link_busy: String,
}

/// Computes the whole transfer percentage in `0..=100`, rounding **down** so
/// `100` is never reported while the last bytes are still in flight (`#483`).
///
/// Returns `0` when `total == 0`.
#[must_use]
pub fn whole_percent(done: u64, total: u64) -> u8 {
    if total == 0 {
        return 0;
    }
    if done >= total {
        return 100;
    }
    let scaled = u128::from(done)
        .saturating_mul(100)
        .checked_div(u128::from(total))
        .unwrap_or(0);
    // Because `done < total` strictly, `scaled` is guaranteed to be in `0..=99`,
    // and we still clamp defensively to `99`.
    u8::try_from(scaled.min(99)).unwrap_or(99)
}

/// Resolves the language whose `progressPercent` placement matches a Windows
/// regional locale (`region_tag`), so a device set to English display language
/// with a Turkish region (`en-TR` or `tr-TR`) writes `"%50"`, and one with a
/// German region (`en-DE` or `de-DE`) writes `"50 %"` (`#483`, ADR 0008).
fn regional_percent_pattern_locale(numeric_locale: &Locale) -> Locale {
    if let Some(region) = numeric_locale.id.region {
        let und_region = format!("und-{region}");
        if let Ok(mut candidate) = Locale::try_from_str(&und_region) {
            LocaleExpander::new_common().maximize(&mut candidate.id);
            if !candidate.id.language.is_unknown() {
                return candidate;
            }
        }
    }
    numeric_locale.clone()
}

/// Formats `done` of `total` bytes as a rounded-down regional percentage string
/// (`#483`).
///
/// Both [`RegionalPercent::whole`] (bound to `ProgressBar.Value` for Windows
/// Narrator) and [`RegionalPercent::formatted`] derive from [`whole_percent`].
#[must_use]
pub fn format_regional_percent(done: u64, total: u64, region_tag: &str) -> RegionalPercent {
    let whole = whole_percent(done, total);
    let numeric_locale = totaldrop_l10n::locale::parse(region_tag)
        .or_else(|| totaldrop_l10n::locale::parse("en-US"))
        .unwrap_or(Locale::UNKNOWN);
    let pattern_locale = regional_percent_pattern_locale(&numeric_locale);
    let regional_strings = Strings::new(Domain::App, &[pattern_locale], Some(&numeric_locale));
    let formatted = regional_strings.get(
        "progressPercent",
        &[("percent", Arg::Count(u64::from(whole)))],
    );
    RegionalPercent { whole, formatted }
}

/// Wraps `value` in Unicode First Strong Isolate (`U+2068`) and Pop Directional
/// Isolate (`U+2069`) so embedded filenames, folder paths, or version numbers
/// never reorder surrounding right-to-left sentences (ADR 0008).
#[must_use]
pub fn isolate_bidi(value: &str) -> String {
    format!("{BIDI_FSI}{value}{BIDI_PDI}")
}

/// Sanitizes an untrusted filename or directory name received from a peer:
/// reveals invisible/bidirectional control characters (`U+202E` -> `<U+202E>`)
/// to defeat extension spoofing (`invoice\u{202E}fdp.exe`) and isolates its
/// reading direction.
#[must_use]
pub fn sanitize_peer_filename(name: &str) -> String {
    let revealed = totaldrop_l10n::reveal_controls(name);
    isolate_bidi(&revealed)
}

/// Sanitizes an incoming plain-text transfer for safe WinUI 3 display (`#313`,
/// `#326`), naming hidden control/bidi code points and capping screen layout at
/// [`MAX_SHOWN_TEXT_CHARS`] characters.
#[must_use]
pub fn sanitize_peer_text(text: &str) -> SanitizedPeerText {
    let revealed = totaldrop_l10n::reveal_text(text);
    let normalized_crlf = text.replace("\r\n", "\n");
    let has_hidden_controls = revealed != normalized_crlf;
    let mut display_text = String::new();
    let mut shortened = false;
    for (idx, ch) in revealed.chars().enumerate() {
        if idx >= MAX_SHOWN_TEXT_CHARS {
            shortened = true;
            break;
        }
        display_text.push(ch);
    }
    SanitizedPeerText {
        display_text,
        shortened,
        has_hidden_controls,
    }
}

/// Looks up the localized **"Send with TotalDrop"** (`desktopSendWith`) verb
/// caption for Windows 11 File Explorer given an ordered list of user display
/// language tags (`GlobalizationPreferences.Languages`).
#[must_use]
pub fn explorer_send_verb<I, S>(preferred_tags: I) -> ExplorerVerbEntry
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let localizer = WindowsLocalizer::new(preferred_tags, None);
    localizer.explorer_verb()
}

/// Generates the complete 35-language catalog of Windows 11 File Explorer
/// **"Send with TotalDrop"** (`desktopSendWith`) verbs across
/// [`SUPPORTED_LANGUAGES`].
///
/// Used both at build time to populate MSIX `.resw` string tables and at
/// runtime by `IExplorerCommand::GetTitle`.
#[must_use]
pub fn explorer_verb_catalog() -> Vec<ExplorerVerbEntry> {
    SUPPORTED_LANGUAGES
        .iter()
        .map(|&tag| explorer_send_verb([tag]))
        .collect()
}

/// Stateful Windows 11 localization and regional-formatting context bound to
/// the user's preferred display languages and regional format.
#[derive(Debug)]
pub struct WindowsLocalizer {
    strings: Strings,
    region_tag: String,
}

impl WindowsLocalizer {
    /// Creates a [`WindowsLocalizer`] from Windows' ordered preferred UI
    /// languages (`preferred_languages`, e.g. `["zh-HK", "en-US"]`) and optional
    /// regional format tag (`region_tag`, e.g. `Some("de-DE")`).
    #[must_use]
    pub fn new<I, S>(preferred_languages: I, region_tag: Option<&str>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let raw_tags: Vec<String> = preferred_languages
            .into_iter()
            .map(|s| s.as_ref().trim().replace('_', "-"))
            .filter(|s| !s.is_empty())
            .collect();

        let numeric_locale = region_tag
            .and_then(totaldrop_l10n::locale::parse)
            .or_else(|| {
                raw_tags
                    .first()
                    .and_then(|first| totaldrop_l10n::locale::parse(first))
            });

        // Preserve pseudo-locales `en-XA` and `ar-XB` when requested first.
        let locales: Vec<Locale> = if let Some(first) = raw_tags.first()
            && PSEUDO.contains(&first.as_str())
        {
            Locale::try_from_str(first).into_iter().collect()
        } else {
            raw_tags
                .iter()
                .filter_map(|t| totaldrop_l10n::locale::parse(t))
                .collect()
        };

        let strings = Strings::new(Domain::App, &locales, numeric_locale.as_ref());
        let resolved_region = region_tag
            .map(|r| r.trim().replace('_', "-"))
            .filter(|r| !r.is_empty())
            .or_else(|| raw_tags.first().cloned())
            .unwrap_or_else(|| strings.tag().to_owned());

        Self {
            strings,
            region_tag: resolved_region,
        }
    }

    /// Negotiated BCP 47 language tag (`"en"`, `"tr"`, `"zh-Hant"`, …).
    #[must_use]
    pub fn language_tag(&self) -> &str {
        self.strings.tag()
    }

    /// Active regional formatting tag (`"tr-TR"`, `"de-DE"`, …).
    #[must_use]
    pub fn region_tag(&self) -> &str {
        &self.region_tag
    }

    /// Window reading order (`LeftToRight` or `RightToLeft`).
    #[must_use]
    pub fn flow_direction(&self) -> WinUiFlowDirection {
        if self.strings.is_rtl() {
            WinUiFlowDirection::RightToLeft
        } else {
            WinUiFlowDirection::LeftToRight
        }
    }

    /// Whether any string in this language layer comes from an unreviewed draft.
    #[must_use]
    pub fn has_drafts(&self) -> bool {
        self.strings.is_draft()
    }

    /// Whether `key` is a safety-critical message that must remain in English
    /// until its translation in [`Self::language_tag`] is reviewed by a human
    /// (ADR 0008).
    #[must_use]
    pub fn needs_english(&self, key: &str) -> bool {
        totaldrop_l10n::needs_english(self.strings.tag(), key)
    }

    /// Returns `true` when `key` is a known `l10n/app` message identifier.
    #[must_use]
    pub fn has_key(&self, key: &str) -> bool {
        !key.is_empty() && self.strings.keys().contains(key)
    }

    /// Formats a simple message key without placeholders.
    #[must_use]
    pub fn text(&self, key: &str) -> String {
        self.strings.get(key, &[])
    }

    /// Formats a known `l10n/app` message key with ICU plural/select/text
    /// arguments while enforcing `l10n/status.json`'s 11-key critical security
    /// English gate. Returns `None` if `key` is empty or unknown.
    #[must_use]
    pub fn format_message(&self, key: &str, args: &[(&str, Arg<'_>)]) -> Option<String> {
        if !self.has_key(key) {
            return None;
        }
        Some(self.strings.get(key, args))
    }

    /// Formats a byte count using TotalDrop's regional SI unit rules (`"0 B"`,
    /// `"1.5 MB"`, `"1,5 MB"`).
    #[must_use]
    pub fn format_bytes(&self, bytes: u64) -> String {
        self.strings.bytes(bytes)
    }

    /// Formats a transfer progress ratio (`done` of `total` bytes) using
    /// regional percent placement and floor rounding (`#483`).
    #[must_use]
    pub fn format_percent(&self, done: u64, total: u64) -> RegionalPercent {
        format_regional_percent(done, total, &self.region_tag)
    }

    /// Formats the localized share sentence (`sendShareText`) with the transfer
    /// code isolated left-to-right when the sentence is right-to-left.
    #[must_use]
    pub fn format_share_text(&self, english_code: &str) -> String {
        self.strings
            .get("sendShareText", &[("code", Arg::Text(english_code))])
    }

    /// Formats the Explorer context-menu verb (`"Send with TotalDrop"`).
    #[must_use]
    pub fn explorer_verb(&self) -> ExplorerVerbEntry {
        ExplorerVerbEntry {
            language_tag: self.strings.tag().to_owned(),
            title: self.strings.get("desktopSendWith", &[]),
            flow_direction: self.flow_direction(),
        }
    }

    /// Builds a complete [`WindowsUiBundle`] snapshot for WinUI 3 data binding.
    #[must_use]
    pub fn ui_bundle(&self, app_version: &str) -> WindowsUiBundle {
        let t = |key: &str| self.strings.get(key, &[]);
        let version_label = self
            .strings
            .get("settingsVersion", &[("version", Arg::Text(app_version))]);
        WindowsUiBundle {
            language_tag: self.strings.tag().to_owned(),
            region_tag: self.region_tag.clone(),
            flow_direction: self.flow_direction(),
            has_draft_translations: self.strings.is_draft(),
            explorer_send_with: t("desktopSendWith"),
            app_tagline: t("appTagline"),
            send_title: t("sendTitle"),
            send_add_files: t("sendAddFiles"),
            send_drop_here: t("sendDropHere"),
            send_drop_hint: t("sendDropHint"),
            send_strong_code: t("sendStrongCode"),
            send_strong_code_hint: t("sendStrongCodeHint"),
            send_create_code: t("sendCreateCode"),
            send_your_code: t("sendYourCode"),
            send_copy: t("sendCopy"),
            send_share: t("sendShare"),
            receive_title: t("receiveTitle"),
            receive_code_label: t("receiveCodeLabel"),
            receive_code_hint: "7-harbor-rocket".to_owned(),
            receive_paste: t("receivePaste"),
            receive_connect: t("receiveConnect"),
            receive_accept: t("receiveAccept"),
            receive_decline: t("receiveDecline"),
            verification_title: t("verificationTitle"),
            verification_hint: t("verificationHint"),
            settings_title: t("settings"),
            cancel: t("cancel"),
            keep_awake_reason: t("keepAwakeReason"),
            version_label,
            desktop_generic_name: t("desktopGenericName"),
            home_send_title: t("homeSendTitle"),
            home_send_body: t("homeSendBody"),
            home_receive_title: t("homeReceiveTitle"),
            home_receive_body: t("homeReceiveBody"),
            home_footer: t("homeFooter"),
            same_network_note: t("sameNetworkNote"),
            done: t("done"),
            try_again: t("tryAgain"),
            back: t("back"),
            stop: t("stop"),
            keep_going: t("keepGoing"),
            more_info: t("moreInfo"),
            open_folder: t("openFolder"),
            cancel_transfer_title: t("cancelTransferTitle"),
            cancel_transfer_body: t("cancelTransferBody"),
            technical_detail: t("technicalDetail"),
            send_empty: t("sendEmpty"),
            send_empty_hint: t("sendEmptyHint"),
            send_counting: t("sendCounting"),
            send_remove: t("sendRemove"),
            send_preparing: t("sendPreparing"),
            send_add_failed: t("sendAddFailed"),
            send_code_hint: t("sendCodeHint"),
            send_waiting: t("sendWaiting"),
            send_waiting_accept: t("sendWaitingAccept"),
            send_copied: t("sendCopied"),
            send_sending: t("sendSending"),
            send_done: t("sendDone"),
            pick_title: t("pickTitle"),
            send_text: t("sendText"),
            send_text_hint: t("sendTextHint"),
            send_text_done: t("sendTextDone"),
            send_text_shortened: t("sendTextShortened"),
            send_text_hidden: t("sendTextHidden"),
            send_clipboard: t("sendClipboard"),
            send_clipboard_empty: t("sendClipboardEmpty"),
            send_clipboard_kept: t("sendClipboardKept"),
            receive_code_help: t("receiveCodeHelp"),
            receive_code_invalid: t("receiveCodeInvalid"),
            receive_connecting: t("receiveConnecting"),
            receive_offer: t("receiveOffer"),
            receive_offer_text: t("receiveOfferText"),
            receive_offer_text_note: t("receiveOfferTextNote"),
            receive_declined: t("receiveDeclined"),
            receive_text_declined: t("receiveTextDeclined"),
            receive_receiving: t("receiveReceiving"),
            receive_done: t("receiveDone"),
            receive_text_done: t("receiveTextDone"),
            receive_text_shortened: t("receiveTextShortened"),
            receive_text_hidden: t("receiveTextHidden"),
            copy_text: t("copyText"),
            text_copied: t("textCopied"),
            code_suggestions: t("codeSuggestions"),
            settings_server: t("settingsServer"),
            settings_server_help: t("settingsServerHelp"),
            settings_server_reset: t("settingsServerReset"),
            settings_server_invalid: t("settingsServerInvalid"),
            settings_save: t("settingsSave"),
            settings_about: t("settingsAbout"),
            settings_about_body: t("settingsAboutBody"),
            settings_privacy: t("settingsPrivacy"),
            settings_privacy_body: t("settingsPrivacyBody"),
            privacy_mode: t("privacyMode"),
            privacy_mode_hint: t("privacyModeHint"),
            privacy_mode_confirm_title: t("privacyModeConfirmTitle"),
            privacy_mode_confirm_body: t("privacyModeConfirmBody"),
            privacy_mode_turn_on: t("privacyModeTurnOn"),
            draft_translation: t("draftTranslation"),
            settings_words_english: t("settingsWordsEnglish"),
            error_invalid_code: t("errorInvalidCode"),
            error_wrong_code: t("errorWrongCode"),
            error_invalid_offer: t("errorInvalidOffer"),
            error_text_damaged: t("errorTextDamaged"),
            error_bad_server: t("errorBadServer"),
            error_code_expired: t("errorCodeExpired"),
            error_code_not_in_use: t("errorCodeNotInUse"),
            error_other: t("errorOther"),
            share_busy: t("shareBusy"),
            link_busy: t("linkBusy"),
        }
    }
}
