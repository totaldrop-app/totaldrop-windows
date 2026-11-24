// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.UI.Xaml;
using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.Services;
using WinRT;

namespace TotalDrop.WinUI.ViewModels;

/// <summary>
/// Trim-safe <see cref="INotifyPropertyChanged"/> base for <c>x:Bind</c> under
/// .NET 10 Native AOT + CsWinRT (zero runtime reflection).
/// </summary>
public abstract class ObservableViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }

    protected void NotifyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

/// <summary>
/// Reactive 35-language UI string bundle hydrated strictly from Rust
/// <c>totaldrop_win_ui_bundle_json</c> (ADR 0008, ADR 0016). Zero hardcoded
/// English UI copy exists in C# or XAML.
/// </summary>
[GeneratedBindableCustomProperty]
public sealed partial class UiStringsViewModel : ObservableViewModel, INotificationLocalizer
{
    private string _languageTag = string.Empty;
    private string _regionTag = string.Empty;
    private string _flowDirection = "LeftToRight";
    private bool _hasDraftTranslations;
    private string _explorerSendWith = string.Empty;
    private string _appTagline = string.Empty;
    private string _sendTitle = string.Empty;
    private string _sendAddFiles = string.Empty;
    private string _sendDropHere = string.Empty;
    private string _sendDropHint = string.Empty;
    private string _sendStrongCode = string.Empty;
    private string _sendStrongCodeHint = string.Empty;
    private string _sendCreateCode = string.Empty;
    private string _sendYourCode = string.Empty;
    private string _sendCopy = string.Empty;
    private string _sendShare = string.Empty;
    private string _receiveTitle = string.Empty;
    private string _receiveCodeLabel = string.Empty;
    private string _receiveCodeHint = "7-harbor-rocket";
    private string _receivePaste = string.Empty;
    private string _receiveConnect = string.Empty;
    private string _receiveAccept = string.Empty;
    private string _receiveDecline = string.Empty;
    private string _verificationTitle = string.Empty;
    private string _verificationHint = string.Empty;
    private string _settingsTitle = string.Empty;
    private string _cancel = string.Empty;
    private string _keepAwakeReason = string.Empty;
    private string _versionLabel = string.Empty;
    private string _desktopGenericName = string.Empty;
    private string _homeSendTitle = string.Empty;
    private string _homeSendBody = string.Empty;
    private string _homeReceiveTitle = string.Empty;
    private string _homeReceiveBody = string.Empty;
    private string _homeFooter = string.Empty;
    private string _sameNetworkNote = string.Empty;
    private string _done = string.Empty;
    private string _tryAgain = string.Empty;
    private string _back = string.Empty;
    private string _stop = string.Empty;
    private string _keepGoing = string.Empty;
    private string _moreInfo = string.Empty;
    private string _openFolder = string.Empty;
    private string _cancelTransferTitle = string.Empty;
    private string _cancelTransferBody = string.Empty;
    private string _technicalDetail = string.Empty;
    private string _sendEmpty = string.Empty;
    private string _sendEmptyHint = string.Empty;
    private string _sendCounting = string.Empty;
    private string _sendRemove = string.Empty;
    private string _sendPreparing = string.Empty;
    private string _sendAddFailed = string.Empty;
    private string _sendCodeHint = string.Empty;
    private string _sendWaiting = string.Empty;
    private string _sendWaitingAccept = string.Empty;
    private string _sendCopied = string.Empty;
    private string _sendSending = string.Empty;
    private string _sendDone = string.Empty;
    private string _pickTitle = string.Empty;
    private string _sendText = string.Empty;
    private string _sendTextHint = string.Empty;
    private string _sendTextDone = string.Empty;
    private string _sendTextShortened = string.Empty;
    private string _sendTextHidden = string.Empty;
    private string _sendClipboard = string.Empty;
    private string _sendClipboardEmpty = string.Empty;
    private string _sendClipboardKept = string.Empty;
    private string _receiveCodeHelp = string.Empty;
    private string _receiveCodeInvalid = string.Empty;
    private string _receiveConnecting = string.Empty;
    private string _receiveOffer = string.Empty;
    private string _receiveOfferText = string.Empty;
    private string _receiveOfferTextNote = string.Empty;
    private string _receiveDeclined = string.Empty;
    private string _receiveTextDeclined = string.Empty;
    private string _receiveReceiving = string.Empty;
    private string _receiveDone = string.Empty;
    private string _receiveTextDone = string.Empty;
    private string _receiveTextShortened = string.Empty;
    private string _receiveTextHidden = string.Empty;
    private string _copyText = string.Empty;
    private string _textCopied = string.Empty;
    private string _codeSuggestions = string.Empty;
    private string _settingsServer = string.Empty;
    private string _settingsServerHelp = string.Empty;
    private string _settingsServerReset = string.Empty;
    private string _settingsServerInvalid = string.Empty;
    private string _settingsSave = string.Empty;
    private string _settingsAbout = string.Empty;
    private string _settingsAboutBody = string.Empty;
    private string _settingsPrivacy = string.Empty;
    private string _settingsPrivacyBody = string.Empty;
    private string _privacyMode = string.Empty;
    private string _privacyModeHint = string.Empty;
    private string _privacyModeConfirmTitle = string.Empty;
    private string _privacyModeConfirmBody = string.Empty;
    private string _privacyModeTurnOn = string.Empty;
    private string _draftTranslation = string.Empty;
    private string _settingsWordsEnglish = string.Empty;
    private string _errorInvalidCode = string.Empty;
    private string _errorWrongCode = string.Empty;
    private string _errorInvalidOffer = string.Empty;
    private string _errorTextDamaged = string.Empty;
    private string _errorBadServer = string.Empty;
    private string _errorCodeExpired = string.Empty;
    private string _errorCodeNotInUse = string.Empty;
    private string _errorOther = string.Empty;
    private string _shareBusy = string.Empty;
    private string _linkBusy = string.Empty;

    public string PreferredLanguageTags { get; private set; } = string.Empty;

    public string LanguageTag { get => _languageTag; private set => SetField(ref _languageTag, value); }
    public string RegionTag { get => _regionTag; private set => SetField(ref _regionTag, value); }
    public string FlowDirection { get => _flowDirection; private set => SetField(ref _flowDirection, value); }
    public bool HasDraftTranslations { get => _hasDraftTranslations; private set => SetField(ref _hasDraftTranslations, value); }
    public string ExplorerSendWith { get => _explorerSendWith; private set => SetField(ref _explorerSendWith, value); }
    public string AppTagline { get => _appTagline; private set => SetField(ref _appTagline, value); }
    public string SendTitle { get => _sendTitle; private set => SetField(ref _sendTitle, value); }
    public string SendAddFiles { get => _sendAddFiles; private set => SetField(ref _sendAddFiles, value); }
    public string SendDropHere { get => _sendDropHere; private set => SetField(ref _sendDropHere, value); }
    public string SendDropHint { get => _sendDropHint; private set => SetField(ref _sendDropHint, value); }
    public string SendStrongCode { get => _sendStrongCode; private set => SetField(ref _sendStrongCode, value); }
    public string SendStrongCodeHint { get => _sendStrongCodeHint; private set => SetField(ref _sendStrongCodeHint, value); }
    public string SendCreateCode { get => _sendCreateCode; private set => SetField(ref _sendCreateCode, value); }
    public string SendYourCode { get => _sendYourCode; private set => SetField(ref _sendYourCode, value); }
    public string SendCopy { get => _sendCopy; private set => SetField(ref _sendCopy, value); }
    public string SendShare { get => _sendShare; private set => SetField(ref _sendShare, value); }
    public string ReceiveTitle { get => _receiveTitle; private set => SetField(ref _receiveTitle, value); }
    public string ReceiveCodeLabel { get => _receiveCodeLabel; private set => SetField(ref _receiveCodeLabel, value); }
    public string ReceiveCodeHint { get => _receiveCodeHint; private set => SetField(ref _receiveCodeHint, value); }
    public string ReceivePaste { get => _receivePaste; private set => SetField(ref _receivePaste, value); }
    public string ReceiveConnect { get => _receiveConnect; private set => SetField(ref _receiveConnect, value); }
    public string ReceiveAccept { get => _receiveAccept; private set => SetField(ref _receiveAccept, value); }
    public string ReceiveDecline { get => _receiveDecline; private set => SetField(ref _receiveDecline, value); }
    public string VerificationTitle { get => _verificationTitle; private set => SetField(ref _verificationTitle, value); }
    public string VerificationHint { get => _verificationHint; private set => SetField(ref _verificationHint, value); }
    public string SettingsTitle { get => _settingsTitle; private set => SetField(ref _settingsTitle, value); }
    public string Cancel { get => _cancel; private set => SetField(ref _cancel, value); }
    public string KeepAwakeReason { get => _keepAwakeReason; private set => SetField(ref _keepAwakeReason, value); }
    public string VersionLabel { get => _versionLabel; private set => SetField(ref _versionLabel, value); }
    public string DesktopGenericName { get => _desktopGenericName; private set => SetField(ref _desktopGenericName, value); }
    public string HomeSendTitle { get => _homeSendTitle; private set => SetField(ref _homeSendTitle, value); }
    public string HomeSendBody { get => _homeSendBody; private set => SetField(ref _homeSendBody, value); }
    public string HomeReceiveTitle { get => _homeReceiveTitle; private set => SetField(ref _homeReceiveTitle, value); }
    public string HomeReceiveBody { get => _homeReceiveBody; private set => SetField(ref _homeReceiveBody, value); }
    public string HomeFooter { get => _homeFooter; private set => SetField(ref _homeFooter, value); }
    public string SameNetworkNote { get => _sameNetworkNote; private set => SetField(ref _sameNetworkNote, value); }
    public string Done { get => _done; private set => SetField(ref _done, value); }
    public string TryAgain { get => _tryAgain; private set => SetField(ref _tryAgain, value); }
    public string Back { get => _back; private set => SetField(ref _back, value); }
    public string Stop { get => _stop; private set => SetField(ref _stop, value); }
    public string KeepGoing { get => _keepGoing; private set => SetField(ref _keepGoing, value); }
    public string MoreInfo { get => _moreInfo; private set => SetField(ref _moreInfo, value); }
    public string OpenFolder { get => _openFolder; private set => SetField(ref _openFolder, value); }
    public string CancelTransferTitle { get => _cancelTransferTitle; private set => SetField(ref _cancelTransferTitle, value); }
    public string CancelTransferBody { get => _cancelTransferBody; private set => SetField(ref _cancelTransferBody, value); }
    public string TechnicalDetail { get => _technicalDetail; private set => SetField(ref _technicalDetail, value); }
    public string SendEmpty { get => _sendEmpty; private set => SetField(ref _sendEmpty, value); }
    public string SendEmptyHint { get => _sendEmptyHint; private set => SetField(ref _sendEmptyHint, value); }
    public string SendCounting { get => _sendCounting; private set => SetField(ref _sendCounting, value); }
    public string SendRemove { get => _sendRemove; private set => SetField(ref _sendRemove, value); }
    public string SendPreparing { get => _sendPreparing; private set => SetField(ref _sendPreparing, value); }
    public string SendAddFailed { get => _sendAddFailed; private set => SetField(ref _sendAddFailed, value); }
    public string SendCodeHint { get => _sendCodeHint; private set => SetField(ref _sendCodeHint, value); }
    public string SendWaiting { get => _sendWaiting; private set => SetField(ref _sendWaiting, value); }
    public string SendWaitingAccept { get => _sendWaitingAccept; private set => SetField(ref _sendWaitingAccept, value); }
    public string SendCopied { get => _sendCopied; private set => SetField(ref _sendCopied, value); }
    public string SendSending { get => _sendSending; private set => SetField(ref _sendSending, value); }
    public string SendDone { get => _sendDone; private set => SetField(ref _sendDone, value); }
    public string PickTitle { get => _pickTitle; private set => SetField(ref _pickTitle, value); }
    public string SendText { get => _sendText; private set => SetField(ref _sendText, value); }
    public string SendTextHint { get => _sendTextHint; private set => SetField(ref _sendTextHint, value); }
    public string SendTextDone { get => _sendTextDone; private set => SetField(ref _sendTextDone, value); }
    public string SendTextShortened { get => _sendTextShortened; private set => SetField(ref _sendTextShortened, value); }
    public string SendTextHidden { get => _sendTextHidden; private set => SetField(ref _sendTextHidden, value); }
    public string SendClipboard { get => _sendClipboard; private set => SetField(ref _sendClipboard, value); }
    public string SendClipboardEmpty { get => _sendClipboardEmpty; private set => SetField(ref _sendClipboardEmpty, value); }
    public string SendClipboardKept { get => _sendClipboardKept; private set => SetField(ref _sendClipboardKept, value); }
    public string ReceiveCodeHelp { get => _receiveCodeHelp; private set => SetField(ref _receiveCodeHelp, value); }
    public string ReceiveCodeInvalid { get => _receiveCodeInvalid; private set => SetField(ref _receiveCodeInvalid, value); }
    public string ReceiveConnecting { get => _receiveConnecting; private set => SetField(ref _receiveConnecting, value); }
    public string ReceiveOffer { get => _receiveOffer; private set => SetField(ref _receiveOffer, value); }
    public string ReceiveOfferText { get => _receiveOfferText; private set => SetField(ref _receiveOfferText, value); }
    public string ReceiveOfferTextNote { get => _receiveOfferTextNote; private set => SetField(ref _receiveOfferTextNote, value); }
    public string ReceiveDeclined { get => _receiveDeclined; private set => SetField(ref _receiveDeclined, value); }
    public string ReceiveTextDeclined { get => _receiveTextDeclined; private set => SetField(ref _receiveTextDeclined, value); }
    public string ReceiveReceiving { get => _receiveReceiving; private set => SetField(ref _receiveReceiving, value); }
    public string ReceiveDone { get => _receiveDone; private set => SetField(ref _receiveDone, value); }
    public string ReceiveTextDone { get => _receiveTextDone; private set => SetField(ref _receiveTextDone, value); }
    public string ReceiveTextShortened { get => _receiveTextShortened; private set => SetField(ref _receiveTextShortened, value); }
    public string ReceiveTextHidden { get => _receiveTextHidden; private set => SetField(ref _receiveTextHidden, value); }
    public string CopyText { get => _copyText; private set => SetField(ref _copyText, value); }
    public string TextCopied { get => _textCopied; private set => SetField(ref _textCopied, value); }
    public string CodeSuggestions { get => _codeSuggestions; private set => SetField(ref _codeSuggestions, value); }
    public string SettingsServer { get => _settingsServer; private set => SetField(ref _settingsServer, value); }
    public string SettingsServerHelp { get => _settingsServerHelp; private set => SetField(ref _settingsServerHelp, value); }
    public string SettingsServerReset { get => _settingsServerReset; private set => SetField(ref _settingsServerReset, value); }
    public string SettingsServerInvalid { get => _settingsServerInvalid; private set => SetField(ref _settingsServerInvalid, value); }
    public string SettingsSave { get => _settingsSave; private set => SetField(ref _settingsSave, value); }
    public string SettingsAbout { get => _settingsAbout; private set => SetField(ref _settingsAbout, value); }
    public string SettingsAboutBody { get => _settingsAboutBody; private set => SetField(ref _settingsAboutBody, value); }
    public string SettingsPrivacy { get => _settingsPrivacy; private set => SetField(ref _settingsPrivacy, value); }
    public string SettingsPrivacyBody { get => _settingsPrivacyBody; private set => SetField(ref _settingsPrivacyBody, value); }
    public string PrivacyMode { get => _privacyMode; private set => SetField(ref _privacyMode, value); }
    public string PrivacyModeHint { get => _privacyModeHint; private set => SetField(ref _privacyModeHint, value); }
    public string PrivacyModeConfirmTitle { get => _privacyModeConfirmTitle; private set => SetField(ref _privacyModeConfirmTitle, value); }
    public string PrivacyModeConfirmBody { get => _privacyModeConfirmBody; private set => SetField(ref _privacyModeConfirmBody, value); }
    public string PrivacyModeTurnOn { get => _privacyModeTurnOn; private set => SetField(ref _privacyModeTurnOn, value); }
    public string DraftTranslation { get => _draftTranslation; private set => SetField(ref _draftTranslation, value); }
    public string SettingsWordsEnglish { get => _settingsWordsEnglish; private set => SetField(ref _settingsWordsEnglish, value); }
    public string ErrorInvalidCode { get => _errorInvalidCode; private set => SetField(ref _errorInvalidCode, value); }
    public string ErrorWrongCode { get => _errorWrongCode; private set => SetField(ref _errorWrongCode, value); }
    public string ErrorInvalidOffer { get => _errorInvalidOffer; private set => SetField(ref _errorInvalidOffer, value); }
    public string ErrorTextDamaged { get => _errorTextDamaged; private set => SetField(ref _errorTextDamaged, value); }
    public string ErrorBadServer { get => _errorBadServer; private set => SetField(ref _errorBadServer, value); }
    public string ErrorCodeExpired { get => _errorCodeExpired; private set => SetField(ref _errorCodeExpired, value); }
    public string ErrorCodeNotInUse { get => _errorCodeNotInUse; private set => SetField(ref _errorCodeNotInUse, value); }
    public string ErrorOther { get => _errorOther; private set => SetField(ref _errorOther, value); }
    public string ShareBusy { get => _shareBusy; private set => SetField(ref _shareBusy, value); }
    public string LinkBusy { get => _linkBusy; private set => SetField(ref _linkBusy, value); }

    public void ApplyBundle(BridgeUiBundleDto bundle, string preferredLanguageTags)
    {
        PreferredLanguageTags = preferredLanguageTags;
        LanguageTag = bundle.LanguageTag;
        RegionTag = bundle.RegionTag;
        FlowDirection = bundle.FlowDirection;
        HasDraftTranslations = bundle.HasDraftTranslations;
        ExplorerSendWith = bundle.ExplorerSendWith;
        AppTagline = bundle.AppTagline;
        SendTitle = bundle.SendTitle;
        SendAddFiles = bundle.SendAddFiles;
        SendDropHere = bundle.SendDropHere;
        SendDropHint = bundle.SendDropHint;
        SendStrongCode = bundle.SendStrongCode;
        SendStrongCodeHint = bundle.SendStrongCodeHint;
        SendCreateCode = bundle.SendCreateCode;
        SendYourCode = bundle.SendYourCode;
        SendCopy = bundle.SendCopy;
        SendShare = bundle.SendShare;
        ReceiveTitle = bundle.ReceiveTitle;
        ReceiveCodeLabel = bundle.ReceiveCodeLabel;
        ReceiveCodeHint = bundle.ReceiveCodeHint;
        ReceivePaste = bundle.ReceivePaste;
        ReceiveConnect = bundle.ReceiveConnect;
        ReceiveAccept = bundle.ReceiveAccept;
        ReceiveDecline = bundle.ReceiveDecline;
        VerificationTitle = bundle.VerificationTitle;
        VerificationHint = bundle.VerificationHint;
        SettingsTitle = bundle.SettingsTitle;
        Cancel = bundle.Cancel;
        KeepAwakeReason = bundle.KeepAwakeReason;
        VersionLabel = bundle.VersionLabel;
        DesktopGenericName = bundle.DesktopGenericName;
        HomeSendTitle = bundle.HomeSendTitle;
        HomeSendBody = bundle.HomeSendBody;
        HomeReceiveTitle = bundle.HomeReceiveTitle;
        HomeReceiveBody = bundle.HomeReceiveBody;
        HomeFooter = bundle.HomeFooter;
        SameNetworkNote = bundle.SameNetworkNote;
        Done = bundle.Done;
        TryAgain = bundle.TryAgain;
        Back = bundle.Back;
        Stop = bundle.Stop;
        KeepGoing = bundle.KeepGoing;
        MoreInfo = bundle.MoreInfo;
        OpenFolder = bundle.OpenFolder;
        CancelTransferTitle = bundle.CancelTransferTitle;
        CancelTransferBody = bundle.CancelTransferBody;
        TechnicalDetail = bundle.TechnicalDetail;
        SendEmpty = bundle.SendEmpty;
        SendEmptyHint = bundle.SendEmptyHint;
        SendCounting = bundle.SendCounting;
        SendRemove = bundle.SendRemove;
        SendPreparing = bundle.SendPreparing;
        SendAddFailed = bundle.SendAddFailed;
        SendCodeHint = bundle.SendCodeHint;
        SendWaiting = bundle.SendWaiting;
        SendWaitingAccept = bundle.SendWaitingAccept;
        SendCopied = bundle.SendCopied;
        SendSending = bundle.SendSending;
        SendDone = bundle.SendDone;
        PickTitle = bundle.PickTitle;
        SendText = bundle.SendText;
        SendTextHint = bundle.SendTextHint;
        SendTextDone = bundle.SendTextDone;
        SendTextShortened = bundle.SendTextShortened;
        SendTextHidden = bundle.SendTextHidden;
        SendClipboard = bundle.SendClipboard;
        SendClipboardEmpty = bundle.SendClipboardEmpty;
        SendClipboardKept = bundle.SendClipboardKept;
        ReceiveCodeHelp = bundle.ReceiveCodeHelp;
        ReceiveCodeInvalid = bundle.ReceiveCodeInvalid;
        ReceiveConnecting = bundle.ReceiveConnecting;
        ReceiveOffer = bundle.ReceiveOffer;
        ReceiveOfferText = bundle.ReceiveOfferText;
        ReceiveOfferTextNote = bundle.ReceiveOfferTextNote;
        ReceiveDeclined = bundle.ReceiveDeclined;
        ReceiveTextDeclined = bundle.ReceiveTextDeclined;
        ReceiveReceiving = bundle.ReceiveReceiving;
        ReceiveDone = bundle.ReceiveDone;
        ReceiveTextDone = bundle.ReceiveTextDone;
        ReceiveTextShortened = bundle.ReceiveTextShortened;
        ReceiveTextHidden = bundle.ReceiveTextHidden;
        CopyText = bundle.CopyText;
        TextCopied = bundle.TextCopied;
        CodeSuggestions = bundle.CodeSuggestions;
        SettingsServer = bundle.SettingsServer;
        SettingsServerHelp = bundle.SettingsServerHelp;
        SettingsServerReset = bundle.SettingsServerReset;
        SettingsServerInvalid = bundle.SettingsServerInvalid;
        SettingsSave = bundle.SettingsSave;
        SettingsAbout = bundle.SettingsAbout;
        SettingsAboutBody = bundle.SettingsAboutBody;
        SettingsPrivacy = bundle.SettingsPrivacy;
        SettingsPrivacyBody = bundle.SettingsPrivacyBody;
        PrivacyMode = bundle.PrivacyMode;
        PrivacyModeHint = bundle.PrivacyModeHint;
        PrivacyModeConfirmTitle = bundle.PrivacyModeConfirmTitle;
        PrivacyModeConfirmBody = bundle.PrivacyModeConfirmBody;
        PrivacyModeTurnOn = bundle.PrivacyModeTurnOn;
        DraftTranslation = bundle.DraftTranslation;
        SettingsWordsEnglish = bundle.SettingsWordsEnglish;
        ErrorInvalidCode = bundle.ErrorInvalidCode;
        ErrorWrongCode = bundle.ErrorWrongCode;
        ErrorInvalidOffer = bundle.ErrorInvalidOffer;
        ErrorTextDamaged = bundle.ErrorTextDamaged;
        ErrorBadServer = bundle.ErrorBadServer;
        ErrorCodeExpired = bundle.ErrorCodeExpired;
        ErrorCodeNotInUse = bundle.ErrorCodeNotInUse;
        ErrorOther = bundle.ErrorOther;
        ShareBusy = bundle.ShareBusy;
        LinkBusy = bundle.LinkBusy;
    }

    public string FormatMessage(string key, params MessageArg[] args)
    {
        try
        {
            if (NativeBridge.TryFormatMessage(key, args, PreferredLanguageTags, RegionTag, out string formatted, out _))
            {
                return formatted;
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time fallback before native DLL is staged.
        }

        return string.Empty;
    }

    public string FormatBytes(ulong bytes)
    {
        try
        {
            FormattedBytesDto? dto = NativeBridge.TryFormatBytes(bytes, PreferredLanguageTags, RegionTag);
            if (dto is not null)
            {
                return dto.Formatted;
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time fallback before native DLL is staged.
        }

        return string.Empty;
    }

    public RegionalPercentDto FormatPercent(ulong doneBytes, ulong totalBytes)
    {
        try
        {
            RegionalPercentDto? dto = NativeBridge.TryFormatRegionalPercent(doneBytes, totalBytes, RegionTag);
            if (dto is not null)
            {
                return dto;
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time fallback before native DLL is staged.
        }

        byte whole = (byte)NativeBridge.ComputeWholePercentFloor(doneBytes, totalBytes);
        return new RegionalPercentDto(whole, string.Empty);
    }

    public string SanitizeFilename(string rawFilename)
    {
        if (string.IsNullOrEmpty(rawFilename))
        {
            return string.Empty;
        }

        try
        {
            SanitizedFilenameDto? dto = NativeBridge.TrySanitizeFilename(rawFilename);
            if (dto is not null)
            {
                return dto.Sanitized;
            }
        }
        catch (DllNotFoundException)
        {
            // Design-time preview fallback below.
        }

        StringBuilder sb = new(rawFilename.Length + 2);
        sb.Append('\u2068');
        foreach (Rune rune in rawFilename.EnumerateRunes())
        {
            int cp = rune.Value;
            UnicodeCategory cat = Rune.GetUnicodeCategory(rune);
            bool isControlOrBidi = cp is not (0x200C or 0x200D)
                && (cat is UnicodeCategory.Control
                    or UnicodeCategory.Format
                    or UnicodeCategory.LineSeparator
                    or UnicodeCategory.ParagraphSeparator
                    || (cp >= 0xFDD0 && cp <= 0xFDEF)
                    || (cp & 0xFFFE) == 0xFFFE
                    || (cp >= 0xE0000 && cp <= 0xE007F));
            if (isControlOrBidi)
            {
                sb.Append($"<U+{cp:X4}>");
            }
            else
            {
                sb.Append(rune.ToString());
            }
        }

        sb.Append('\u2069');
        return sb.ToString();
    }
}

/// <summary>
/// Represents a single selected file or folder with bidi-isolated display text
/// (<c>U+2068…U+2069</c>) and Rust-validated extended-length <c>\\?\</c> path.
/// </summary>
[GeneratedBindableCustomProperty]
public sealed partial class TransferItemModel : ObservableViewModel
{
    private string _formattedSize;

    public TransferItemModel(
        string safeDisplayName,
        string extendedPath,
        string unprefixedPath,
        bool isDirectory,
        ulong byteSize,
        string formattedSize)
    {
        SafeDisplayName = safeDisplayName;
        ExtendedPath = extendedPath;
        UnprefixedPath = unprefixedPath;
        IsDirectory = isDirectory;
        ByteSize = byteSize;
        _formattedSize = formattedSize;
    }

    public string SafeDisplayName { get; }

    public string ExtendedPath { get; }

    public string UnprefixedPath { get; }

    public bool IsDirectory { get; }

    public ulong ByteSize { get; set; }

    public string FormattedSize
    {
        get => _formattedSize;
        set => SetField(ref _formattedSize, value);
    }
}

/// <summary>
/// Single sanitized top-level filename inside an incoming transfer offer.
/// </summary>
[GeneratedBindableCustomProperty]
public sealed partial class OfferFileItemModel(string safeDisplayName)
{
    public string SafeDisplayName { get; } = safeDisplayName;
}

public enum SendInputMode
{
    Files,
    Text,
}

public enum SendPhase
{
    Idle,
    Preparing,
    Waiting,
    Connected,
    Transferring,
    Done,
    Failed,
}

public enum ReceivePhase
{
    Idle,
    Connecting,
    Offer,
    Transferring,
    Done,
    Declined,
    Failed,
}

/// <summary>
/// ViewModel for <c>Views/SendPage.xaml</c> bound purely via <c>x:Bind</c>.
/// </summary>
[GeneratedBindableCustomProperty]
public sealed partial class SendViewModel : ObservableViewModel
{
    private SendInputMode _mode = SendInputMode.Files;
    private SendPhase _phase = SendPhase.Idle;
    private bool _useStrongerThreeWordCode;
    private string _selectionSummary = string.Empty;
    private string _selectionError = string.Empty;
    private string _rawTextInput = string.Empty;
    private string _bigText = string.Empty;
    private bool _isBigTextActive;
    private ulong _textByteCount;
    private string _formattedTextBytes = string.Empty;
    private bool _isTextTooLong;
    private string _textTooLongMessage = string.Empty;
    private bool _textHiddenNoticeVisible;
    private bool _textShortenedNoticeVisible;
    private string _textClipboardNotice = string.Empty;
    private string _transferCode = string.Empty;
    private string _transferWebUri = string.Empty;
    private string _shareText = string.Empty;
    private bool _copiedFeedbackVisible;
    private string _verificationWords = string.Empty;
    private int _wholePercent;
    private string _regionalPercentText = string.Empty;
    private string _formattedProgressBytes = string.Empty;
    private string _statusCaption = string.Empty;
    private string _resultTitle = string.Empty;
    private string _resultBody = string.Empty;
    private string _errorSummary = string.Empty;
    private string _errorCauseDetail = string.Empty;
    private string _errorTechnicalEnglish = string.Empty;
    private bool _showErrorDetails;

    public SendViewModel(UiStringsViewModel? strings = null, SettingsStore? settings = null)
    {
        Strings = strings ?? new UiStringsViewModel();
        Settings = settings ?? new SettingsStore();
        _useStrongerThreeWordCode = Settings.Current.StrongerThreeWordCode;
    }

    public UiStringsViewModel Strings { get; }

    public SettingsStore Settings { get; }

    public ObservableCollection<TransferItemModel> SelectedItems { get; } = [];

    public Action<bool, bool>? BrandMarkStateChanged { get; set; }

    public Action? TransferLifecycleChanged { get; set; }

    public Action<NotificationEventInput>? BackgroundNotificationReady { get; set; }

    public ulong ActiveSessionId { get; set; }

    public ulong DoneBytes { get; private set; }

    public ulong TotalBytes { get; private set; }

    public TransferLifecycleStage ToLifecycleStage() => _phase switch
    {
        SendPhase.Preparing => TransferLifecycleStage.Preparing,
        SendPhase.Waiting => TransferLifecycleStage.Waiting,
        SendPhase.Connected => TransferLifecycleStage.Connected,
        SendPhase.Transferring => TransferLifecycleStage.Transferring,
        SendPhase.Done => TransferLifecycleStage.Done,
        SendPhase.Failed => TransferLifecycleStage.Failed,
        _ => TransferLifecycleStage.Idle,
    };

    public SendInputMode Mode
    {
        get => _mode;
        set
        {
            if (SetField(ref _mode, value))
            {
                NotifyModeAndActionProperties();
            }
        }
    }

    public SendPhase Phase
    {
        get => _phase;
        set
        {
            if (SetField(ref _phase, value))
            {
                NotifyPhaseProperties();
                BrandMarkStateChanged?.Invoke(IsTransferRunning, value == SendPhase.Done);
                TransferLifecycleChanged?.Invoke();
            }
        }
    }

    public bool UseStrongerThreeWordCode
    {
        get => _useStrongerThreeWordCode;
        set
        {
            if (SetField(ref _useStrongerThreeWordCode, value))
            {
                _ = Settings.TrySetStrongerThreeWordCode(value);
            }
        }
    }

    public string PageTitle =>
        _mode == SendInputMode.Text ? Strings.SendText : Strings.SendTitle;

    public string SelectionSummary
    {
        get => _selectionSummary;
        private set => SetField(ref _selectionSummary, value);
    }

    public string SelectionError
    {
        get => _selectionError;
        set
        {
            if (SetField(ref _selectionError, value))
            {
                NotifyChanged(nameof(SelectionErrorVisibility));
            }
        }
    }

    public string OutgoingText => _isBigTextActive ? _bigText : _rawTextInput;

    public string RawTextInput
    {
        get => _rawTextInput;
        set
        {
            if (SetField(ref _rawTextInput, value))
            {
                if (!_isBigTextActive)
                {
                    RecomputeTextMetrics();
                }
            }
        }
    }

    public bool IsBigTextActive
    {
        get => _isBigTextActive;
        private set
        {
            if (SetField(ref _isBigTextActive, value))
            {
                NotifyChanged(nameof(ClearBigTextVisibility));
            }
        }
    }

    public ulong TextByteCount
    {
        get => _textByteCount;
        private set => SetField(ref _textByteCount, value);
    }

    public string FormattedTextBytes
    {
        get => _formattedTextBytes;
        private set => SetField(ref _formattedTextBytes, value);
    }

    public bool IsTextTooLong
    {
        get => _isTextTooLong;
        private set
        {
            if (SetField(ref _isTextTooLong, value))
            {
                NotifyChanged(nameof(TextTooLongVisibility));
                NotifyChanged(nameof(CanCreateCode));
            }
        }
    }

    public string TextTooLongMessage
    {
        get => _textTooLongMessage;
        private set => SetField(ref _textTooLongMessage, value);
    }

    public bool TextHiddenNoticeVisible
    {
        get => _textHiddenNoticeVisible;
        private set
        {
            if (SetField(ref _textHiddenNoticeVisible, value))
            {
                NotifyChanged(nameof(TextHiddenNoticeVisibility));
            }
        }
    }

    public bool TextShortenedNoticeVisible
    {
        get => _textShortenedNoticeVisible;
        private set
        {
            if (SetField(ref _textShortenedNoticeVisible, value))
            {
                NotifyChanged(nameof(TextShortenedNoticeVisibility));
            }
        }
    }

    public string TextClipboardNotice
    {
        get => _textClipboardNotice;
        set
        {
            if (SetField(ref _textClipboardNotice, value))
            {
                NotifyChanged(nameof(TextClipboardNoticeVisibility));
            }
        }
    }

    public string TransferCode
    {
        get => _transferCode;
        set
        {
            if (SetField(ref _transferCode, value))
            {
                NotifyChanged(nameof(CodeCardVisibility));
            }
        }
    }

    public string TransferWebUri
    {
        get => _transferWebUri;
        set => SetField(ref _transferWebUri, value);
    }

    public string ShareText
    {
        get => _shareText;
        set => SetField(ref _shareText, value);
    }

    public bool CopiedFeedbackVisible
    {
        get => _copiedFeedbackVisible;
        set
        {
            if (SetField(ref _copiedFeedbackVisible, value))
            {
                NotifyChanged(nameof(CopiedFeedbackVisibility));
            }
        }
    }

    public string VerificationWords
    {
        get => _verificationWords;
        set
        {
            if (SetField(ref _verificationWords, value))
            {
                NotifyChanged(nameof(VerificationVisibility));
            }
        }
    }

    public int WholePercent
    {
        get => _wholePercent;
        private set => SetField(ref _wholePercent, value);
    }

    public string RegionalPercentText
    {
        get => _regionalPercentText;
        private set => SetField(ref _regionalPercentText, value);
    }

    public string FormattedProgressBytes
    {
        get => _formattedProgressBytes;
        private set => SetField(ref _formattedProgressBytes, value);
    }

    public string StatusCaption
    {
        get => _statusCaption;
        set => SetField(ref _statusCaption, value);
    }

    public string ResultTitle
    {
        get => _resultTitle;
        private set => SetField(ref _resultTitle, value);
    }

    public string ResultBody
    {
        get => _resultBody;
        private set => SetField(ref _resultBody, value);
    }

    public string ErrorSummary
    {
        get => _errorSummary;
        private set => SetField(ref _errorSummary, value);
    }

    public string ErrorCauseDetail
    {
        get => _errorCauseDetail;
        private set
        {
            if (SetField(ref _errorCauseDetail, value))
            {
                NotifyChanged(nameof(ErrorCauseDetailVisibility));
            }
        }
    }

    public string ErrorTechnicalEnglish
    {
        get => _errorTechnicalEnglish;
        private set => SetField(ref _errorTechnicalEnglish, value);
    }

    public bool ShowErrorDetails
    {
        get => _showErrorDetails;
        set
        {
            if (SetField(ref _showErrorDetails, value))
            {
                NotifyChanged(nameof(ErrorDetailsVisibility));
            }
        }
    }

    public bool IsTransferRunning =>
        _phase is SendPhase.Preparing or SendPhase.Waiting or SendPhase.Connected or SendPhase.Transferring;

    public bool HasUnsentInput =>
        _phase == SendPhase.Idle
        && (_mode == SendInputMode.Files ? SelectedItems.Count > 0 : !string.IsNullOrEmpty(OutgoingText));

    public bool CanCreateCode =>
        _phase == SendPhase.Idle
        && (_mode == SendInputMode.Files
            ? SelectedItems.Count > 0
            : !string.IsNullOrEmpty(OutgoingText) && !_isTextTooLong);

    public Visibility IdleVisibility => _phase == SendPhase.Idle ? Visibility.Visible : Visibility.Collapsed;
    public Visibility FilesModeVisibility => _phase == SendPhase.Idle && _mode == SendInputMode.Files ? Visibility.Visible : Visibility.Collapsed;
    public Visibility TextModeVisibility => _phase == SendPhase.Idle && _mode == SendInputMode.Text ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ActiveVisibility => IsTransferRunning ? Visibility.Visible : Visibility.Collapsed;
    public Visibility CodeCardVisibility => !string.IsNullOrEmpty(_transferCode) && IsTransferRunning ? Visibility.Visible : Visibility.Collapsed;
    public Visibility VerificationVisibility => !string.IsNullOrEmpty(_verificationWords) && IsTransferRunning ? Visibility.Visible : Visibility.Collapsed;
    public Visibility WaitingAcceptVisibility => _phase == SendPhase.Connected ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ProgressVisibility => _phase == SendPhase.Transferring ? Visibility.Visible : Visibility.Collapsed;
    public Visibility DoneVisibility => _phase == SendPhase.Done ? Visibility.Visible : Visibility.Collapsed;
    public Visibility FailedVisibility => _phase == SendPhase.Failed ? Visibility.Visible : Visibility.Collapsed;
    public Visibility SelectionErrorVisibility => string.IsNullOrEmpty(_selectionError) ? Visibility.Collapsed : Visibility.Visible;
    public Visibility TextTooLongVisibility => _isTextTooLong ? Visibility.Visible : Visibility.Collapsed;
    public Visibility TextHiddenNoticeVisibility => _textHiddenNoticeVisible ? Visibility.Visible : Visibility.Collapsed;
    public Visibility TextShortenedNoticeVisibility => _textShortenedNoticeVisible ? Visibility.Visible : Visibility.Collapsed;
    public Visibility TextClipboardNoticeVisibility => string.IsNullOrEmpty(_textClipboardNotice) ? Visibility.Collapsed : Visibility.Visible;
    public Visibility ClearBigTextVisibility => _isBigTextActive ? Visibility.Visible : Visibility.Collapsed;
    public Visibility CopiedFeedbackVisibility => _copiedFeedbackVisible ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ErrorDetailsVisibility => _showErrorDetails ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ErrorCauseDetailVisibility => string.IsNullOrEmpty(_errorCauseDetail) ? Visibility.Collapsed : Visibility.Visible;

    public void RefreshLocalizedDefaults()
    {
        NotifyChanged(nameof(PageTitle));
        if (SelectedItems.Count == 0)
        {
            SelectionSummary = Strings.SendEmpty;
        }
        else
        {
            UpdateSelectionSummaryFromItems();
        }

        if (_phase == SendPhase.Idle && string.IsNullOrEmpty(_statusCaption))
        {
            StatusCaption = Strings.SendEmptyHint;
        }

        if (_phase == SendPhase.Idle && string.IsNullOrEmpty(_regionalPercentText))
        {
            RegionalPercentText = Strings.FormatPercent(0, 0).Formatted;
        }

        RecomputeTextMetrics();
    }

    /// <summary>
    /// Validates and normalizes <paramref name="rawPaths"/> strictly via Rust
    /// <c>totaldrop_win_validate_paths_json</c> (handling drive, UNC
    /// <c>\\?\UNC\...</c>, case-insensitive deduplication, and dangerous path
    /// rejection). Never concatenates <c>\\?\</c> in C#.
    /// </summary>
    public bool TryAddRawPaths(IEnumerable<string> rawPaths)
    {
        List<string> combined = new(SelectedItems.Count + 4);
        foreach (TransferItemModel existing in SelectedItems)
        {
            combined.Add(existing.ExtendedPath);
        }

        foreach (string raw in rawPaths)
        {
            if (!string.IsNullOrWhiteSpace(raw))
            {
                combined.Add(raw);
            }
        }

        if (combined.Count == 0)
        {
            return false;
        }

        ValidatedPathDto[] normalized;
        try
        {
            if (!NativeBridge.TryValidatePaths(combined, out normalized, out _))
            {
                SelectionError = Strings.SendAddFailed;
                return false;
            }
        }
        catch (DllNotFoundException)
        {
            SelectionError = Strings.SendAddFailed;
            return false;
        }

        Dictionary<string, TransferItemModel> priorByKey = new(StringComparer.OrdinalIgnoreCase);
        foreach (TransferItemModel existing in SelectedItems)
        {
            priorByKey[existing.ExtendedPath] = existing;
        }

        SelectedItems.Clear();
        foreach (ValidatedPathDto item in normalized)
        {
            if (priorByKey.TryGetValue(item.ExtendedPath, out TransferItemModel? reused))
            {
                SelectedItems.Add(reused);
                continue;
            }

            string trimmedUnprefixed = item.UnprefixedPath.TrimEnd('\\');
            string rawLeaf = Path.GetFileName(trimmedUnprefixed);
            if (string.IsNullOrEmpty(rawLeaf))
            {
                rawLeaf = item.SafeDisplayPath;
            }

            string safeLeaf = NativeBridge.TrySanitizeFilename(rawLeaf)?.Sanitized
                ?? item.SafeDisplayPath;

            bool isDir = false;
            ulong size = 0;
            string formattedSize = string.Empty;
            try
            {
                if (Directory.Exists(item.ExtendedPath))
                {
                    isDir = true;
                    formattedSize = Strings.SendCounting;
                }
                else if (File.Exists(item.ExtendedPath))
                {
                    FileInfo info = new(item.ExtendedPath);
                    size = (ulong)Math.Max(0, info.Length);
                    formattedSize = Strings.FormatBytes(size);
                }
            }
            catch (IOException)
            {
                // Keep item listed; Rust scan reports authoritative storage error if unreadable.
            }
            catch (UnauthorizedAccessException)
            {
                // Keep item listed; Rust scan reports authoritative storage error if unreadable.
            }

            SelectedItems.Add(new TransferItemModel(
                safeLeaf,
                item.ExtendedPath,
                item.UnprefixedPath,
                isDir,
                size,
                formattedSize));
        }

        SelectionError = string.Empty;
        Mode = SendInputMode.Files;
        UpdateSelectionSummaryFromItems();
        NotifyChanged(nameof(CanCreateCode));
        NotifyChanged(nameof(HasUnsentInput));
        return true;
    }

    public void RemoveItem(TransferItemModel item)
    {
        if (SelectedItems.Remove(item))
        {
            UpdateSelectionSummaryFromItems();
            NotifyChanged(nameof(CanCreateCode));
            NotifyChanged(nameof(HasUnsentInput));
        }
    }

    public void UpdateSelectionSummaryFromItems()
    {
        if (SelectedItems.Count == 0)
        {
            SelectionSummary = Strings.SendEmpty;
            return;
        }

        ulong totalBytes = 0;
        bool stillCounting = false;
        foreach (TransferItemModel item in SelectedItems)
        {
            totalBytes += item.ByteSize;
            if (item.IsDirectory && string.Equals(item.FormattedSize, Strings.SendCounting, StringComparison.Ordinal))
            {
                stillCounting = true;
            }
        }

        string sizeStr = stillCounting ? Strings.SendCounting : Strings.FormatBytes(totalBytes);
        SelectionSummary = Strings.FormatMessage(
            "itemsAndSize",
            MessageArg.FromCount("count", (ulong)SelectedItems.Count),
            MessageArg.FromText("size", sizeStr));
    }

    public void ApplyPastedText(string pasted, bool fromClipboardShortcut)
    {
        Mode = SendInputMode.Text;
        TextClipboardNotice = string.Empty;

        if (fromClipboardShortcut && !string.IsNullOrEmpty(OutgoingText))
        {
            TextClipboardNotice = Strings.SendClipboardKept;
            return;
        }

        if (string.IsNullOrEmpty(pasted))
        {
            if (fromClipboardShortcut)
            {
                TextClipboardNotice = Strings.SendClipboardEmpty;
            }

            return;
        }

        SanitizedPeerTextDto? sanitized = null;
        try
        {
            sanitized = NativeBridge.TrySanitizeText(pasted);
        }
        catch (DllNotFoundException)
        {
            // Ignore in design preview.
        }

        if (sanitized is { Shortened: true })
        {
            _bigText = pasted;
            IsBigTextActive = true;
            RawTextInput = sanitized.DisplayText;
            TextShortenedNoticeVisible = true;
            TextHiddenNoticeVisible = sanitized.HasHiddenControls;
        }
        else
        {
            _bigText = string.Empty;
            IsBigTextActive = false;
            RawTextInput = pasted;
            TextShortenedNoticeVisible = false;
            TextHiddenNoticeVisible = sanitized is { HasHiddenControls: true };
        }

        RecomputeTextMetrics();
    }

    public void ClearTextInput()
    {
        _bigText = string.Empty;
        IsBigTextActive = false;
        RawTextInput = string.Empty;
        TextShortenedNoticeVisible = false;
        TextHiddenNoticeVisible = false;
        TextClipboardNotice = string.Empty;
        RecomputeTextMetrics();
    }

    private void RecomputeTextMetrics()
    {
        string text = OutgoingText;
        ulong bytes = (ulong)Encoding.UTF8.GetByteCount(text);
        TextByteCount = bytes;
        FormattedTextBytes = Strings.FormatBytes(bytes);

        bool tooLong = bytes > NativeBridge.MaxTextBytes;
        IsTextTooLong = tooLong;
        TextTooLongMessage = tooLong
            ? Strings.FormatMessage("sendTextTooLong", MessageArg.FromText("size", Strings.FormatBytes(NativeBridge.MaxTextBytes)))
            : string.Empty;

        if (!_isBigTextActive && !string.IsNullOrEmpty(text))
        {
            try
            {
                SanitizedPeerTextDto? sanitized = NativeBridge.TrySanitizeText(text);
                TextHiddenNoticeVisible = sanitized is { HasHiddenControls: true };
            }
            catch (DllNotFoundException)
            {
                TextHiddenNoticeVisible = false;
            }
        }
        else if (string.IsNullOrEmpty(text))
        {
            TextHiddenNoticeVisible = false;
            TextShortenedNoticeVisible = false;
        }

        NotifyChanged(nameof(CanCreateCode));
        NotifyChanged(nameof(HasUnsentInput));
    }

    public void BeginPreparing()
    {
        TransferCode = string.Empty;
        TransferWebUri = string.Empty;
        ShareText = string.Empty;
        CopiedFeedbackVisible = false;
        VerificationWords = string.Empty;
        DoneBytes = 0;
        TotalBytes = 0;
        WholePercent = 0;
        RegionalPercentText = Strings.FormatPercent(0, 0).Formatted;
        FormattedProgressBytes = string.Empty;
        ResultTitle = string.Empty;
        ResultBody = string.Empty;
        ErrorSummary = string.Empty;
        ErrorCauseDetail = string.Empty;
        ErrorTechnicalEnglish = string.Empty;
        ShowErrorDetails = false;
        StatusCaption = Strings.SendPreparing;
        Phase = SendPhase.Preparing;
    }

    public void ApplySessionEvent(SessionEventDto ev)
    {
        switch (ev.Event)
        {
            case "code_ready":
                if (ev.Code is not null)
                {
                    TransferCode = ev.Code.DisplayEnglish;
                    TransferWebUri = ev.Code.WebUri;
                }

                DoneBytes = 0;
                TotalBytes = ev.TotalBytes ?? 0;
                ShareText = ev.ShareText ?? string.Empty;
                StatusCaption = Strings.SendWaiting;
                Phase = SendPhase.Waiting;
                break;

            case "waiting":
                StatusCaption = string.IsNullOrEmpty(ev.Caption) ? Strings.SendWaiting : ev.Caption;
                Phase = SendPhase.Waiting;
                break;

            case "connected":
                VerificationWords = ev.JoinedWordsLtr ?? string.Empty;
                StatusCaption = Strings.SendWaitingAccept;
                Phase = SendPhase.Connected;
                break;

            case "progress":
                if (ev.DoneBytes.HasValue)
                {
                    DoneBytes = ev.DoneBytes.Value;
                }

                if (ev.TotalBytes.HasValue)
                {
                    TotalBytes = ev.TotalBytes.Value;
                }

                if (ev.Percent is not null)
                {
                    WholePercent = ev.Percent.Whole;
                    RegionalPercentText = ev.Percent.Formatted;
                }

                FormattedProgressBytes = !string.IsNullOrEmpty(ev.FormattedDone) && !string.IsNullOrEmpty(ev.FormattedTotal)
                    ? $"{ev.FormattedDone} / {ev.FormattedTotal}"
                    : string.Empty;
                StatusCaption = Strings.SendSending;
                Phase = SendPhase.Transferring;
                break;

            case "done":
                WholePercent = 100;
                RegionalPercentText = Strings.FormatPercent(1, 1).Formatted;
                bool isTextSend = ev.IsText == true;
                ulong sendOkCount = ev.FilesOk ?? 1;
                ulong sendFailedCount = ev.FilesFailed ?? 0;
                ResultTitle = Strings.SendDone;
                if (isTextSend)
                {
                    ResultBody = sendFailedCount > 0 ? Strings.ErrorTextDamaged : Strings.SendTextDone;
                }
                else
                {
                    string doneBody = Strings.FormatMessage("sendDoneBody", MessageArg.FromCount("count", sendOkCount));
                    if (sendFailedCount > 0)
                    {
                        string failPart = Strings.FormatMessage("sendSomeFailed", MessageArg.FromCount("count", sendFailedCount));
                        doneBody = $"{doneBody} {failPart}";
                    }

                    ResultBody = doneBody;
                }

                Phase = SendPhase.Done;
                BackgroundNotificationReady?.Invoke(new NotificationEventInput(
                    Role: TransferRole.Send,
                    Stage: TransferLifecycleStage.Done,
                    WindowActive: false,
                    IsText: isTextSend,
                    FilesOk: sendOkCount,
                    FilesFailed: sendFailedCount,
                    ByteCount: ev.Bytes ?? TotalBytes,
                    FormattedBytes: ev.FormattedBytes));
                break;

            case "failed":
                ErrorSummary = string.IsNullOrEmpty(ev.Summary) ? Strings.ErrorOther : ev.Summary;
                ErrorCauseDetail = ev.CauseDetail ?? string.Empty;
                ErrorTechnicalEnglish = ev.TechnicalEnglish ?? string.Empty;
                ShowErrorDetails = false;
                Phase = SendPhase.Failed;
                BackgroundNotificationReady?.Invoke(new NotificationEventInput(
                    Role: TransferRole.Send,
                    Stage: TransferLifecycleStage.Failed,
                    WindowActive: false,
                    IsText: Mode == SendInputMode.Text,
                    ErrorL10nKey: ev.L10nKey,
                    LocalizedErrorSummary: ErrorSummary));
                break;
        }
    }

    public void ResetToIdle(bool clearSelection)
    {
        if (clearSelection)
        {
            SelectedItems.Clear();
            ClearTextInput();
            UpdateSelectionSummaryFromItems();
        }

        TransferCode = string.Empty;
        TransferWebUri = string.Empty;
        ShareText = string.Empty;
        CopiedFeedbackVisible = false;
        VerificationWords = string.Empty;
        DoneBytes = 0;
        TotalBytes = 0;
        WholePercent = 0;
        RegionalPercentText = Strings.FormatPercent(0, 0).Formatted;
        FormattedProgressBytes = string.Empty;
        ResultTitle = string.Empty;
        ResultBody = string.Empty;
        ErrorSummary = string.Empty;
        ErrorCauseDetail = string.Empty;
        ErrorTechnicalEnglish = string.Empty;
        ShowErrorDetails = false;
        ActiveSessionId = 0;
        StatusCaption = Strings.SendEmptyHint;
        Phase = SendPhase.Idle;
        NotifyModeAndActionProperties();
    }

    private void NotifyModeAndActionProperties()
    {
        NotifyChanged(nameof(PageTitle));
        NotifyChanged(nameof(FilesModeVisibility));
        NotifyChanged(nameof(TextModeVisibility));
        NotifyChanged(nameof(CanCreateCode));
        NotifyChanged(nameof(HasUnsentInput));
    }

    private void NotifyPhaseProperties()
    {
        NotifyChanged(nameof(IsTransferRunning));
        NotifyChanged(nameof(CanCreateCode));
        NotifyChanged(nameof(HasUnsentInput));
        NotifyChanged(nameof(IdleVisibility));
        NotifyChanged(nameof(FilesModeVisibility));
        NotifyChanged(nameof(TextModeVisibility));
        NotifyChanged(nameof(ActiveVisibility));
        NotifyChanged(nameof(CodeCardVisibility));
        NotifyChanged(nameof(VerificationVisibility));
        NotifyChanged(nameof(WaitingAcceptVisibility));
        NotifyChanged(nameof(ProgressVisibility));
        NotifyChanged(nameof(DoneVisibility));
        NotifyChanged(nameof(FailedVisibility));
    }
}

/// <summary>
/// ViewModel for <c>Views/ReceivePage.xaml</c> bound purely via <c>x:Bind</c>.
/// </summary>
[GeneratedBindableCustomProperty]
public sealed partial class ReceiveViewModel : ObservableViewModel
{
    private ReceivePhase _phase = ReceivePhase.Idle;
    private string _codeInput = string.Empty;
    private string _connectingCode = string.Empty;
    private string _validationMessage = string.Empty;
    private bool _isTextOffer;
    private string _offerTitle = string.Empty;
    private string _offerSummary = string.Empty;
    private string _offerMoreText = string.Empty;
    private string _verificationWords = string.Empty;
    private string _destinationFolder;
    private int _wholePercent;
    private string _regionalPercentText = string.Empty;
    private string _formattedProgressBytes = string.Empty;
    private string _resultTitle = string.Empty;
    private string _resultBody = string.Empty;
    private string _savedToFolder = string.Empty;
    private string _rawReceivedText = string.Empty;
    private string _displayReceivedText = string.Empty;
    private bool _receivedTextShortened;
    private bool _receivedTextHidden;
    private bool _textCopiedFeedbackVisible;
    private string _errorSummary = string.Empty;
    private string _errorCauseDetail = string.Empty;
    private string _errorTechnicalEnglish = string.Empty;
    private bool _showErrorDetails;

    public ReceiveViewModel(UiStringsViewModel? strings = null, SettingsStore? settings = null)
    {
        Strings = strings ?? new UiStringsViewModel();
        Settings = settings ?? new SettingsStore();
        _destinationFolder = NativeBridge.ResolveDefaultDownloadsFolder();
    }

    public UiStringsViewModel Strings { get; }

    public SettingsStore Settings { get; }

    public ObservableCollection<OfferFileItemModel> OfferFiles { get; } = [];

    public Action<bool, bool>? BrandMarkStateChanged { get; set; }

    public Action? TransferLifecycleChanged { get; set; }

    public Action<NotificationEventInput>? BackgroundNotificationReady { get; set; }

    public ulong ActiveSessionId { get; set; }

    public ulong DoneBytes { get; private set; }

    public ulong TotalBytes { get; private set; }

    public TransferLifecycleStage ToLifecycleStage() => _phase switch
    {
        ReceivePhase.Connecting => TransferLifecycleStage.Connecting,
        ReceivePhase.Offer => TransferLifecycleStage.Offer,
        ReceivePhase.Transferring => TransferLifecycleStage.Transferring,
        ReceivePhase.Done => TransferLifecycleStage.Done,
        ReceivePhase.Declined => TransferLifecycleStage.Declined,
        ReceivePhase.Failed => TransferLifecycleStage.Failed,
        _ => TransferLifecycleStage.Idle,
    };

    public ReceivePhase Phase
    {
        get => _phase;
        set
        {
            if (SetField(ref _phase, value))
            {
                NotifyPhaseProperties();
                BrandMarkStateChanged?.Invoke(IsTransferRunning, value == ReceivePhase.Done);
                TransferLifecycleChanged?.Invoke();
            }
        }
    }

    public string CodeInput
    {
        get => _codeInput;
        set
        {
            if (SetField(ref _codeInput, value))
            {
                NotifyChanged(nameof(CanConnect));
            }
        }
    }

    public string ConnectingCode
    {
        get => _connectingCode;
        private set => SetField(ref _connectingCode, value);
    }

    public string ValidationMessage
    {
        get => _validationMessage;
        set
        {
            if (SetField(ref _validationMessage, value))
            {
                NotifyChanged(nameof(ValidationVisibility));
            }
        }
    }

    public bool IsTextOffer
    {
        get => _isTextOffer;
        private set
        {
            if (SetField(ref _isTextOffer, value))
            {
                NotifyPhaseProperties();
            }
        }
    }

    public string OfferTitle
    {
        get => _offerTitle;
        private set => SetField(ref _offerTitle, value);
    }

    public string OfferSummary
    {
        get => _offerSummary;
        private set => SetField(ref _offerSummary, value);
    }

    public string OfferMoreText
    {
        get => _offerMoreText;
        private set
        {
            if (SetField(ref _offerMoreText, value))
            {
                NotifyChanged(nameof(OfferMoreVisibility));
            }
        }
    }

    public string VerificationWords
    {
        get => _verificationWords;
        private set
        {
            if (SetField(ref _verificationWords, value))
            {
                NotifyChanged(nameof(VerificationVisibility));
            }
        }
    }

    public string DestinationFolder
    {
        get => _destinationFolder;
        set => SetField(ref _destinationFolder, value);
    }

    public int WholePercent
    {
        get => _wholePercent;
        private set => SetField(ref _wholePercent, value);
    }

    public string RegionalPercentText
    {
        get => _regionalPercentText;
        private set => SetField(ref _regionalPercentText, value);
    }

    public string FormattedProgressBytes
    {
        get => _formattedProgressBytes;
        private set => SetField(ref _formattedProgressBytes, value);
    }

    public string ResultTitle
    {
        get => _resultTitle;
        private set => SetField(ref _resultTitle, value);
    }

    public string ResultBody
    {
        get => _resultBody;
        private set => SetField(ref _resultBody, value);
    }

    public string SavedToFolder
    {
        get => _savedToFolder;
        private set
        {
            if (SetField(ref _savedToFolder, value))
            {
                NotifyChanged(nameof(OpenFolderVisibility));
            }
        }
    }

    public string RawReceivedText
    {
        get => _rawReceivedText;
        private set => SetField(ref _rawReceivedText, value);
    }

    public string DisplayReceivedText
    {
        get => _displayReceivedText;
        private set
        {
            if (SetField(ref _displayReceivedText, value))
            {
                NotifyChanged(nameof(IsReceivedTextVisible));
                TransferLifecycleChanged?.Invoke();
            }
        }
    }

    public bool ReceivedTextShortened
    {
        get => _receivedTextShortened;
        private set
        {
            if (SetField(ref _receivedTextShortened, value))
            {
                NotifyChanged(nameof(ReceivedTextShortenedVisibility));
            }
        }
    }

    public bool ReceivedTextHidden
    {
        get => _receivedTextHidden;
        private set
        {
            if (SetField(ref _receivedTextHidden, value))
            {
                NotifyChanged(nameof(ReceivedTextHiddenVisibility));
            }
        }
    }

    public bool TextCopiedFeedbackVisible
    {
        get => _textCopiedFeedbackVisible;
        set
        {
            if (SetField(ref _textCopiedFeedbackVisible, value))
            {
                NotifyChanged(nameof(TextCopiedFeedbackVisibility));
            }
        }
    }

    public string ErrorSummary
    {
        get => _errorSummary;
        private set => SetField(ref _errorSummary, value);
    }

    public string ErrorCauseDetail
    {
        get => _errorCauseDetail;
        private set
        {
            if (SetField(ref _errorCauseDetail, value))
            {
                NotifyChanged(nameof(ErrorCauseDetailVisibility));
            }
        }
    }

    public string ErrorTechnicalEnglish
    {
        get => _errorTechnicalEnglish;
        private set => SetField(ref _errorTechnicalEnglish, value);
    }

    public bool ShowErrorDetails
    {
        get => _showErrorDetails;
        set
        {
            if (SetField(ref _showErrorDetails, value))
            {
                NotifyChanged(nameof(ErrorDetailsVisibility));
            }
        }
    }

    public bool CanConnect => _phase == ReceivePhase.Idle && !string.IsNullOrWhiteSpace(_codeInput);

    public bool IsTransferRunning =>
        _phase is ReceivePhase.Connecting or ReceivePhase.Offer or ReceivePhase.Transferring;

    /// <summary>
    /// True while a verified in-memory received plain-text transfer is displayed.
    /// Escape MUST be suppressed while true so the user cannot accidentally lose
    /// unsaved text (Linux <c>ReceivePage.qml:45-52</c> parity).
    /// </summary>
    public bool IsReceivedTextVisible =>
        _phase == ReceivePhase.Done && _isTextOffer && !string.IsNullOrEmpty(_displayReceivedText);

    public Visibility IdleVisibility => _phase == ReceivePhase.Idle ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ConnectingVisibility => _phase == ReceivePhase.Connecting ? Visibility.Visible : Visibility.Collapsed;
    public Visibility OfferCardVisibility => _phase == ReceivePhase.Offer ? Visibility.Visible : Visibility.Collapsed;
    public Visibility OfferDestinationVisibility => _phase == ReceivePhase.Offer && !_isTextOffer ? Visibility.Visible : Visibility.Collapsed;
    public Visibility OfferTextNoteVisibility => _phase == ReceivePhase.Offer && _isTextOffer ? Visibility.Visible : Visibility.Collapsed;
    public Visibility OfferMoreVisibility => string.IsNullOrEmpty(_offerMoreText) ? Visibility.Collapsed : Visibility.Visible;
    public Visibility VerificationVisibility => !string.IsNullOrEmpty(_verificationWords) && _phase == ReceivePhase.Offer ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ProgressVisibility => _phase == ReceivePhase.Transferring ? Visibility.Visible : Visibility.Collapsed;
    public Visibility DoneFilesVisibility => _phase == ReceivePhase.Done && !_isTextOffer ? Visibility.Visible : Visibility.Collapsed;
    public Visibility DoneTextVisibility => _phase == ReceivePhase.Done && _isTextOffer ? Visibility.Visible : Visibility.Collapsed;
    public Visibility DeclinedVisibility => _phase == ReceivePhase.Declined ? Visibility.Visible : Visibility.Collapsed;
    public Visibility FailedVisibility => _phase == ReceivePhase.Failed ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ValidationVisibility => string.IsNullOrEmpty(_validationMessage) ? Visibility.Collapsed : Visibility.Visible;
    public Visibility OpenFolderVisibility => !string.IsNullOrEmpty(_savedToFolder) ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ReceivedTextShortenedVisibility => _receivedTextShortened ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ReceivedTextHiddenVisibility => _receivedTextHidden ? Visibility.Visible : Visibility.Collapsed;
    public Visibility TextCopiedFeedbackVisibility => _textCopiedFeedbackVisible ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ErrorDetailsVisibility => _showErrorDetails ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ErrorCauseDetailVisibility => string.IsNullOrEmpty(_errorCauseDetail) ? Visibility.Collapsed : Visibility.Visible;

    public void RefreshLocalizedDefaults()
    {
        if (string.IsNullOrEmpty(_regionalPercentText))
        {
            RegionalPercentText = Strings.FormatPercent(0, 0).Formatted;
        }
    }

    public void ApplyActivatedCode(string validatedEnglishCode)
    {
        CodeInput = validatedEnglishCode;
        ValidationMessage = string.Empty;
    }

    public void BeginConnecting(string displayEnglishCode)
    {
        ConnectingCode = displayEnglishCode;
        ValidationMessage = string.Empty;
        OfferFiles.Clear();
        OfferTitle = string.Empty;
        OfferSummary = string.Empty;
        OfferMoreText = string.Empty;
        VerificationWords = string.Empty;
        DoneBytes = 0;
        TotalBytes = 0;
        WholePercent = 0;
        RegionalPercentText = Strings.FormatPercent(0, 0).Formatted;
        FormattedProgressBytes = string.Empty;
        ResultTitle = string.Empty;
        ResultBody = string.Empty;
        SavedToFolder = string.Empty;
        RawReceivedText = string.Empty;
        DisplayReceivedText = string.Empty;
        ReceivedTextShortened = false;
        ReceivedTextHidden = false;
        TextCopiedFeedbackVisible = false;
        ErrorSummary = string.Empty;
        ErrorCauseDetail = string.Empty;
        ErrorTechnicalEnglish = string.Empty;
        ShowErrorDetails = false;
        Phase = ReceivePhase.Connecting;
    }

    public void BeginTransferring()
    {
        DoneBytes = 0;
        WholePercent = 0;
        RegionalPercentText = Strings.FormatPercent(0, 0).Formatted;
        FormattedProgressBytes = string.Empty;
        Phase = ReceivePhase.Transferring;
    }

    public void ApplySessionEvent(SessionEventDto ev)
    {
        switch (ev.Event)
        {
            case "offer_ready":
                IsTextOffer = ev.IsText == true;
                DoneBytes = 0;
                TotalBytes = ev.TotalBytes ?? 0;
                OfferTitle = _isTextOffer ? Strings.ReceiveOfferText : Strings.ReceiveOffer;
                VerificationWords = ev.JoinedWordsLtr ?? string.Empty;

                OfferFiles.Clear();
                if (!_isTextOffer && ev.TopLevelSanitized is { Length: > 0 } sanitizedNames)
                {
                    int shown = Math.Min(5, sanitizedNames.Length);
                    for (int i = 0; i < shown; i++)
                    {
                        OfferFiles.Add(new OfferFileItemModel(sanitizedNames[i]));
                    }
                }

                ulong moreCount = ev.MoreCount ?? 0;
                OfferMoreText = !_isTextOffer && moreCount > 0
                    ? Strings.FormatMessage("receiveAndMore", MessageArg.FromCount("count", moreCount))
                    : string.Empty;

                ulong offerFileCount = ev.Files ?? 0;
                string formattedTotal = ev.FormattedTotal ?? Strings.FormatBytes(ev.TotalBytes ?? 0);
                if (_isTextOffer)
                {
                    OfferSummary = formattedTotal;
                }
                else
                {
                    OfferSummary = Strings.FormatMessage(
                        "receiveOfferSummary",
                        MessageArg.FromCount("files", offerFileCount),
                        MessageArg.FromText("size", formattedTotal));
                }

                Phase = ReceivePhase.Offer;
                BackgroundNotificationReady?.Invoke(new NotificationEventInput(
                    Role: TransferRole.Receive,
                    Stage: TransferLifecycleStage.Offer,
                    WindowActive: false,
                    IsText: _isTextOffer,
                    OfferFiles: offerFileCount,
                    ByteCount: ev.TotalBytes ?? 0,
                    FormattedBytes: formattedTotal));
                break;

            case "progress":
                if (ev.DoneBytes.HasValue)
                {
                    DoneBytes = ev.DoneBytes.Value;
                }

                if (ev.TotalBytes.HasValue)
                {
                    TotalBytes = ev.TotalBytes.Value;
                }

                if (ev.Percent is not null)
                {
                    WholePercent = ev.Percent.Whole;
                    RegionalPercentText = ev.Percent.Formatted;
                }

                FormattedProgressBytes = !string.IsNullOrEmpty(ev.FormattedDone) && !string.IsNullOrEmpty(ev.FormattedTotal)
                    ? $"{ev.FormattedDone} / {ev.FormattedTotal}"
                    : string.Empty;
                Phase = ReceivePhase.Transferring;
                break;

            case "done":
                WholePercent = 100;
                RegionalPercentText = Strings.FormatPercent(1, 1).Formatted;
                bool isTextReceive = ev.IsText == true;
                if (isTextReceive)
                {
                    IsTextOffer = true;
                    ResultTitle = Strings.ReceiveTextDone;
                    RawReceivedText = ev.ReceivedText ?? string.Empty;
                    DisplayReceivedText = ev.SanitizedText?.DisplayText
                        ?? TrySanitizeReceivedTextFallback(RawReceivedText);
                    ReceivedTextShortened = ev.SanitizedText?.Shortened == true;
                    ReceivedTextHidden = ev.SanitizedText?.HasHiddenControls == true;
                    SavedToFolder = string.Empty;
                    ResultBody = string.Empty;
                }
                else
                {
                    IsTextOffer = false;
                    ResultTitle = Strings.ReceiveDone;
                    SavedToFolder = ev.SavedTo ?? DestinationFolder;
                    string savedLine = Strings.FormatMessage(
                        "receiveSaveTo",
                        MessageArg.FromText("folder", SavedToFolder));
                    ulong failedCount = ev.FilesFailed ?? 0;
                    if (failedCount > 0)
                    {
                        string failPart = Strings.FormatMessage(
                            "sendSomeFailed",
                            MessageArg.FromCount("count", failedCount));
                        savedLine = $"{savedLine} {failPart}";
                    }

                    ResultBody = savedLine;
                }

                Phase = ReceivePhase.Done;
                BackgroundNotificationReady?.Invoke(new NotificationEventInput(
                    Role: TransferRole.Receive,
                    Stage: TransferLifecycleStage.Done,
                    WindowActive: false,
                    IsText: isTextReceive,
                    FilesOk: ev.FilesOk ?? 0,
                    FilesFailed: ev.FilesFailed ?? 0,
                    ByteCount: ev.Bytes ?? TotalBytes,
                    FormattedBytes: ev.FormattedBytes,
                    SavedToFolder: SavedToFolder));
                break;

            case "declined":
                IsTextOffer = ev.IsText == true;
                ResultTitle = string.IsNullOrEmpty(ev.Summary)
                    ? (_isTextOffer ? Strings.ReceiveTextDeclined : Strings.ReceiveDeclined)
                    : ev.Summary;
                Phase = ReceivePhase.Declined;
                BackgroundNotificationReady?.Invoke(new NotificationEventInput(
                    Role: TransferRole.Receive,
                    Stage: TransferLifecycleStage.Declined,
                    WindowActive: false,
                    IsText: _isTextOffer,
                    ErrorL10nKey: ev.L10nKey,
                    LocalizedErrorSummary: ev.Summary));
                break;

            case "failed":
                ErrorSummary = string.IsNullOrEmpty(ev.Summary) ? Strings.ErrorOther : ev.Summary;
                ErrorCauseDetail = ev.CauseDetail ?? string.Empty;
                ErrorTechnicalEnglish = ev.TechnicalEnglish ?? string.Empty;
                ShowErrorDetails = false;
                Phase = ReceivePhase.Failed;
                BackgroundNotificationReady?.Invoke(new NotificationEventInput(
                    Role: TransferRole.Receive,
                    Stage: TransferLifecycleStage.Failed,
                    WindowActive: false,
                    IsText: _isTextOffer,
                    ErrorL10nKey: ev.L10nKey,
                    LocalizedErrorSummary: ErrorSummary));
                break;
        }
    }

    public void ResetToIdle(bool clearCode)
    {
        if (clearCode)
        {
            CodeInput = string.Empty;
        }

        ConnectingCode = string.Empty;
        ValidationMessage = string.Empty;
        IsTextOffer = false;
        OfferTitle = string.Empty;
        OfferSummary = string.Empty;
        OfferMoreText = string.Empty;
        OfferFiles.Clear();
        VerificationWords = string.Empty;
        DoneBytes = 0;
        TotalBytes = 0;
        WholePercent = 0;
        RegionalPercentText = Strings.FormatPercent(0, 0).Formatted;
        FormattedProgressBytes = string.Empty;
        ResultTitle = string.Empty;
        ResultBody = string.Empty;
        SavedToFolder = string.Empty;
        RawReceivedText = string.Empty;
        DisplayReceivedText = string.Empty;
        ReceivedTextShortened = false;
        ReceivedTextHidden = false;
        TextCopiedFeedbackVisible = false;
        ErrorSummary = string.Empty;
        ErrorCauseDetail = string.Empty;
        ErrorTechnicalEnglish = string.Empty;
        ShowErrorDetails = false;
        ActiveSessionId = 0;
        Phase = ReceivePhase.Idle;
    }

    private void NotifyPhaseProperties()
    {
        NotifyChanged(nameof(CanConnect));
        NotifyChanged(nameof(IsTransferRunning));
        NotifyChanged(nameof(IsReceivedTextVisible));
        NotifyChanged(nameof(IdleVisibility));
        NotifyChanged(nameof(ConnectingVisibility));
        NotifyChanged(nameof(OfferCardVisibility));
        NotifyChanged(nameof(OfferDestinationVisibility));
        NotifyChanged(nameof(OfferTextNoteVisibility));
        NotifyChanged(nameof(VerificationVisibility));
        NotifyChanged(nameof(ProgressVisibility));
        NotifyChanged(nameof(DoneFilesVisibility));
        NotifyChanged(nameof(DoneTextVisibility));
        NotifyChanged(nameof(DeclinedVisibility));
        NotifyChanged(nameof(FailedVisibility));
    }

    private static string TrySanitizeReceivedTextFallback(string raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return string.Empty;
        }

        try
        {
            return NativeBridge.TrySanitizeText(raw)?.DisplayText ?? string.Empty;
        }
        catch (DllNotFoundException)
        {
            return string.Empty;
        }
    }
}

/// <summary>
/// ViewModel for <c>Views/SettingsPage.xaml</c> bound purely via <c>x:Bind</c>.
/// </summary>
[GeneratedBindableCustomProperty]
public sealed partial class SettingsViewModel : ObservableViewModel
{
    private string _serverUrlInput;
    private string _savedServerUrl;
    private string _serverUrlError = string.Empty;
    private bool _privacyModeEnabled;

    public SettingsViewModel(UiStringsViewModel? strings = null, SettingsStore? store = null)
    {
        Strings = strings ?? new UiStringsViewModel();
        Store = store ?? new SettingsStore();
        _savedServerUrl = Store.Current.RendezvousServer;
        _serverUrlInput = _savedServerUrl;
        _privacyModeEnabled = Store.Current.PrivacyRelayOnly;
    }

    public UiStringsViewModel Strings { get; }

    public SettingsStore Store { get; }

    public Action? RequestNavigateBack { get; set; }

    public string ServerUrlInput
    {
        get => _serverUrlInput;
        set
        {
            if (SetField(ref _serverUrlInput, value))
            {
                ServerUrlError = string.Empty;
                NotifyChanged(nameof(CanSaveServer));
                NotifyChanged(nameof(HasUnsavedServerEdit));
            }
        }
    }

    public string SavedServerUrl
    {
        get => _savedServerUrl;
        private set
        {
            if (SetField(ref _savedServerUrl, value))
            {
                NotifyChanged(nameof(CanSaveServer));
                NotifyChanged(nameof(CanResetServer));
                NotifyChanged(nameof(HasUnsavedServerEdit));
            }
        }
    }

    public string ServerUrlError
    {
        get => _serverUrlError;
        private set
        {
            if (SetField(ref _serverUrlError, value))
            {
                NotifyChanged(nameof(ServerUrlErrorVisibility));
            }
        }
    }

    public bool PrivacyModeEnabled
    {
        get => _privacyModeEnabled;
        private set => SetField(ref _privacyModeEnabled, value);
    }

    public bool CanSaveServer =>
        !string.Equals(_serverUrlInput.Trim(), _savedServerUrl, StringComparison.Ordinal);

    public bool CanResetServer =>
        !string.Equals(_savedServerUrl, SettingsStore.DefaultRendezvousServer, StringComparison.Ordinal);

    public bool HasUnsavedServerEdit =>
        !string.Equals(_serverUrlInput, _savedServerUrl, StringComparison.Ordinal);

    public Visibility DraftBannerVisibility =>
        Strings.HasDraftTranslations ? Visibility.Visible : Visibility.Collapsed;

    public Visibility ServerUrlErrorVisibility =>
        string.IsNullOrEmpty(_serverUrlError) ? Visibility.Collapsed : Visibility.Visible;

    public void RefreshDraftBanner()
    {
        NotifyChanged(nameof(DraftBannerVisibility));
    }

    public bool TrySaveServerUrl()
    {
        if (Store.TrySaveServerUrl(_serverUrlInput, out string? errorKey))
        {
            SavedServerUrl = Store.Current.RendezvousServer;
            ServerUrlInput = _savedServerUrl;
            ServerUrlError = string.Empty;
            return true;
        }

        ServerUrlError = errorKey == "errorStorage"
            ? Strings.FormatMessage("errorStorage")
            : Strings.SettingsServerInvalid;
        return false;
    }

    public bool TryResetServerUrl()
    {
        if (Store.TryResetServerUrl())
        {
            SavedServerUrl = Store.Current.RendezvousServer;
            ServerUrlInput = _savedServerUrl;
            ServerUrlError = string.Empty;
            return true;
        }

        ServerUrlError = Strings.FormatMessage("errorStorage");
        return false;
    }

    public void RevertServerUrlEdit()
    {
        ServerUrlInput = _savedServerUrl;
        ServerUrlError = string.Empty;
    }

    public bool TrySetPrivacyMode(bool enabled)
    {
        if (Store.TrySetPrivacyMode(enabled))
        {
            PrivacyModeEnabled = enabled;
            return true;
        }

        return false;
    }
}
