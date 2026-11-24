// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later

using System.Reflection;
using System.Xml.Linq;
using TotalDrop.WinUI.Interop;
using TotalDrop.WinUI.Services;
using Xunit;

namespace TotalDrop.WinUI.Tests;

public sealed class NotificationPlannerTests
{
    /// <summary>
    /// Live Rust-FFI-backed <see cref="INotificationLocalizer"/> exercising real
    /// <c>totaldrop_windows_ffi</c> localization, byte formatting, and Bidi filename sanitization.
    /// </summary>
    private sealed class RustBackedNotificationLocalizer(string langTag = "en-US", string regionTag = "en-US")
        : INotificationLocalizer
    {
        public string SendDone => FormatMessage("sendDone");

        public string SendTextDone => FormatMessage("sendTextDone");

        public string ReceiveOffer => FormatMessage("receiveOffer");

        public string ReceiveOfferText => FormatMessage("receiveOfferText");

        public string ReceiveDone => FormatMessage("receiveDone");

        public string ReceiveTextDone => FormatMessage("receiveTextDone");

        public string ReceiveDeclined => FormatMessage("receiveDeclined");

        public string ReceiveTextDeclined => FormatMessage("receiveTextDeclined");

        public string ErrorTextDamaged => FormatMessage("errorTextDamaged");

        public string ErrorOther => FormatMessage("errorOther");

        public string FormatMessage(string key, params MessageArg[] args)
        {
            if (NativeBridge.TryFormatMessage(key, args, langTag, regionTag, out string formatted, out _))
            {
                return formatted;
            }

            return string.Empty;
        }

        public string FormatBytes(ulong bytes) =>
            NativeBridge.TryFormatBytes(bytes, langTag, regionTag)?.Formatted ?? $"{bytes} B";

        public string SanitizeFilename(string rawFilename) =>
            NativeBridge.TrySanitizeFilename(rawFilename)?.Sanitized ?? rawFilename;
    }

    private static XDocument ParseAndAssertToastStructure(string xmlPayload)
    {
        XDocument doc = XDocument.Parse(xmlPayload);
        Assert.Equal("toast", doc.Root?.Name.LocalName);
        Assert.Equal("activate", doc.Root?.Attribute("launch")?.Value);
        XElement? binding = doc.Root?.Element("visual")?.Element("binding");
        Assert.NotNull(binding);
        Assert.Equal("ToastGeneric", binding.Attribute("template")?.Value);
        XElement[] texts = binding.Elements("text").ToArray();
        Assert.Equal(2, texts.Length);
        Assert.All(texts, static t => Assert.False(string.IsNullOrWhiteSpace(t.Value)));
        return doc;
    }

    [Fact]
    public void T1_F19_02_BackgroundNotifications_AllSixTerminalAndOfferOutcomes()
    {
        RustBackedNotificationLocalizer loc = new("en-US", "en-US");

        // 1. Background Receive Offer (files)
        PlannedToastNotification? offerFiles = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Offer,
                WindowActive: false,
                IsText: false,
                OfferFiles: 3,
                ByteCount: 1_048_576),
            loc);
        Assert.NotNull(offerFiles);
        Assert.Equal(loc.ReceiveOffer, offerFiles.Title);
        Assert.Contains("3", offerFiles.Body, StringComparison.Ordinal);
        _ = ParseAndAssertToastStructure(offerFiles.XmlPayload);

        // 2. Background Receive Offer (text)
        PlannedToastNotification? offerText = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Offer,
                WindowActive: false,
                IsText: true,
                ByteCount: 512),
            loc);
        Assert.NotNull(offerText);
        Assert.Equal(loc.ReceiveOfferText, offerText.Title);
        Assert.Contains("512", offerText.Body, StringComparison.Ordinal);
        _ = ParseAndAssertToastStructure(offerText.XmlPayload);

        // 3. Background Send Done (files)
        PlannedToastNotification? sendDone = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Send,
                TransferLifecycleStage.Done,
                WindowActive: false,
                IsText: false,
                FilesOk: 2),
            loc);
        Assert.NotNull(sendDone);
        Assert.Equal(loc.SendDone, sendDone.Title);
        Assert.Contains("2", sendDone.Body, StringComparison.Ordinal);
        _ = ParseAndAssertToastStructure(sendDone.XmlPayload);

        // 4. Background Send Done (text ok + text verification failure parity with Main.qml:206)
        PlannedToastNotification? sendTextDone = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Send,
                TransferLifecycleStage.Done,
                WindowActive: false,
                IsText: true,
                FilesOk: 1),
            loc);
        Assert.NotNull(sendTextDone);
        Assert.Equal(loc.SendDone, sendTextDone.Title);
        Assert.Equal(loc.SendTextDone, sendTextDone.Body);
        _ = ParseAndAssertToastStructure(sendTextDone.XmlPayload);

        PlannedToastNotification? sendTextDamaged = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Send,
                TransferLifecycleStage.Done,
                WindowActive: false,
                IsText: true,
                FilesFailed: 1),
            loc);
        Assert.NotNull(sendTextDamaged);
        Assert.Equal("TotalDrop", sendTextDamaged.Title);
        Assert.Equal(loc.ErrorTextDamaged, sendTextDamaged.Body);
        _ = ParseAndAssertToastStructure(sendTextDamaged.XmlPayload);

        // 5. Background Receive Done (files + text)
        PlannedToastNotification? recvDone = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Done,
                WindowActive: false,
                IsText: false,
                SavedToFolder: "TotalDrop"),
            loc);
        Assert.NotNull(recvDone);
        Assert.Equal(loc.ReceiveDone, recvDone.Title);
        Assert.Contains("TotalDrop", recvDone.Body, StringComparison.Ordinal);
        _ = ParseAndAssertToastStructure(recvDone.XmlPayload);

        PlannedToastNotification? recvTextDone = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Done,
                WindowActive: false,
                IsText: true,
                ByteCount: 2048),
            loc);
        Assert.NotNull(recvTextDone);
        Assert.Equal(loc.ReceiveTextDone, recvTextDone.Title);
        _ = ParseAndAssertToastStructure(recvTextDone.XmlPayload);

        // 6. Background Declined & Failed
        PlannedToastNotification? declined = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Send,
                TransferLifecycleStage.Declined,
                WindowActive: false),
            loc);
        Assert.NotNull(declined);
        Assert.Equal("TotalDrop", declined.Title);
        _ = ParseAndAssertToastStructure(declined.XmlPayload);

        PlannedToastNotification? failed = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Failed,
                WindowActive: false,
                ErrorL10nKey: "errorWrongCode"),
            loc);
        Assert.NotNull(failed);
        Assert.Equal("TotalDrop", failed.Title);
        Assert.Equal(loc.FormatMessage("errorWrongCode"), failed.Body);
        _ = ParseAndAssertToastStructure(failed.XmlPayload);
    }

    [Fact]
    public void T1_F19_03_ToastTextSanitization_XmlEscapingAndRustBidiReveal()
    {
        RustBackedNotificationLocalizer loc = new("en-US", "en-US");
        string hostileFolder = "Downloads\\<script>&\"'\u202Etxt.exe";

        PlannedToastNotification? planned = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Done,
                WindowActive: false,
                IsText: false,
                SavedToFolder: hostileFolder),
            loc);

        Assert.NotNull(planned);
        Assert.DoesNotContain("\u202E", planned.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("\u202E", planned.XmlPayload, StringComparison.Ordinal);
        Assert.Contains("<U+202E>", planned.Body, StringComparison.Ordinal);

        // Raw XML must properly escape &, <, >, ", '
        Assert.Contains("&lt;script&gt;", planned.XmlPayload, StringComparison.Ordinal);
        Assert.Contains("&amp;", planned.XmlPayload, StringComparison.Ordinal);
        Assert.Contains("&quot;", planned.XmlPayload, StringComparison.Ordinal);
        Assert.Contains("&apos;", planned.XmlPayload, StringComparison.Ordinal);
        Assert.DoesNotContain("<script>", planned.XmlPayload, StringComparison.Ordinal);

        XDocument parsed = ParseAndAssertToastStructure(planned.XmlPayload);
        string decodedBody = parsed.Root!.Element("visual")!.Element("binding")!.Elements("text").ElementAt(1).Value;
        Assert.Contains("<U+202E>", decodedBody, StringComparison.Ordinal);
        Assert.Contains("<script>&\"'", decodedBody, StringComparison.Ordinal);
    }

    [Fact]
    public void T2_F19_01_ForegroundWindowActive_SuppressesAllNotifications()
    {
        RustBackedNotificationLocalizer loc = new("en-US", "en-US");

        foreach (TransferLifecycleStage stage in Enum.GetValues<TransferLifecycleStage>())
        {
            foreach (TransferRole role in Enum.GetValues<TransferRole>())
            {
                foreach (bool isText in new[] { false, true })
                {
                    PlannedToastNotification? planned = NotificationPlanner.TryPlan(
                        new NotificationEventInput(
                            role,
                            stage,
                            WindowActive: true,
                            IsText: isText,
                            FilesOk: 1,
                            OfferFiles: 1,
                            ByteCount: 1024,
                            SavedToFolder: "TotalDrop",
                            ErrorL10nKey: "errorWrongCode"),
                        loc);
                    Assert.Null(planned);
                }
            }
        }
    }

    [Fact]
    public void T2_F19_02_ProgressAndTransientStages_NeverEmitToastSpam()
    {
        RustBackedNotificationLocalizer loc = new("en-US", "en-US");
        TransferLifecycleStage[] nonToastStages =
        [
            TransferLifecycleStage.Idle,
            TransferLifecycleStage.Preparing,
            TransferLifecycleStage.Waiting,
            TransferLifecycleStage.Connected,
            TransferLifecycleStage.Transferring,
            TransferLifecycleStage.Connecting,
        ];

        foreach (TransferLifecycleStage stage in nonToastStages)
        {
            foreach (TransferRole role in Enum.GetValues<TransferRole>())
            {
                PlannedToastNotification? planned = NotificationPlanner.TryPlan(
                    new NotificationEventInput(
                        role,
                        stage,
                        WindowActive: false,
                        IsText: false,
                        ByteCount: 4096),
                    loc);
                Assert.Null(planned);
            }
        }
    }

    [Fact]
    public void T2_F19_03_PlainTextAndTechnicalEnglish_StructurallyCannotLeakIntoToasts()
    {
        // Structural proof: NotificationEventInput has NO property for raw text body or technical_english.
        string[] propNames = typeof(NotificationEventInput)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(static p => p.Name)
            .ToArray();

        Assert.DoesNotContain(propNames, static n => n.Contains("RawText", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(propNames, static n => n.Contains("PlainText", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(propNames, static n => n.Contains("TechnicalEnglish", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(propNames, static n => n.Contains("MessageText", StringComparison.OrdinalIgnoreCase));

        // Behavioral proof: text Offer & Done toasts only surface localized title + formatted byte size.
        RustBackedNotificationLocalizer loc = new("en-US", "en-US");
        PlannedToastNotification? recvTextDone = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Done,
                WindowActive: false,
                IsText: true,
                ByteCount: 128),
            loc);
        Assert.NotNull(recvTextDone);
        Assert.Contains("128", recvTextDone.Body, StringComparison.Ordinal);

        // Failure toast prefers localized ErrorL10nKey over any raw fallback text.
        PlannedToastNotification? failed = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Failed,
                WindowActive: false,
                ErrorL10nKey: "errorWrongCode",
                LocalizedErrorSummary: "SECRET_RAW_TECHNICAL_DIAGNOSTIC_CANARY"),
            loc);
        Assert.NotNull(failed);
        Assert.DoesNotContain("SECRET_RAW_TECHNICAL_DIAGNOSTIC_CANARY", failed.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("SECRET_RAW_TECHNICAL_DIAGNOSTIC_CANARY", failed.XmlPayload, StringComparison.Ordinal);
    }

    [Fact]
    public void T2_F19_04_HostileXmlAndControlChars_ProduceValidEscapedToastXml()
    {
        string hostileTitle = "TotalDrop ]]><toast><actions><action content=\"pwn\"/></actions>";
        string hostileBody = "Err \0\u0007\u001B\uD800\uFFFE\uFFFF <text>&\"'injection</text>";

        string xml = NotificationPlanner.BuildToastXml(hostileTitle, hostileBody);
        XDocument doc = ParseAndAssertToastStructure(xml);

        // Verify zero injected child elements beyond the 2 canonical <text> nodes.
        Assert.Empty(doc.Descendants("actions"));
        Assert.Empty(doc.Descendants("action"));
        Assert.Single(doc.Descendants("toast"));
        Assert.Equal(2, doc.Descendants("text").Count());
        Assert.DoesNotContain("\0", xml, StringComparison.Ordinal);
        Assert.DoesNotContain("\u001B", xml, StringComparison.Ordinal);
        Assert.DoesNotContain("\uFFFE", xml, StringComparison.Ordinal);
    }

    [Fact]
    public void T3_12_PartA_BackgroundToastSequence_OfferDoneFailedWithForegroundSuppression()
    {
        RustBackedNotificationLocalizer loc = new("en-US", "en-US");

        // 1. Background Receive Offer -> emits toast
        PlannedToastNotification? step1 = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Offer,
                WindowActive: false,
                OfferFiles: 2,
                ByteCount: 65_536),
            loc);
        Assert.NotNull(step1);
        _ = ParseAndAssertToastStructure(step1.XmlPayload);

        // 2. Background Transferring progress -> suppressed
        Assert.Null(NotificationPlanner.TryPlan(
            new NotificationEventInput(TransferRole.Receive, TransferLifecycleStage.Transferring, WindowActive: false),
            loc));

        // 3. User focuses window -> foreground Done suppressed
        Assert.Null(NotificationPlanner.TryPlan(
            new NotificationEventInput(TransferRole.Receive, TransferLifecycleStage.Done, WindowActive: true, SavedToFolder: "TotalDrop"),
            loc));

        // 4. Background Done with hostile folder name -> emits sanitized escaped XML toast
        PlannedToastNotification? step4 = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Done,
                WindowActive: false,
                SavedToFolder: "Drop<&>\u202Edir"),
            loc);
        Assert.NotNull(step4);
        Assert.DoesNotContain("\u202E", step4.XmlPayload, StringComparison.Ordinal);
        _ = ParseAndAssertToastStructure(step4.XmlPayload);

        // 5. Background Failed -> emits localized error toast
        PlannedToastNotification? step5 = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Send,
                TransferLifecycleStage.Failed,
                WindowActive: false,
                ErrorL10nKey: "errorWrongCode"),
            loc);
        Assert.NotNull(step5);
        Assert.Equal(loc.FormatMessage("errorWrongCode"), step5.Body);
        _ = ParseAndAssertToastStructure(step5.XmlPayload);
    }

    [Fact]
    public void Tier5_SendTextTooLong_ExpandsSizeAndDefensivelyFallsBackOnUnexpandedPlaceholders()
    {
        // 1. en-US: sendTextTooLong must expand {size} to localized NativeBridge.MaxTextBytes ("1 MB").
        RustBackedNotificationLocalizer enLoc = new("en-US", "en-US");
        string expectedEnSize = enLoc.FormatBytes(NativeBridge.MaxTextBytes);
        PlannedToastNotification? enToast = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Send,
                TransferLifecycleStage.Failed,
                WindowActive: false,
                IsText: true,
                ErrorL10nKey: "sendTextTooLong",
                LocalizedErrorSummary: "fallback summary"),
            enLoc);
        Assert.NotNull(enToast);
        Assert.Equal("TotalDrop", enToast.Title);
        Assert.Contains(expectedEnSize, enToast.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("{size}", enToast.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("{size}", enToast.XmlPayload, StringComparison.Ordinal);
        _ = ParseAndAssertToastStructure(enToast.XmlPayload);

        // 2. tr-TR: regional byte formatting with zero unexpanded {size}.
        RustBackedNotificationLocalizer trLoc = new("tr-TR", "tr-TR");
        string expectedTrSize = trLoc.FormatBytes(NativeBridge.MaxTextBytes);
        PlannedToastNotification? trToast = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Send,
                TransferLifecycleStage.Failed,
                WindowActive: false,
                IsText: true,
                ErrorL10nKey: "sendTextTooLong"),
            trLoc);
        Assert.NotNull(trToast);
        Assert.Contains(expectedTrSize, trToast.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("{size}", trToast.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("{size}", trToast.XmlPayload, StringComparison.Ordinal);
        _ = ParseAndAssertToastStructure(trToast.XmlPayload);

        // 3. Defensive fallback: parameterized key formatted with 0 args emits unexpanded {folder}
        // and must fall through to sanitized LocalizedErrorSummary (or ErrorOther when absent).
        PlannedToastNotification? fallbackSummary = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Failed,
                WindowActive: false,
                ErrorL10nKey: "receiveSaveTo",
                LocalizedErrorSummary: "Sanitized fallback summary"),
            enLoc);
        Assert.NotNull(fallbackSummary);
        Assert.Equal("Sanitized fallback summary", fallbackSummary.Body);
        Assert.DoesNotContain("{folder}", fallbackSummary.XmlPayload, StringComparison.Ordinal);

        PlannedToastNotification? fallbackErrorOther = NotificationPlanner.TryPlan(
            new NotificationEventInput(
                TransferRole.Receive,
                TransferLifecycleStage.Failed,
                WindowActive: false,
                ErrorL10nKey: "receiveSaveTo"),
            enLoc);
        Assert.NotNull(fallbackErrorOther);
        Assert.Equal(enLoc.ErrorOther, fallbackErrorOther.Body);
        Assert.DoesNotContain("{folder}", fallbackErrorOther.XmlPayload, StringComparison.Ordinal);
    }
}
