// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end integration tests for single-instance Windows Named Pipe IPC
//! framing, `WinUiWindowRouter` busy-window collision protection across
//! locales, NDJSON view-model snapshots, regional `#483` progress formatting,
//! `Kose` mark reduced-motion gating, and `WindowsCancellationToken`
//! cancellation semantics.

use std::error::Error as StdError;
use std::time::Duration;

use tokio::net::TcpListener;
use totaldrop_core::{Error as CoreError, Event};
use totaldrop_windows_bridge::{
    ActivationEnvelope, ActivationError, BridgeNetworkConfig, IpcFrameDecoder, MARK_CYCLE_MS,
    MARK_HEX_DARK, MARK_HEX_LIGHT, MAX_IPC_FRAME_BYTES, RegionalPercent, RouterDecision,
    ScreenTarget, TransferViewEvent, ValidatedCode, WinUiBridgeMessage, WinUiFlowDirection,
    WinUiWindowRouter, WindowsActivityState, WindowsCancellationToken, WindowsLocalizer,
    WindowsSelectionPath, connect_windows_receive, decode_ndjson_stream, encode_ndjson_batch,
    prepare_windows_send, prepare_windows_text_send,
};

type TestResult = Result<(), Box<dyn StdError>>;

fn build_sample_envelopes() -> Result<Vec<ActivationEnvelope>, ActivationError> {
    let mut long_ntfs_path = String::from(r"D:\Engineering");
    for _ in 0..9 {
        long_ntfs_path.push_str(r"\release_candidate_verified_2026_artifact");
    }
    long_ntfs_path.push_str(r"\installer-arm64.msix");

    let explorer = ActivationEnvelope::explorer_send(
        [
            long_ntfs_path.as_str(),
            r"\\nas-corp\builds\TotalDrop_x64.msix",
        ],
        Some(4100),
    )?;
    let share_files = ActivationEnvelope::share_target(
        [r"C:\Users\Alice\Pictures\diagram.png"],
        None,
        Some(5200),
    )?;
    let share_text = ActivationEnvelope::share_target(
        Vec::<&str>::new(),
        Some("Shared design note\r\nwithspoof\u{202E}txt.exe".to_owned()),
        Some(5201),
    )?;
    let protocol_uri =
        ActivationEnvelope::protocol_uri("totaldrop://r/7-harbor-rocket", Some(6300))?;
    let open_settings = ActivationEnvelope::open_screen(ScreenTarget::Settings, Some(7400));

    Ok(vec![
        explorer,
        share_files,
        share_text,
        protocol_uri,
        open_settings,
    ])
}

#[test]
fn coalesced_and_single_byte_streaming_ipc_decoder_routes_multi_envelope_burst() -> TestResult {
    let expected_envelopes = build_sample_envelopes()?;
    let mut coalesced_wire = Vec::new();
    for env in &expected_envelopes {
        let frame = env.encode_ipc_frame()?;
        coalesced_wire.extend_from_slice(&frame);
    }

    // 1. Coalesced multi-frame burst: all 5 frames arrive in a single ReadFile buffer.
    let mut burst_decoder = IpcFrameDecoder::new();
    let decoded_burst = burst_decoder.push_bytes(&coalesced_wire)?;
    assert_eq!(decoded_burst, expected_envelopes);
    assert!(!burst_decoder.has_partial_frame());
    assert_eq!(burst_decoder.buffered_bytes(), 0);
    burst_decoder.finish_eof()?;

    // 2. 1-byte-at-a-time streaming through WinUiWindowRouter on session 7.
    let localizer = WindowsLocalizer::new(["en-US"], Some("en-US"));
    let mut router = WinUiWindowRouter::new(7, localizer, "0.2.0-beta.5", true);
    assert_eq!(router.session_id(), 7);
    assert_eq!(
        router.pipe_path(),
        r"\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.7"
    );

    let mut streamed_decisions = Vec::new();
    for byte in &coalesced_wire {
        let decisions = router.ingest_ipc_bytes(std::slice::from_ref(byte))?;
        streamed_decisions.extend(decisions);
    }
    assert!(!router.decoder().has_partial_frame());
    assert_eq!(streamed_decisions.len(), 5);

    // Verify each routed outcome in order.
    let mut iter = streamed_decisions.into_iter();
    match iter.next().ok_or("missing decision 0")? {
        RouterDecision::NavigateSendFiles {
            paths,
            initiator_pid,
        } => {
            assert_eq!(paths.len(), 2);
            assert_eq!(initiator_pid, Some(4100));
            let first = paths.first().ok_or("missing long path")?;
            assert!(first.exceeds_legacy_max_path());
            assert!(first.extended_path().starts_with(r"\\?\D:\Engineering\"));
        }
        other => return Err(format!("unexpected decision 0: {other:?}").into()),
    }

    match iter.next().ok_or("missing decision 1")? {
        RouterDecision::NavigateSendFiles {
            paths,
            initiator_pid,
        } => {
            assert_eq!(paths.len(), 1);
            assert_eq!(initiator_pid, Some(5200));
        }
        other => return Err(format!("unexpected decision 1: {other:?}").into()),
    }

    match iter.next().ok_or("missing decision 2")? {
        RouterDecision::NavigateSendText {
            raw_text,
            sanitized_preview,
            initiator_pid,
        } => {
            assert_eq!(initiator_pid, Some(5201));
            assert!(raw_text.contains('\u{202E}'));
            assert!(sanitized_preview.has_hidden_controls);
            assert!(sanitized_preview.display_text.contains("<U+202E>"));
        }
        other => return Err(format!("unexpected decision 2: {other:?}").into()),
    }

    match iter.next().ok_or("missing decision 3")? {
        RouterDecision::NavigateReceiveCode {
            code,
            initiator_pid,
        } => {
            assert_eq!(code.display_english, "7-harbor-rocket");
            assert_eq!(code.canonical, "7-840-1499");
            assert_eq!(initiator_pid, Some(6300));
        }
        other => return Err(format!("unexpected decision 3: {other:?}").into()),
    }

    match iter.next().ok_or("missing decision 4")? {
        RouterDecision::SwitchScreen {
            screen,
            initiator_pid,
        } => {
            assert_eq!(screen, ScreenTarget::Settings);
            assert_eq!(initiator_pid, Some(7400));
        }
        other => return Err(format!("unexpected decision 4: {other:?}").into()),
    }

    // 3. Odd 7-byte chunks and clean EOF truncation detection.
    let mut chunk_decoder = IpcFrameDecoder::new();
    let mut chunked_out = Vec::new();
    for piece in coalesced_wire.chunks(7) {
        chunked_out.extend(chunk_decoder.push_bytes(piece)?);
    }
    assert_eq!(chunked_out, expected_envelopes);

    // Truncated stream disconnecting mid-frame must error on finish_eof.
    let single_frame = expected_envelopes
        .first()
        .ok_or("missing sample envelope")?
        .encode_ipc_frame()?;
    let (partial_prefix, _) = single_frame
        .split_at_checked(6)
        .ok_or("frame shorter than 6 bytes")?;
    assert!(chunk_decoder.push_bytes(partial_prefix)?.is_empty());
    assert!(chunk_decoder.has_partial_frame());
    assert_eq!(
        chunk_decoder.finish_eof(),
        Err(ActivationError::MalformedIpcFrame)
    );
    assert!(!chunk_decoder.has_partial_frame());

    Ok(())
}

#[test]
fn oversized_length_header_rejected_immediately_without_heap_allocation() -> TestResult {
    let just_over_limit = u32::try_from(MAX_IPC_FRAME_BYTES.saturating_add(1))?;

    for bad_len in [just_over_limit, u32::MAX] {
        let header = bad_len.to_le_bytes();
        let expected_byte_len = usize::try_from(bad_len)?;

        // Case A: 4-byte header + trailing payload bytes delivered together.
        let mut wire = Vec::with_capacity(68);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[b'A'; 64]);

        let mut decoder = IpcFrameDecoder::new();
        assert_eq!(decoder.payload_capacity(), 0);
        let result = decoder.push_bytes(&wire);
        assert_eq!(
            result,
            Err(ActivationError::EnvelopeTooLarge {
                byte_len: expected_byte_len,
            })
        );
        assert_eq!(
            decoder.payload_capacity(),
            0,
            "oversized header must be rejected before allocating any payload buffer"
        );
        assert!(!decoder.has_partial_frame());

        // Case B: Streamed 1 byte at a time; bytes 1..=3 buffer only on the stack,
        // byte 4 rejects immediately with zero heap allocation.
        let mut streamed_decoder = IpcFrameDecoder::new();
        let (first_three, fourth_and_rest) =
            header.split_at_checked(3).ok_or("header must be 4 bytes")?;
        for b in first_three {
            assert!(
                streamed_decoder
                    .push_bytes(std::slice::from_ref(b))?
                    .is_empty()
            );
            assert_eq!(streamed_decoder.payload_capacity(), 0);
            assert!(streamed_decoder.has_partial_frame());
        }
        assert_eq!(
            streamed_decoder.push_bytes(fourth_and_rest),
            Err(ActivationError::EnvelopeTooLarge {
                byte_len: expected_byte_len,
            })
        );
        assert_eq!(streamed_decoder.payload_capacity(), 0);
        assert!(!streamed_decoder.has_partial_frame());

        // Decoder remains healthy for a valid frame right after rejecting the bad one.
        let valid = ActivationEnvelope::open_screen(ScreenTarget::Receive, None);
        let valid_frame = valid.encode_ipc_frame()?;
        let recovered = streamed_decoder.push_bytes(&valid_frame)?;
        assert_eq!(recovered, vec![valid]);
    }

    // Zero-length header is also rejected immediately without allocating.
    let mut zero_decoder = IpcFrameDecoder::new();
    assert_eq!(
        zero_decoder.push_bytes(&0u32.to_le_bytes()),
        Err(ActivationError::MalformedIpcFrame)
    );
    assert_eq!(zero_decoder.payload_capacity(), 0);

    Ok(())
}

#[test]
fn busy_window_collision_protection_across_en_us_tr_tr_and_rtl_ar_eg() -> TestResult {
    let explorer_frame =
        ActivationEnvelope::explorer_send([r"C:\Users\Alice\Documents\spec.pdf"], Some(10))?
            .encode_ipc_frame()?;
    let share_text_frame =
        ActivationEnvelope::share_target(Vec::<&str>::new(), Some("hello".to_owned()), Some(11))?
            .encode_ipc_frame()?;
    let uri_frame =
        ActivationEnvelope::protocol_uri("https://totaldrop.app/r#7-harbor-rocket", Some(12))?
            .encode_ipc_frame()?;

    let busy_states = [
        WindowsActivityState::PreparingSend,
        WindowsActivityState::WaitingForPeer {
            code: "7-harbor-rocket".to_owned(),
        },
        WindowsActivityState::ConnectingReceive {
            code: "7-harbor-rocket".to_owned(),
        },
        WindowsActivityState::OfferPromptPending,
        WindowsActivityState::Transferring {
            done_bytes: 250_000,
            total_bytes: 1_000_000,
        },
        WindowsActivityState::ShowingTextNote,
    ];

    let locales = [
        ("en-US", "en", WinUiFlowDirection::LeftToRight),
        ("tr-TR", "tr", WinUiFlowDirection::LeftToRight),
        ("ar-EG", "ar", WinUiFlowDirection::RightToLeft),
    ];

    let mut share_banners_by_lang = Vec::new();
    let mut link_banners_by_lang = Vec::new();

    for (bcp47, expected_lang, expected_flow) in locales {
        let localizer = WindowsLocalizer::new([bcp47], Some(bcp47));
        assert_eq!(localizer.language_tag(), expected_lang);
        assert_eq!(localizer.flow_direction(), expected_flow);

        let expected_share_busy = localizer.text("shareBusy");
        let expected_link_busy = localizer.text("linkBusy");
        assert!(!expected_share_busy.is_empty());
        assert!(!expected_link_busy.is_empty());
        assert_ne!(expected_share_busy, "shareBusy");
        assert_ne!(expected_link_busy, "linkBusy");

        if expected_lang == "ar" {
            assert!(
                expected_share_busy
                    .chars()
                    .any(|ch| ('\u{0600}'..='\u{06FF}').contains(&ch)),
                "Arabic shareBusy banner must contain Arabic script characters"
            );
            assert!(
                expected_link_busy
                    .chars()
                    .any(|ch| ('\u{0600}'..='\u{06FF}').contains(&ch)),
                "Arabic linkBusy banner must contain Arabic script characters"
            );
        }

        let mut router = WinUiWindowRouter::new(1, localizer, "0.2.0-beta.5", true);

        for state in &busy_states {
            let _ = router.set_activity(state.clone());
            assert!(router.activity().is_busy());

            // ExplorerSend while busy -> RejectBusy(shareBusy)
            let decisions_explorer = router.ingest_ipc_bytes(&explorer_frame)?;
            assert_eq!(
                decisions_explorer,
                vec![RouterDecision::RejectBusy {
                    localized_banner: expected_share_busy.clone(),
                }]
            );
            assert_eq!(router.activity(), state);

            // ShareTarget while busy -> RejectBusy(shareBusy)
            let decisions_share = router.ingest_ipc_bytes(&share_text_frame)?;
            assert_eq!(
                decisions_share,
                vec![RouterDecision::RejectBusy {
                    localized_banner: expected_share_busy.clone(),
                }]
            );
            assert_eq!(router.activity(), state);

            // ProtocolUri while busy -> RejectBusy(linkBusy)
            let decisions_uri = router.ingest_ipc_bytes(&uri_frame)?;
            assert_eq!(
                decisions_uri,
                vec![RouterDecision::RejectBusy {
                    localized_banner: expected_link_busy.clone(),
                }]
            );
            assert_eq!(router.activity(), state);
        }

        // Returning to Idle immediately restores normal navigation.
        let _ = router.set_activity(WindowsActivityState::Idle);
        assert!(router.activity().is_idle());
        let resumed = router.ingest_ipc_bytes(&uri_frame)?;
        assert_eq!(
            resumed,
            vec![RouterDecision::NavigateReceiveCode {
                code: ValidatedCode::from_activation_uri(
                    "https://totaldrop.app/r#7-harbor-rocket"
                )?,
                initiator_pid: Some(12),
            }]
        );

        share_banners_by_lang.push(expected_share_busy);
        link_banners_by_lang.push(expected_link_busy);
    }

    // Verify English, Turkish, and Arabic localized banners are all distinct.
    let en_share = share_banners_by_lang.first().ok_or("missing en share")?;
    let tr_share = share_banners_by_lang.get(1).ok_or("missing tr share")?;
    let ar_share = share_banners_by_lang.get(2).ok_or("missing ar share")?;
    assert_ne!(en_share, tr_share);
    assert_ne!(en_share, ar_share);
    assert_ne!(tr_share, ar_share);

    let en_link = link_banners_by_lang.first().ok_or("missing en link")?;
    let tr_link = link_banners_by_lang.get(1).ok_or("missing tr link")?;
    let ar_link = link_banners_by_lang.get(2).ok_or("missing ar link")?;
    assert_ne!(en_link, tr_link);
    assert_ne!(en_link, ar_link);
    assert_ne!(tr_link, ar_link);

    Ok(())
}

#[test]
fn ndjson_bridge_snapshots_regional_483_progress_and_kose_mark_animation_gating() -> TestResult {
    // English UI language paired with Turkish regional format (`tr-TR`, #483).
    let localizer = WindowsLocalizer::new(["en-US"], Some("tr-TR"));
    let mut router = WinUiWindowRouter::new(3, localizer, "0.2.0-beta.5", true);

    // Startup queued UiBundleReady + MarkAnimationState(animate: false).
    assert_eq!(router.pending_message_count(), 2);

    // WaitingForPeer does not rotate the Kose mark yet.
    let waiting_mark = router.set_activity(WindowsActivityState::WaitingForPeer {
        code: "7-harbor-rocket".to_owned(),
    });
    assert_eq!(
        waiting_mark,
        WinUiBridgeMessage::MarkAnimationState {
            animate: false,
            hex_light: MARK_HEX_LIGHT.to_owned(),
            hex_dark: MARK_HEX_DARK.to_owned(),
            cycle_ms: MARK_CYCLE_MS,
        }
    );

    let _ = router.on_core_event(Event::Waiting);
    let _ = router.on_core_event(Event::Connected {
        words: vec![
            "alpha".to_owned(),
            "bravo".to_owned(),
            "charlie".to_owned(),
            "delta".to_owned(),
        ],
    });

    // Regional #483 floor-rounding: 999,999 / 1,000,000 -> whole 99, "%99" in tr-TR.
    let progress_msg = router.on_core_event(Event::Progress {
        done: 999_999,
        total: 1_000_000,
    });
    assert_eq!(
        router.activity(),
        &WindowsActivityState::Transferring {
            done_bytes: 999_999,
            total_bytes: 1_000_000,
        }
    );
    assert_eq!(
        progress_msg,
        WinUiBridgeMessage::TransferEvent(TransferViewEvent::Progress {
            done_bytes: 999_999,
            total_bytes: 1_000_000,
            formatted_done: "1,0 MB".to_owned(),
            formatted_total: "1,0 MB".to_owned(),
            percent: RegionalPercent {
                whole: 99,
                formatted: "%99".to_owned(),
            },
        })
    );

    // Disabling Windows UISettings.AnimationsEnabled mid-transfer immediately
    // stops Kose mark rotation while preserving Transferring state.
    let reduced_motion_mark = router.set_animations_enabled(false);
    assert!(!router.animations_enabled());
    assert_eq!(
        reduced_motion_mark,
        WinUiBridgeMessage::MarkAnimationState {
            animate: false,
            hex_light: "#6D4AE0".to_owned(),
            hex_dark: "#A68BFF".to_owned(),
            cycle_ms: 3200,
        }
    );

    // Re-enabling Windows animations while still Transferring resumes rotation.
    let resumed_motion_mark = router.set_animations_enabled(true);
    assert_eq!(
        resumed_motion_mark,
        WinUiBridgeMessage::MarkAnimationState {
            animate: true,
            hex_light: "#6D4AE0".to_owned(),
            hex_dark: "#A68BFF".to_owned(),
            cycle_ms: 3200,
        }
    );

    // Final byte completes -> 100% ("%100" in tr-TR).
    let done_msg = router.on_core_event(Event::Progress {
        done: 1_000_000,
        total: 1_000_000,
    });
    assert_eq!(
        done_msg,
        WinUiBridgeMessage::TransferEvent(TransferViewEvent::Progress {
            done_bytes: 1_000_000,
            total_bytes: 1_000_000,
            formatted_done: "1,0 MB".to_owned(),
            formatted_total: "1,0 MB".to_owned(),
            percent: RegionalPercent {
                whole: 100,
                formatted: "%100".to_owned(),
            },
        })
    );

    // Route one envelope while busy so RouteDecision(RejectBusy) is also in the NDJSON batch.
    let probe_env = ActivationEnvelope::open_screen(ScreenTarget::Receive, Some(99));
    let _ = router.route_envelope(probe_env);

    // Simulate a transfer error, resetting state to Idle and emitting TransferFailed.
    let err_msg = router.on_core_error(&CoreError::WrongCode);
    assert!(router.activity().is_idle());
    assert!(matches!(err_msg, WinUiBridgeMessage::TransferFailed(_)));

    // Drain NDJSON stream and verify round-trip fidelity across every variant.
    let ndjson = router.drain_ndjson()?;
    assert_eq!(router.pending_message_count(), 0);
    assert!(ndjson.ends_with('\n'));

    let line_count = ndjson.lines().count();
    assert!(line_count >= 10);

    let decoded = decode_ndjson_stream(&ndjson)?;
    assert_eq!(decoded.len(), line_count);

    // Re-encoding the decoded slice reproduces the exact NDJSON stream byte-for-byte.
    let reencoded = encode_ndjson_batch(&decoded)?;
    assert_eq!(reencoded, ndjson);

    // Verify all 5 WinUiBridgeMessage variants appeared in the stream.
    assert!(
        decoded
            .iter()
            .any(|m| matches!(m, WinUiBridgeMessage::UiBundleReady(_)))
    );
    assert!(
        decoded
            .iter()
            .any(|m| matches!(m, WinUiBridgeMessage::RouteDecision(_)))
    );
    assert!(
        decoded
            .iter()
            .any(|m| matches!(m, WinUiBridgeMessage::TransferEvent(_)))
    );
    assert!(
        decoded
            .iter()
            .any(|m| matches!(m, WinUiBridgeMessage::TransferFailed(_)))
    );
    assert!(decoded.iter().any(|m| matches!(
        m,
        WinUiBridgeMessage::MarkAnimationState { animate: true, .. }
    )));

    Ok(())
}

#[tokio::test]
async fn cancellation_token_pre_cancelled_and_inflight_returns_stopped_immediately() -> TestResult {
    // 1. Pre-cancelled token via `WindowsCancellationToken::cancelled()` and `.cancel()`
    //    must short-circuit before touching filesystem or network.
    let pre_cancelled = WindowsCancellationToken::cancelled();
    assert!(pre_cancelled.is_cancelled());
    tokio::time::timeout(Duration::from_millis(50), pre_cancelled.wait_cancelled()).await?;

    let token_pair = WindowsCancellationToken::new();
    let cloned_observer = token_pair.clone();
    assert!(!token_pair.is_cancelled());
    assert!(!cloned_observer.is_cancelled());
    token_pair.cancel();
    assert!(token_pair.is_cancelled());
    assert!(cloned_observer.is_cancelled());

    let cfg = BridgeNetworkConfig::default();
    let sample_win_path = WindowsSelectionPath::parse(r"C:\Users\Alice\Documents\nonexistent.bin")?;

    let send_err = prepare_windows_send(&cfg, [&sample_win_path], &pre_cancelled).await;
    assert!(
        matches!(send_err, Err(CoreError::Stopped)),
        "expected Stopped for pre-cancelled prepare_windows_send, got {send_err:?}"
    );

    let text_err =
        prepare_windows_text_send(&cfg, "hello windows", "note.txt", &cloned_observer).await;
    assert!(
        matches!(text_err, Err(CoreError::Stopped)),
        "expected Stopped for pre-cancelled prepare_windows_text_send, got {text_err:?}"
    );

    let recv_err =
        connect_windows_receive(&cfg, "totaldrop://r/7-harbor-rocket", &pre_cancelled).await;
    assert!(
        matches!(recv_err, Err(CoreError::Stopped)),
        "expected Stopped for pre-cancelled connect_windows_receive, got {recv_err:?}"
    );

    // 2. Uncancelled token rejects malformed user code before opening sockets.
    let active_token = WindowsCancellationToken::new();
    let bad_code_res = connect_windows_receive(&cfg, "0-harbor-rocket", &active_token).await;
    assert!(
        matches!(bad_code_res, Err(CoreError::Code(_))),
        "expected CoreError::Code on invalid nameplate, got {bad_code_res:?}"
    );

    // 3. Mid-flight cancellation against a stalled local loopback listener aborts
    //    both `prepare_windows_text_send` and `connect_windows_receive` promptly.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let hold_connections = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let loopback_cfg = BridgeNetworkConfig {
        rendezvous_server: format!("ws://127.0.0.1:{port}"),
        relay_server: String::new(),
        stun_server: String::new(),
        privacy_relay_only: false,
        stronger_three_word_code: false,
    };

    let inflight_send_token = WindowsCancellationToken::new();
    let cancel_send = inflight_send_token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        cancel_send.cancel();
    });
    let inflight_send_res = tokio::time::timeout(
        Duration::from_secs(2),
        prepare_windows_text_send(&loopback_cfg, "hello", "note.txt", &inflight_send_token),
    )
    .await?;
    assert!(
        matches!(inflight_send_res, Err(CoreError::Stopped)),
        "expected mid-flight send cancellation to return Stopped, got {inflight_send_res:?}"
    );

    let inflight_recv_token = WindowsCancellationToken::new();
    let cancel_recv = inflight_recv_token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        cancel_recv.cancel();
    });
    let inflight_recv_res = tokio::time::timeout(
        Duration::from_secs(2),
        connect_windows_receive(&loopback_cfg, "7-harbor-rocket", &inflight_recv_token),
    )
    .await?;
    assert!(
        matches!(inflight_recv_res, Err(CoreError::Stopped)),
        "expected mid-flight receive cancellation to return Stopped, got {inflight_recv_res:?}"
    );

    hold_connections.abort();
    Ok(())
}

#[test]
fn router_finish_ipc_eof_validates_clean_boundary_and_resets_truncated_streams() -> TestResult {
    let localizer = WindowsLocalizer::new(["en-US"], Some("en-US"));
    let mut router = WinUiWindowRouter::new(1, localizer, "0.1.0-beta.1", true);

    // Clean boundary on idle decoder succeeds.
    assert!(router.finish_ipc_eof().is_ok());

    // Valid complete frame followed by clean EOF succeeds.
    let ok_frame =
        ActivationEnvelope::open_screen(ScreenTarget::Receive, Some(7)).encode_ipc_frame()?;
    let decisions = router.ingest_ipc_bytes(&ok_frame)?;
    assert_eq!(decisions.len(), 1);
    assert!(router.finish_ipc_eof().is_ok());

    // Truncated 2-byte header triggers MalformedIpcFrame on EOF and resets decoder.
    assert!(router.ingest_ipc_bytes(&[0x10, 0x00])?.is_empty());
    assert!(matches!(
        router.finish_ipc_eof(),
        Err(ActivationError::MalformedIpcFrame)
    ));
    assert!(!router.decoder().has_partial_frame());

    // Truncated payload (declared 100 bytes, only 40 delivered) triggers MalformedIpcFrame on EOF and resets.
    let mut partial = Vec::with_capacity(44);
    partial.extend_from_slice(&100u32.to_le_bytes());
    partial.extend_from_slice(&[b' '; 40]);
    assert!(router.ingest_ipc_bytes(&partial)?.is_empty());
    assert!(matches!(
        router.finish_ipc_eof(),
        Err(ActivationError::MalformedIpcFrame)
    ));
    assert!(!router.decoder().has_partial_frame());

    // Subsequent valid frame decodes cleanly after EOF reset.
    let recovered = router.ingest_ipc_bytes(&ok_frame)?;
    assert_eq!(recovered.len(), 1);
    assert!(router.finish_ipc_eof().is_ok());

    Ok(())
}
