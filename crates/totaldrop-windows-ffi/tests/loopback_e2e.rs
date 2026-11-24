// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real end-to-end loopback transfer tests exercising the `extern "C"` ABI of
//! `totaldrop-windows-ffi` against Architecture B in-process MIT/Apache-2.0
//! loopback rendezvous and relay servers bound strictly to `127.0.0.1:0` and
//! `[::1]:0`.
//!
//! Zero live production endpoints are ever contacted.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::ffi::{CStr, CString, c_char};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use totaldrop_core::framing::write_frame;
use totaldrop_core::{pairing, path, rendezvous, secure, transport};
use totaldrop_crypto::cpace::Role;
use totaldrop_crypto::identity::DeviceKeys;
use totaldrop_crypto::{ContentKey, EntryCipher};
use totaldrop_proto::TransferCode;
use totaldrop_proto::limits;
use totaldrop_proto::relay as proto_relay;
use totaldrop_proto::wire::{
    Address, ClientMessage, Control, DataHeader, Entry, EntryKind, Hints, Manifest, Mood,
    ServerMessage,
};
use totaldrop_windows_ffi::{
    FFI_ERR_INVALID_HANDLE, FFI_OK, totaldrop_win_receive_accept_files,
    totaldrop_win_receive_accept_text, totaldrop_win_receive_connect_start,
    totaldrop_win_receive_decline, totaldrop_win_send_files_start, totaldrop_win_send_text_start,
    totaldrop_win_session_cancel, totaldrop_win_session_destroy,
    totaldrop_win_session_poll_events_ndjson, totaldrop_win_shutdown, totaldrop_win_string_free,
};

type TestResult = Result<(), Box<dyn StdError>>;

/// Coordinates tests that call global `totaldrop_win_shutdown` (write lock)
/// with concurrent loopback session tests (read lock) inside the same process.
static SHUTDOWN_GATE: LazyLock<RwLock<()>> = LazyLock::new(|| RwLock::new(()));

static TEST_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .thread_name("totaldrop-e2e-srv")
        .build()
        .unwrap_or_else(|_| std::process::abort())
});

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Result<Self, std::io::Error> {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("totaldrop-win-ffi-e2e-{prefix}-{pid}-{id}"));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn c_str(s: &str) -> Result<CString, Box<dyn StdError>> {
    Ok(CString::new(s)?)
}

fn poll_events(sid: u64) -> Result<Vec<Value>, Box<dyn StdError>> {
    let ptr = totaldrop_win_session_poll_events_ndjson(sid);
    if ptr.is_null() {
        return Err("poll returned null".into());
    }
    // SAFETY: `ptr` was returned by `totaldrop_win_session_poll_events_ndjson`.
    let raw = unsafe { CStr::from_ptr(ptr) }.to_str()?.to_owned();
    // SAFETY: Freed exactly once via `totaldrop_win_string_free`.
    unsafe { totaldrop_win_string_free(ptr) };

    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            out.push(serde_json::from_str(trimmed)?);
        }
    }
    Ok(out)
}

fn wait_for_event(
    sid: u64,
    all: &mut Vec<Value>,
    target_event: &str,
    timeout: Duration,
) -> Result<Value, Box<dyn StdError>> {
    let started = Instant::now();
    loop {
        let batch = poll_events(sid)?;
        for ev in batch {
            let matches = ev.get("event").and_then(Value::as_str) == Some(target_event);
            all.push(ev.clone());
            if matches {
                return Ok(ev);
            }
            if target_event != "failed" && ev.get("event").and_then(Value::as_str) == Some("failed")
            {
                return Err(format!(
                    "unexpected failed event while waiting for {target_event}: {ev}"
                )
                .into());
            }
        }
        if started.elapsed() >= timeout {
            return Err(
                format!("timed out waiting for event {target_event:?}; saw: {all:?}").into(),
            );
        }
        std::thread::sleep(Duration::from_millis(15));
    }
}

fn make_cfg_json(rendezvous_url: &str, relay_url: &str, privacy_relay_only: bool) -> String {
    json!({
        "rendezvous_server": rendezvous_url,
        "relay_server": relay_url,
        "stun_server": "",
        "privacy_relay_only": privacy_relay_only,
        "stronger_three_word_code": false
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Architecture B In-Process Loopback Rendezvous Server (MIT OR Apache-2.0)

#[derive(Clone, Debug)]
enum RendezvousFault {
    None,
    AlwaysError(String),
    ErrorAfterClaim(String),
}

struct MailboxSlot {
    token: [u8; 16],
    mailbox_id: [u8; 16],
    peers: Vec<mpsc::UnboundedSender<ServerMessage>>,
    buffered_for_second: Vec<ServerMessage>,
    retired: bool,
}

struct RendezvousState {
    next_nameplate: AtomicU32,
    boxes: Mutex<HashMap<u32, MailboxSlot>>,
    fault: RendezvousFault,
}

struct MockRendezvous {
    url: String,
    abort: tokio::task::AbortHandle,
}

impl Drop for MockRendezvous {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl MockRendezvous {
    fn start(bind_addr: &str, fault: RendezvousFault) -> Result<Self, Box<dyn StdError>> {
        let (url, abort) = TEST_RUNTIME.block_on(async move {
            let listener = TcpListener::bind(bind_addr).await?;
            let local: SocketAddr = listener.local_addr()?;
            let url = match local {
                SocketAddr::V4(v4) => format!("ws://{v4}"),
                SocketAddr::V6(v6) => format!("ws://[{}]:{}", v6.ip(), v6.port()),
            };
            let state = Arc::new(RendezvousState {
                next_nameplate: AtomicU32::new(7),
                boxes: Mutex::new(HashMap::new()),
                fault,
            });
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let st = Arc::clone(&state);
                    tokio::spawn(async move {
                        let _ = handle_rendezvous_conn(stream, st).await;
                    });
                }
            });
            Ok::<_, std::io::Error>((url, task.abort_handle()))
        })?;
        Ok(Self { url, abort })
    }
}

async fn handle_rendezvous_conn(
    stream: tokio::net::TcpStream,
    state: Arc<RendezvousState>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let mut ws = tokio_tungstenite::accept_async(stream).await?;

    if let RendezvousFault::AlwaysError(ref reason) = state.fault {
        let msg = ServerMessage::Error {
            reason: reason.clone(),
        };
        let _ = ws.send(Message::Binary(msg.encode().into())).await;
        let _ = ws.close(None).await;
        return Ok(());
    }

    let first_msg = loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => break ClientMessage::decode(&b)?,
            Some(Ok(Message::Ping(p))) => {
                let _ = ws.send(Message::Pong(p)).await;
            }
            _ => return Ok(()),
        }
    };

    match first_msg {
        ClientMessage::Allocate => {
            let nameplate = state.next_nameplate.fetch_add(1, Ordering::Relaxed);
            let mut token = [0u8; 16];
            let mut mailbox_id = [0u8; 16];
            for (idx, b) in token.iter_mut().enumerate() {
                *b = u8::try_from(idx.wrapping_add(nameplate as usize) & 0xFF).unwrap_or(1);
            }
            for (idx, b) in mailbox_id.iter_mut().enumerate() {
                *b = u8::try_from(idx.wrapping_mul(7).wrapping_add(nameplate as usize) & 0xFF)
                    .unwrap_or(2);
            }
            {
                let mut boxes = state.boxes.lock().await;
                boxes.insert(
                    nameplate,
                    MailboxSlot {
                        token,
                        mailbox_id,
                        peers: Vec::new(),
                        buffered_for_second: Vec::new(),
                        retired: false,
                    },
                );
            }
            let reply = ServerMessage::Allocated { nameplate, token };
            let _ = ws.send(Message::Binary(reply.encode().into())).await;
            let _ = ws.close(None).await;
        }
        ClientMessage::Claim { nameplate, token } => {
            let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
            let (mailbox_id, peer_index, replay) = {
                let mut boxes = state.boxes.lock().await;
                let Some(slot) = boxes.get_mut(&nameplate) else {
                    let err = ServerMessage::Error {
                        reason: "unknown nameplate".to_owned(),
                    };
                    let _ = ws.send(Message::Binary(err.encode().into())).await;
                    let _ = ws.close(None).await;
                    return Ok(());
                };
                if slot.retired {
                    let err = ServerMessage::Error {
                        reason: "mailbox expired".to_owned(),
                    };
                    let _ = ws.send(Message::Binary(err.encode().into())).await;
                    let _ = ws.close(None).await;
                    return Ok(());
                }
                if slot.peers.is_empty() {
                    if token != Some(slot.token) {
                        let err = ServerMessage::Error {
                            reason: "unknown nameplate".to_owned(),
                        };
                        let _ = ws.send(Message::Binary(err.encode().into())).await;
                        let _ = ws.close(None).await;
                        return Ok(());
                    }
                    slot.peers.push(tx);
                    (slot.mailbox_id, 0usize, Vec::new())
                } else if slot.peers.len() == 1 {
                    slot.peers.push(tx);
                    let replay = std::mem::take(&mut slot.buffered_for_second);
                    (slot.mailbox_id, 1usize, replay)
                } else {
                    let err = ServerMessage::Error {
                        reason: "nameplate full".to_owned(),
                    };
                    let _ = ws.send(Message::Binary(err.encode().into())).await;
                    let _ = ws.close(None).await;
                    return Ok(());
                }
            };

            let claimed = ServerMessage::Claimed {
                mailbox: mailbox_id,
            };
            ws.send(Message::Binary(claimed.encode().into())).await?;

            if let RendezvousFault::ErrorAfterClaim(ref reason) = state.fault {
                let err = ServerMessage::Error {
                    reason: reason.clone(),
                };
                let _ = ws.send(Message::Binary(err.encode().into())).await;
                let _ = ws.close(None).await;
                return Ok(());
            }

            for msg in replay {
                ws.send(Message::Binary(msg.encode().into())).await?;
            }

            loop {
                tokio::select! {
                    outgoing = rx.recv() => {
                        let Some(msg) = outgoing else { break; };
                        if ws.send(Message::Binary(msg.encode().into())).await.is_err() {
                            break;
                        }
                    }
                    incoming = ws.next() => {
                        match incoming {
                            Some(Ok(Message::Binary(b))) => {
                                let Ok(cmd) = ClientMessage::decode(&b) else { break; };
                                match cmd {
                                    ClientMessage::Add { phase, body } => {
                                        let forwarded = ServerMessage::Message { phase, body };
                                        let mut boxes = state.boxes.lock().await;
                                        if let Some(slot) = boxes.get_mut(&nameplate) {
                                            let other_idx = 1usize.saturating_sub(peer_index);
                                            if let Some(other) = slot.peers.get(other_idx) {
                                                let _ = other.send(forwarded);
                                            } else if peer_index == 0 {
                                                slot.buffered_for_second.push(forwarded);
                                            }
                                        }
                                    }
                                    ClientMessage::Close { mood } => {
                                        let mut boxes = state.boxes.lock().await;
                                        if let Some(slot) = boxes.get_mut(&nameplate) {
                                            if mood == Mood::Scary {
                                                slot.retired = true;
                                            }
                                            let other_idx = 1usize.saturating_sub(peer_index);
                                            if let Some(other) = slot.peers.get(other_idx) {
                                                let _ = other.send(ServerMessage::PeerClosed { mood });
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
                            Some(Ok(Message::Close(_))) | None => break,
                            _ => {}
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Architecture B In-Process Loopback Relay Server (MIT OR Apache-2.0)

#[derive(Clone, Copy)]
enum RelayMode {
    Normal,
    Throttled(Duration),
    DropOnConnect,
}

type RelayPeerMap = HashMap<[u8; 32], mpsc::UnboundedSender<Vec<u8>>>;
type RelayPairTable = HashMap<([u8; 32], [u8; 32]), RelayPeerMap>;

struct RelayState {
    mode: RelayMode,
    pairs: Mutex<RelayPairTable>,
}

struct MockRelay {
    url: String,
    abort: tokio::task::AbortHandle,
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl MockRelay {
    fn start(mode: RelayMode) -> Result<Self, Box<dyn StdError>> {
        let (url, abort) = TEST_RUNTIME.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let local = listener.local_addr()?;
            let url = format!("ws://{local}/v0/relay");
            let state = Arc::new(RelayState {
                mode,
                pairs: Mutex::new(HashMap::new()),
            });
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let st = Arc::clone(&state);
                    tokio::spawn(async move {
                        let _ = handle_relay_conn(stream, st).await;
                    });
                }
            });
            Ok::<_, std::io::Error>((url, task.abort_handle()))
        })?;
        Ok(Self { url, abort })
    }
}

#[allow(clippy::result_large_err)]
async fn handle_relay_conn(
    stream: tokio::net::TcpStream,
    state: Arc<RelayState>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let mut captured_path = String::new();
    let mut ws = tokio_tungstenite::accept_hdr_async(stream, |req: &Request, resp: Response| {
        captured_path = req.uri().path().to_owned();
        Ok(resp)
    })
    .await?;

    if matches!(state.mode, RelayMode::DropOnConnect) {
        let _ = ws.close(None).await;
        return Ok(());
    }

    let Some(pair_segment) = captured_path.rsplit('/').next() else {
        return Ok(());
    };
    let Some(pair) = proto_relay::parse_pair_name(pair_segment) else {
        return Ok(());
    };

    let nonce = [0x5Au8; 32];
    ws.send(Message::Binary(proto_relay::challenge(&nonce).into()))
        .await?;

    let hello_bytes = match ws.next().await {
        Some(Ok(Message::Binary(b))) => b,
        _ => return Ok(()),
    };
    let Some((key, sig)) = proto_relay::parse_hello(&hello_bytes) else {
        return Ok(());
    };
    if key != pair.0 && key != pair.1 {
        return Ok(());
    }
    let signed = proto_relay::signed_bytes(&nonce);
    if UnparsedPublicKey::new(&ED25519, &key)
        .verify(&signed, &sig)
        .is_err()
    {
        return Ok(());
    }

    ws.send(Message::Binary(proto_relay::ok().into())).await?;

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        let mut pairs = state.pairs.lock().await;
        pairs.entry(pair).or_default().insert(key, tx);
    }

    loop {
        tokio::select! {
            outbound = rx.recv() => {
                let Some(frame) = outbound else { break; };
                if let RelayMode::Throttled(delay) = state.mode {
                    tokio::time::sleep(delay).await;
                }
                if ws.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
            inbound = ws.next() => {
                match inbound {
                    Some(Ok(Message::Binary(b))) => {
                        if proto_relay::is_probe(&b) {
                            continue;
                        }
                        if b.len() < 35 {
                            continue;
                        }
                        let Some((dst_slice, rest)) = b.split_at_checked(32) else {
                            continue;
                        };
                        let Ok(dst): Result<[u8; 32], _> = dst_slice.try_into() else {
                            continue;
                        };
                        let mut delivered = Vec::with_capacity(b.len());
                        delivered.extend_from_slice(&key);
                        delivered.extend_from_slice(rest);
                        let pairs = state.pairs.lock().await;
                        if let Some(peer_tx) = pairs.get(&pair).and_then(|m| m.get(&dst)) {
                            let _ = peer_tx.send(delivered);
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = ws.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    let mut pairs = state.pairs.lock().await;
    if let Some(map) = pairs.get_mut(&pair) {
        map.remove(&key);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fault-Injecting Custom Sender (TextDamaged BLAKE3 / Invalid UTF-8 / AEAD Tamper)

#[derive(Clone, Copy)]
enum SenderFault {
    CorruptTextBlake3Hash,
    InvalidUtf8TextPayload,
    TamperOfferAeadTag,
}

async fn run_fault_sender(
    rendezvous_url: String,
    fault: SenderFault,
    code_tx: tokio::sync::oneshot::Sender<String>,
) -> Result<(), Box<dyn StdError + Send + Sync>> {
    let keys = DeviceKeys::generate()?;
    let alloc = rendezvous::allocate(&rendezvous_url).await?;
    let code = TransferCode::generate(alloc.nameplate, 2)?;
    let mailbox =
        rendezvous::Mailbox::claim(&rendezvous_url, alloc.nameplate, Some(&alloc)).await?;
    let mailbox_id = mailbox.id;
    let _ = code_tx.send(code.to_english());

    let socket = transport::bind_socket()?;
    let endpoint_key = Arc::new(transport::EndpointKey::generate()?);
    let hints = Hints {
        versions: pairing::VERSIONS.to_vec(),
        endpoint_key: endpoint_key.public(),
        public: Vec::new(),
        local: transport::local_addresses(&socket)?
            .into_iter()
            .map(Address)
            .collect(),
        relay: None,
    };
    let paired =
        pairing::exchange(mailbox, Role::Initiator, &code, mailbox_id, &keys, &hints).await?;
    let (endpoint, _pipes, _fallback) =
        transport::endpoint(socket, &endpoint_key, &paired.hints.endpoint_key)?;
    let peer_addrs: Vec<SocketAddr> = paired
        .hints
        .local
        .iter()
        .map(|a| path::canonical(a.0))
        .collect();
    let paths = transport::Paths {
        direct: peer_addrs,
        relay: None,
        relay_only: false,
    };
    let (conn, send, recv) =
        transport::sender_connection(&endpoint, &paths, Duration::from_secs(15)).await?;
    let mut chan = secure::handshake_on(
        send,
        recv,
        secure::HandshakeInput {
            keys: &keys,
            peer: &paired.peer,
            psk: paired.psk,
            mailbox_id: paired.mailbox_id,
        },
        false,
    )
    .await?;

    let transfer_id = totaldrop_crypto::new_transfer_id()?;
    let ck = ContentKey::generate()?;
    let payload: Vec<u8> = match fault {
        SenderFault::CorruptTextBlake3Hash => b"valid utf-8 text".to_vec(),
        SenderFault::InvalidUtf8TextPayload => vec![0xFF, 0xFE],
        SenderFault::TamperOfferAeadTag => b"tampered offer".to_vec(),
    };
    let mut hash = *blake3::hash(&payload).as_bytes();
    if matches!(fault, SenderFault::CorruptTextBlake3Hash)
        && let Some(first) = hash.first_mut()
    {
        *first ^= 0x01;
    }

    let entry = Entry {
        path: vec!["text.txt".to_owned()],
        kind: EntryKind::File,
        size: u64::try_from(payload.len()).unwrap_or(0),
        hash: Some(hash),
        mtime: None,
    };
    let manifest = Manifest {
        transfer_id,
        entries: vec![entry],
        total_size: u64::try_from(payload.len()).unwrap_or(0),
        chunk_size: limits::CHUNK_SIZE,
    };
    let signature = keys.sign(&manifest.signed_bytes());
    let offer = Control::Offer {
        manifest,
        content_key: *ck.as_bytes(),
        signature,
        progress: true,
        text: true,
    };

    if matches!(fault, SenderFault::TamperOfferAeadTag) {
        let mut ct = chan.sealer.seal(&offer.encode())?;
        if let Some(last) = ct.last_mut() {
            *last ^= 0x01;
        }
        write_frame(&mut chan.send, &ct).await?;
        let _ = tokio::time::timeout(Duration::from_secs(20), conn.closed()).await;
        drop(endpoint);
        return Ok(());
    }

    secure::send_control(&mut chan.sealer, &mut chan.send, &offer).await?;

    // Wait for receiver Accept control message.
    let reply = secure::recv_control(&mut chan.opener, &mut chan.recv).await?;
    if !matches!(reply, Control::Accept { .. }) {
        return Ok(());
    }

    // Stream the single encrypted text chunk.
    let mut uni = conn.open_uni().await?;
    let cipher = EntryCipher::new(&ck, &transfer_id, 0);
    let header = DataHeader {
        transfer_id,
        entry: 0,
        first_chunk: 0,
    };
    write_frame(&mut uni, &header.encode()).await?;
    let sealed_chunk = cipher.seal(0, true, &payload)?;
    write_frame(&mut uni, &sealed_chunk).await?;
    let _ = uni.finish();
    let _ = secure::recv_control(&mut chan.opener, &mut chan.recv).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// E2E Test Cases

#[test]
fn loopback_file_transfer_nested_dir_no_clobber_and_ipv6() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let tmp = TempDirGuard::new("files")?;

    // Prepare source file + nested directory.
    let src_dir = tmp.path().join("src");
    let nested = src_dir.join("nested").join("deep");
    std::fs::create_dir_all(&nested)?;
    let payload_a = vec![0x42u8; 64 * 1024 + 137];
    let payload_b = b"TotalDrop Windows nested file content!".to_vec();
    let file_a = src_dir.join("report.bin");
    let file_b = nested.join("notes.txt");
    std::fs::write(&file_a, &payload_a)?;
    std::fs::write(&file_b, &payload_b)?;

    // Pre-populate destination with an existing `report.bin` to verify no-clobber!
    let dest_dir = tmp.path().join("dest");
    std::fs::create_dir_all(&dest_dir)?;
    let existing_sentinel = b"EXISTING-DO-NOT-OVERWRITE";
    std::fs::write(dest_dir.join("report.bin"), existing_sentinel)?;

    let cfg = c_str(&make_cfg_json(&srv.url, "", false))?;
    let paths_json = c_str(&serde_json::to_string(&vec![
        file_a.to_string_lossy().into_owned(),
        src_dir.join("nested").to_string_lossy().into_owned(),
    ])?)?;
    let en = c_str("en-US")?;
    let tr = c_str("tr-TR")?;

    // SAFETY: All pointers are live NUL-terminated CStrings.
    let send_sid = unsafe {
        totaldrop_win_send_files_start(cfg.as_ptr(), paths_json.as_ptr(), en.as_ptr(), tr.as_ptr())
    };
    assert_ne!(send_sid, 0);

    let mut send_events = Vec::new();
    let code_ev = wait_for_event(
        send_sid,
        &mut send_events,
        "code_ready",
        Duration::from_secs(10),
    )?;
    let code_str = code_ev
        .pointer("/code/display_english")
        .and_then(Value::as_str)
        .ok_or("missing display_english in code_ready")?
        .to_owned();

    let code_c = c_str(&code_str)?;
    // SAFETY: All pointers are live NUL-terminated CStrings.
    let recv_sid = unsafe {
        totaldrop_win_receive_connect_start(cfg.as_ptr(), code_c.as_ptr(), en.as_ptr(), tr.as_ptr())
    };
    assert_ne!(recv_sid, 0);

    let mut recv_events = Vec::new();
    let offer_ev = wait_for_event(
        recv_sid,
        &mut recv_events,
        "offer_ready",
        Duration::from_secs(15),
    )?;
    assert_eq!(
        offer_ev.get("is_text").and_then(Value::as_bool),
        Some(false)
    );
    let recv_words = offer_ev
        .get("verification_words")
        .and_then(Value::as_array)
        .ok_or("missing offer verification_words")?
        .clone();
    assert_eq!(recv_words.len(), 4);

    let send_conn = wait_for_event(
        send_sid,
        &mut send_events,
        "connected",
        Duration::from_secs(10),
    )?;
    let send_words = send_conn
        .get("verification_words")
        .and_then(Value::as_array)
        .ok_or("missing sender verification_words")?;
    assert_eq!(send_words, &recv_words);

    let dest_c = c_str(&dest_dir.to_string_lossy())?;
    // SAFETY: `dest_c` is a live NUL-terminated CString.
    let accept_rc = unsafe { totaldrop_win_receive_accept_files(recv_sid, dest_c.as_ptr()) };
    assert_eq!(accept_rc, FFI_OK);

    let recv_done = wait_for_event(recv_sid, &mut recv_events, "done", Duration::from_secs(20))?;
    let send_done = wait_for_event(send_sid, &mut send_events, "done", Duration::from_secs(20))?;
    assert_eq!(recv_done.get("files_ok").and_then(Value::as_u64), Some(2));
    assert_eq!(
        recv_done.get("files_failed").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(send_done.get("files_ok").and_then(Value::as_u64), Some(2));

    // Existing file MUST remain untouched (no-clobber), and renamed copy matches BLAKE3!
    assert_eq!(
        std::fs::read(dest_dir.join("report.bin"))?,
        existing_sentinel
    );
    let placed = recv_done
        .get("placed")
        .and_then(Value::as_array)
        .ok_or("missing placed array")?;
    assert!(!placed.is_empty());

    let mut found_a = false;
    let mut found_b = false;
    for entry in std::fs::read_dir(&dest_dir)? {
        let p = entry?.path();
        if p.is_file() && p.file_name().and_then(|n| n.to_str()) != Some("report.bin") {
            let data = std::fs::read(&p)?;
            if blake3::hash(&data) == blake3::hash(&payload_a) {
                found_a = true;
            }
        }
    }
    let nested_received = dest_dir.join("nested").join("deep").join("notes.txt");
    if nested_received.is_file()
        && blake3::hash(&std::fs::read(&nested_received)?) == blake3::hash(&payload_b)
    {
        found_b = true;
    }
    assert!(
        found_a,
        "no-clobber renamed report.bin copy not found or hash mismatch"
    );
    assert!(found_b, "nested/deep/notes.txt not found or hash mismatch");

    // Idempotent cancel after Done preserves terminal state and returns 0.
    assert_eq!(totaldrop_win_session_cancel(recv_sid), FFI_OK);
    assert_eq!(totaldrop_win_session_destroy(send_sid), FFI_OK);
    assert_eq!(totaldrop_win_session_destroy(recv_sid), FFI_OK);
    assert_eq!(
        totaldrop_win_session_destroy(recv_sid),
        FFI_ERR_INVALID_HANDLE
    );

    // IPv6 `[::1]:0` loopback verification (runs whenever IPv6 loopback is available).
    if let Ok(v6_srv) = MockRendezvous::start("[::1]:0", RendezvousFault::None) {
        let v6_cfg = c_str(&make_cfg_json(&v6_srv.url, "", false))?;
        let text_c = c_str("IPv6 loopback check")?;
        // SAFETY: Live CStrings.
        let s6 = unsafe {
            totaldrop_win_send_text_start(
                v6_cfg.as_ptr(),
                text_c.as_ptr(),
                en.as_ptr(),
                en.as_ptr(),
            )
        };
        assert_ne!(s6, 0);
        let mut s6_evs = Vec::new();
        let c6 = wait_for_event(s6, &mut s6_evs, "code_ready", Duration::from_secs(10))?;
        let code6 = c6
            .pointer("/code/display_english")
            .and_then(Value::as_str)
            .ok_or("missing ipv6 code")?;
        let code6_c = c_str(code6)?;
        // SAFETY: Live CStrings.
        let r6 = unsafe {
            totaldrop_win_receive_connect_start(
                v6_cfg.as_ptr(),
                code6_c.as_ptr(),
                en.as_ptr(),
                en.as_ptr(),
            )
        };
        assert_ne!(r6, 0);
        let mut r6_evs = Vec::new();
        let _ = wait_for_event(r6, &mut r6_evs, "offer_ready", Duration::from_secs(15))?;
        assert_eq!(totaldrop_win_receive_accept_text(r6), FFI_OK);
        let done6 = wait_for_event(r6, &mut r6_evs, "done", Duration::from_secs(15))?;
        assert_eq!(
            done6.get("received_text").and_then(Value::as_str),
            Some("IPv6 loopback check")
        );
        let _ = totaldrop_win_session_destroy(s6);
        let _ = totaldrop_win_session_destroy(r6);
    }

    Ok(())
}

#[test]
fn loopback_plain_text_unicode_bidi_sanitization_and_zero_disk_writes() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let raw_text = "Merhaba 🌍\r\nsecret\u{202E}fdp.exe\u{200D}ok";

    let cfg = c_str(&make_cfg_json(&srv.url, "", false))?;
    let text_c = c_str(raw_text)?;
    let en = c_str("en-US")?;

    // SAFETY: Live CStrings.
    let send_sid = unsafe {
        totaldrop_win_send_text_start(cfg.as_ptr(), text_c.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    assert_ne!(send_sid, 0);

    let mut s_evs = Vec::new();
    let code_ev = wait_for_event(send_sid, &mut s_evs, "code_ready", Duration::from_secs(10))?;
    assert_eq!(code_ev.get("is_text").and_then(Value::as_bool), Some(true));
    let code_str = code_ev
        .pointer("/code/display_english")
        .and_then(Value::as_str)
        .ok_or("missing display_english")?;

    let code_c = c_str(code_str)?;
    // SAFETY: Live CStrings.
    let recv_sid = unsafe {
        totaldrop_win_receive_connect_start(cfg.as_ptr(), code_c.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    assert_ne!(recv_sid, 0);

    let mut r_evs = Vec::new();
    let offer_ev = wait_for_event(recv_sid, &mut r_evs, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(offer_ev.get("is_text").and_then(Value::as_bool), Some(true));

    assert_eq!(totaldrop_win_receive_accept_text(recv_sid), FFI_OK);
    let recv_done = wait_for_event(recv_sid, &mut r_evs, "done", Duration::from_secs(15))?;
    let send_done = wait_for_event(send_sid, &mut s_evs, "done", Duration::from_secs(15))?;

    assert_eq!(
        recv_done.get("is_text").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        recv_done.get("received_text").and_then(Value::as_str),
        Some(raw_text)
    );
    assert_eq!(
        recv_done
            .pointer("/sanitized_text/display_text")
            .and_then(Value::as_str),
        Some("Merhaba 🌍\nsecret<U+202E>fdp.exe\u{200D}ok")
    );
    assert_eq!(
        recv_done
            .pointer("/sanitized_text/has_hidden_controls")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(recv_done.get("saved_to").is_none() || recv_done.get("saved_to") == Some(&Value::Null));
    assert_eq!(
        recv_done
            .get("placed")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        send_done.get("is_text").and_then(Value::as_bool),
        Some(true)
    );

    // > MAX_TEXT (1_048_577 bytes) emits text_too_long / sendTextTooLong with zero sockets opened.
    let oversized = "a".repeat(1_048_577);
    let over_c = c_str(&oversized)?;
    let dummy_cfg = c_str(&make_cfg_json("ws://127.0.0.1:1", "", false))?;
    // SAFETY: Live CStrings.
    let over_sid = unsafe {
        totaldrop_win_send_text_start(
            dummy_cfg.as_ptr(),
            over_c.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    assert_ne!(over_sid, 0);
    let mut over_evs = Vec::new();
    let over_fail = wait_for_event(over_sid, &mut over_evs, "failed", Duration::from_secs(5))?;
    assert_eq!(
        over_fail.get("kind").and_then(Value::as_str),
        Some("text_too_long")
    );
    assert_eq!(
        over_fail.get("l10n_key").and_then(Value::as_str),
        Some("sendTextTooLong")
    );

    let _ = totaldrop_win_session_destroy(send_sid);
    let _ = totaldrop_win_session_destroy(recv_sid);
    let _ = totaldrop_win_session_destroy(over_sid);
    Ok(())
}

#[test]
fn loopback_privacy_mode_relay_transfer_and_relay_drop_error() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let relay = MockRelay::start(RelayMode::Normal)?;

    let cfg = c_str(&make_cfg_json(&srv.url, &relay.url, true))?;
    let en = c_str("en-US")?;
    let msg = c_str("Privacy relay-only loopback message")?;

    // SAFETY: Live CStrings.
    let send_sid = unsafe {
        totaldrop_win_send_text_start(cfg.as_ptr(), msg.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    let mut s_evs = Vec::new();
    let code_ev = wait_for_event(send_sid, &mut s_evs, "code_ready", Duration::from_secs(10))?;
    let code_c = c_str(
        code_ev
            .pointer("/code/display_english")
            .and_then(Value::as_str)
            .ok_or("missing code")?,
    )?;

    // SAFETY: Live CStrings.
    let recv_sid = unsafe {
        totaldrop_win_receive_connect_start(cfg.as_ptr(), code_c.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    let mut r_evs = Vec::new();
    let _ = wait_for_event(recv_sid, &mut r_evs, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(totaldrop_win_receive_accept_text(recv_sid), FFI_OK);
    let done = wait_for_event(recv_sid, &mut r_evs, "done", Duration::from_secs(15))?;
    assert_eq!(
        done.get("received_text").and_then(Value::as_str),
        Some("Privacy relay-only loopback message")
    );
    let _ = totaldrop_win_session_destroy(send_sid);
    let _ = totaldrop_win_session_destroy(recv_sid);

    // Mismatched privacy relays (sender on relay, receiver on other_relay) -> errorConnect + causeRelay!
    let other_relay = MockRelay::start(RelayMode::DropOnConnect)?;
    let sender_priv_cfg = c_str(&make_cfg_json(&srv.url, &relay.url, true))?;
    let recv_other_cfg = c_str(&make_cfg_json(&srv.url, &other_relay.url, true))?;
    // SAFETY: Live CStrings.
    let mismatch_send = unsafe {
        totaldrop_win_send_text_start(
            sender_priv_cfg.as_ptr(),
            msg.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    let mut ds_evs = Vec::new();
    let mismatch_code_ev = wait_for_event(
        mismatch_send,
        &mut ds_evs,
        "code_ready",
        Duration::from_secs(10),
    )?;
    let mismatch_code_c = c_str(
        mismatch_code_ev
            .pointer("/code/display_english")
            .and_then(Value::as_str)
            .ok_or("missing mismatch code")?,
    )?;
    // SAFETY: Live CStrings.
    let mismatch_recv = unsafe {
        totaldrop_win_receive_connect_start(
            recv_other_cfg.as_ptr(),
            mismatch_code_c.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    let mut dr_evs = Vec::new();
    let fail = wait_for_event(
        mismatch_recv,
        &mut dr_evs,
        "failed",
        Duration::from_secs(15),
    )?;
    assert_eq!(
        fail.get("l10n_key").and_then(Value::as_str),
        Some("errorConnect")
    );
    assert_eq!(
        fail.get("cause").and_then(Value::as_str),
        Some("causeRelay")
    );

    let _ = totaldrop_win_session_destroy(mismatch_send);
    let _ = totaldrop_win_session_destroy(mismatch_recv);
    Ok(())
}

#[test]
fn loopback_offer_decline_and_throttled_active_cancel() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let en = c_str("en-US")?;
    let cfg = c_str(&make_cfg_json(&srv.url, "", false))?;
    let txt = c_str("Please decline me")?;

    // 1. Offer decline.
    // SAFETY: Live CStrings.
    let s1 = unsafe {
        totaldrop_win_send_text_start(cfg.as_ptr(), txt.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    let mut s1_evs = Vec::new();
    let c1 = wait_for_event(s1, &mut s1_evs, "code_ready", Duration::from_secs(10))?;
    let code1_c = c_str(
        c1.pointer("/code/display_english")
            .and_then(Value::as_str)
            .ok_or("missing code1")?,
    )?;
    // SAFETY: Live CStrings.
    let r1 = unsafe {
        totaldrop_win_receive_connect_start(
            cfg.as_ptr(),
            code1_c.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    let mut r1_evs = Vec::new();
    let _ = wait_for_event(r1, &mut r1_evs, "offer_ready", Duration::from_secs(15))?;
    assert_eq!(totaldrop_win_receive_decline(r1), FFI_OK);
    let declined = wait_for_event(r1, &mut r1_evs, "declined", Duration::from_secs(5))?;
    assert_eq!(declined.get("is_text").and_then(Value::as_bool), Some(true));

    let sender_fail = wait_for_event(s1, &mut s1_evs, "failed", Duration::from_secs(15))?;
    assert_eq!(
        sender_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorDeclined")
    );
    let _ = totaldrop_win_session_destroy(s1);
    let _ = totaldrop_win_session_destroy(r1);

    // 2. Active cancel on throttled relay file transfer.
    let slow_relay = MockRelay::start(RelayMode::Throttled(Duration::from_millis(8)))?;
    let tmp = TempDirGuard::new("cancel")?;
    let big_file = tmp.path().join("big.bin");
    std::fs::write(&big_file, vec![0x77u8; 512 * 1024])?;
    let dest = tmp.path().join("out");
    std::fs::create_dir_all(&dest)?;

    let slow_cfg = c_str(&make_cfg_json(&srv.url, &slow_relay.url, true))?;
    let paths_c = c_str(&serde_json::to_string(&vec![
        big_file.to_string_lossy().into_owned(),
    ])?)?;
    // SAFETY: Live CStrings.
    let s2 = unsafe {
        totaldrop_win_send_files_start(
            slow_cfg.as_ptr(),
            paths_c.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    let mut s2_evs = Vec::new();
    let c2 = wait_for_event(s2, &mut s2_evs, "code_ready", Duration::from_secs(10))?;
    let code2_c = c_str(
        c2.pointer("/code/display_english")
            .and_then(Value::as_str)
            .ok_or("missing code2")?,
    )?;
    // SAFETY: Live CStrings.
    let r2 = unsafe {
        totaldrop_win_receive_connect_start(
            slow_cfg.as_ptr(),
            code2_c.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    let mut r2_evs = Vec::new();
    let _ = wait_for_event(r2, &mut r2_evs, "offer_ready", Duration::from_secs(15))?;
    let dest_c = c_str(&dest.to_string_lossy())?;
    // SAFETY: Live CString.
    let accept2_rc = unsafe { totaldrop_win_receive_accept_files(r2, dest_c.as_ptr()) };
    assert_eq!(accept2_rc, FFI_OK);

    // Wait briefly so transfer is mid-flight, then cancel receiver.
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(totaldrop_win_session_cancel(r2), FFI_OK);
    let r2_fail = wait_for_event(r2, &mut r2_evs, "failed", Duration::from_secs(15))?;
    assert_eq!(
        r2_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorStopped")
    );
    let _ = totaldrop_win_session_destroy(s2);
    let _ = totaldrop_win_session_destroy(r2);
    Ok(())
}

#[test]
fn loopback_error_taxonomy_wrong_code_nameplate_bad_server_and_destinations() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let de = c_str("de-DE")?;
    let en = c_str("en-US")?;
    let cfg = c_str(&make_cfg_json(&srv.url, "", false))?;
    let txt = c_str("secret payload")?;

    // 1. Wrong code on unreviewed German locale -> critical English errorWrongCode!
    // SAFETY: Live CStrings.
    let s1 = unsafe {
        totaldrop_win_send_text_start(cfg.as_ptr(), txt.as_ptr(), de.as_ptr(), de.as_ptr())
    };
    let mut s1_evs = Vec::new();
    let c1 = wait_for_event(s1, &mut s1_evs, "code_ready", Duration::from_secs(10))?;
    let np = c1
        .pointer("/code/nameplate")
        .and_then(Value::as_u64)
        .ok_or("missing nameplate")?;
    let wrong_code = c_str(&format!("{np}-abandon-abandon"))?;
    let right_code = c1
        .pointer("/code/display_english")
        .and_then(Value::as_str)
        .ok_or("missing code")?;
    let wrong_str = if right_code.ends_with("abandon-abandon") {
        format!("{np}-zoo-zone")
    } else {
        format!("{np}-abandon-abandon")
    };
    drop(wrong_code);
    let wrong_c = c_str(&wrong_str)?;
    // SAFETY: Live CStrings.
    let r1 = unsafe {
        totaldrop_win_receive_connect_start(
            cfg.as_ptr(),
            wrong_c.as_ptr(),
            de.as_ptr(),
            de.as_ptr(),
        )
    };
    let mut r1_evs = Vec::new();
    let wrong_fail = wait_for_event(r1, &mut r1_evs, "failed", Duration::from_secs(15))?;
    assert_eq!(
        wrong_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorWrongCode")
    );
    assert!(
        wrong_fail
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("The code did not match")),
        "unreviewed German locale must display critical English errorWrongCode: {wrong_fail}"
    );
    let _ = totaldrop_win_session_destroy(s1);
    let _ = totaldrop_win_session_destroy(r1);

    // 2. Unknown nameplate on receiver -> errorCodeNotInUse.
    let missing_c = c_str("99999-harbor-rocket")?;
    // SAFETY: Live CStrings.
    let r_miss = unsafe {
        totaldrop_win_receive_connect_start(
            cfg.as_ptr(),
            missing_c.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    let mut rm_evs = Vec::new();
    let miss_fail = wait_for_event(r_miss, &mut rm_evs, "failed", Duration::from_secs(10))?;
    assert_eq!(
        miss_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorCodeNotInUse")
    );
    let _ = totaldrop_win_session_destroy(r_miss);

    // 3. Mailbox expired on sender -> errorCodeExpired!
    let exp_srv = MockRendezvous::start(
        "127.0.0.1:0",
        RendezvousFault::ErrorAfterClaim("mailbox expired".to_owned()),
    )?;
    let exp_cfg = c_str(&make_cfg_json(&exp_srv.url, "", false))?;
    // SAFETY: Live CStrings.
    let s_exp = unsafe {
        totaldrop_win_send_text_start(exp_cfg.as_ptr(), txt.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    let mut se_evs = Vec::new();
    let exp_fail = wait_for_event(s_exp, &mut se_evs, "failed", Duration::from_secs(10))?;
    assert_eq!(
        exp_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorCodeExpired")
    );
    let _ = totaldrop_win_session_destroy(s_exp);

    // 4. Generic server error ("rate limit exceeded") -> errorServer.
    let rl_srv = MockRendezvous::start(
        "127.0.0.1:0",
        RendezvousFault::AlwaysError("rate limit exceeded".to_owned()),
    )?;
    let rl_cfg = c_str(&make_cfg_json(&rl_srv.url, "", false))?;
    // SAFETY: Live CStrings.
    let r_rl = unsafe {
        totaldrop_win_receive_connect_start(
            rl_cfg.as_ptr(),
            missing_c.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    let mut rl_evs = Vec::new();
    let rl_fail = wait_for_event(r_rl, &mut rl_evs, "failed", Duration::from_secs(10))?;
    assert_eq!(
        rl_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorServer")
    );
    let _ = totaldrop_win_session_destroy(r_rl);

    // 5. Bad server URLs -> errorBadServer with exact core technical_english, zero sockets opened.
    for (bad_url, expected_substr) in [
        (
            "ws://192.168.1.10:4000",
            "unencrypted ws:// is only allowed for a server on this machine",
        ),
        (
            "wss://user@rendezvous.example",
            "the server address must not contain a user name",
        ),
    ] {
        let bad_cfg = c_str(&make_cfg_json(bad_url, "", false))?;
        // SAFETY: Live CStrings.
        let s_bad = unsafe {
            totaldrop_win_send_text_start(bad_cfg.as_ptr(), txt.as_ptr(), en.as_ptr(), en.as_ptr())
        };
        let mut sb_evs = Vec::new();
        let bad_fail = wait_for_event(s_bad, &mut sb_evs, "failed", Duration::from_secs(5))?;
        assert_eq!(
            bad_fail.get("kind").and_then(Value::as_str),
            Some("bad_server")
        );
        assert_eq!(
            bad_fail.get("l10n_key").and_then(Value::as_str),
            Some("errorBadServer")
        );
        assert!(
            bad_fail
                .get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|t| t.contains(expected_substr)),
            "expected core message {expected_substr:?} in {bad_fail}"
        );
        let _ = totaldrop_win_session_destroy(s_bad);
    }

    // 5b. All 14 malformed authority/port/fragment URL bypass vectors fail OFFLINE (zero DNS/sockets)
    // with exact kind="bad_server" and l10n_key="errorBadServer".
    const MALFORMED_BYPASS_URLS: [&str; 14] = [
        "wss://:443",
        "wss://:",
        "wss://:0",
        "wss://:443/v0/allocate",
        "wss://[]:443",
        "wss://example.invalid:99999",
        "wss://example.invalid:abc",
        "wss://example.invalid:0",
        "wss://example.invalid#frag",
        "ws://127.0.0.1:99999",
        "ws://127.0.0.1:abc",
        "ws://localhost:99999",
        "ws://localhost:abc",
        "ws://localhost#frag",
    ];
    for malformed in MALFORMED_BYPASS_URLS {
        let bad_cfg = c_str(&make_cfg_json(malformed, "", false))?;
        // SAFETY: Live CStrings.
        let s_bad = unsafe {
            totaldrop_win_send_text_start(bad_cfg.as_ptr(), txt.as_ptr(), en.as_ptr(), en.as_ptr())
        };
        let mut sb_evs = Vec::new();
        let bad_fail = wait_for_event(s_bad, &mut sb_evs, "failed", Duration::from_secs(2))?;
        assert_eq!(
            bad_fail.get("kind").and_then(Value::as_str),
            Some("bad_server"),
            "expected bad_server for {malformed:?}: {bad_fail}"
        );
        assert_eq!(
            bad_fail.get("l10n_key").and_then(Value::as_str),
            Some("errorBadServer"),
            "expected errorBadServer for {malformed:?}: {bad_fail}"
        );
        let _ = totaldrop_win_session_destroy(s_bad);
    }

    // Also verify malformed rendezvous/relay URLs fail offline on send_files_start & receive_connect_start.
    let bad_relay_cfg = c_str(&make_cfg_json(&srv.url, "wss://:443/v0/relay", true))?;
    // SAFETY: Live CStrings.
    let r_bad_relay = unsafe {
        totaldrop_win_receive_connect_start(
            bad_relay_cfg.as_ptr(),
            missing_c.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    let mut rbr_evs = Vec::new();
    let rbr_fail = wait_for_event(r_bad_relay, &mut rbr_evs, "failed", Duration::from_secs(2))?;
    assert_eq!(
        rbr_fail.get("kind").and_then(Value::as_str),
        Some("bad_server")
    );
    assert_eq!(
        rbr_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorBadServer")
    );
    let _ = totaldrop_win_session_destroy(r_bad_relay);

    let bad_rdv_cfg = c_str(&make_cfg_json("wss://example.invalid:99999", "", false))?;
    let dummy_path = if cfg!(windows) {
        r"C:\nonexistent\path\must-fail-before-disk-scan.bin"
    } else {
        "/nonexistent/path/must-fail-before-disk-scan.bin"
    };
    let dummy_file_paths = c_str(&serde_json::to_string(&[dummy_path])?)?;
    // SAFETY: Live CStrings.
    let sf_bad = unsafe {
        totaldrop_win_send_files_start(
            bad_rdv_cfg.as_ptr(),
            dummy_file_paths.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    let mut sfb_evs = Vec::new();
    let sfb_fail = wait_for_event(sf_bad, &mut sfb_evs, "failed", Duration::from_secs(2))?;
    assert_eq!(
        sfb_fail.get("kind").and_then(Value::as_str),
        Some("bad_server")
    );
    assert_eq!(
        sfb_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorBadServer")
    );
    let _ = totaldrop_win_session_destroy(sf_bad);

    // 6. Regular file destination -> errorStorage + cause == "" + "is not a directory".
    let tmp = TempDirGuard::new("bad-dest")?;
    let src_file = tmp.path().join("src.txt");
    std::fs::write(&src_file, b"hello")?;
    let regular_file_dest = tmp.path().join("not_a_dir.txt");
    std::fs::write(&regular_file_dest, b"i am a file")?;

    let paths_c = c_str(&serde_json::to_string(&vec![
        src_file.to_string_lossy().into_owned(),
    ])?)?;
    // SAFETY: Live CStrings.
    let sf = unsafe {
        totaldrop_win_send_files_start(cfg.as_ptr(), paths_c.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    let mut sf_evs = Vec::new();
    let cf = wait_for_event(sf, &mut sf_evs, "code_ready", Duration::from_secs(10))?;
    let cf_code = c_str(
        cf.pointer("/code/display_english")
            .and_then(Value::as_str)
            .ok_or("missing cf code")?,
    )?;
    // SAFETY: Live CStrings.
    let rf = unsafe {
        totaldrop_win_receive_connect_start(
            cfg.as_ptr(),
            cf_code.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    let mut rf_evs = Vec::new();
    let _ = wait_for_event(rf, &mut rf_evs, "offer_ready", Duration::from_secs(15))?;
    let bad_dest_c = c_str(&regular_file_dest.to_string_lossy())?;
    // SAFETY: Live CString.
    let bad_dest_rc = unsafe { totaldrop_win_receive_accept_files(rf, bad_dest_c.as_ptr()) };
    assert_eq!(bad_dest_rc, FFI_OK);
    let dest_fail = wait_for_event(rf, &mut rf_evs, "failed", Duration::from_secs(10))?;
    assert_eq!(
        dest_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorStorage")
    );
    assert_eq!(dest_fail.get("cause").and_then(Value::as_str), Some(""));
    assert!(
        dest_fail
            .get("technical_english")
            .and_then(Value::as_str)
            .is_some_and(|t| t.contains("is not a directory")),
        "expected 'is not a directory' in {dest_fail}"
    );
    let _ = totaldrop_win_session_destroy(sf);
    let _ = totaldrop_win_session_destroy(rf);

    Ok(())
}

#[test]
fn loopback_fault_injection_text_damaged_blake3_invalid_utf8_and_aead_tamper() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let cfg = c_str(&make_cfg_json(&srv.url, "", false))?;
    let en = c_str("en-US")?;

    // 1. Tampered BLAKE3 hash & Invalid UTF-8 [0xFF, 0xFE] -> both emit errorTextDamaged.
    for fault in [
        SenderFault::CorruptTextBlake3Hash,
        SenderFault::InvalidUtf8TextPayload,
    ] {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let url_clone = srv.url.clone();
        TEST_RUNTIME.spawn(async move {
            let _ = run_fault_sender(url_clone, fault, tx).await;
        });
        let code_str = TEST_RUNTIME.block_on(rx)?;
        let code_c = c_str(&code_str)?;
        // SAFETY: Live CStrings.
        let rsid = unsafe {
            totaldrop_win_receive_connect_start(
                cfg.as_ptr(),
                code_c.as_ptr(),
                en.as_ptr(),
                en.as_ptr(),
            )
        };
        let mut r_evs = Vec::new();
        let offer = wait_for_event(rsid, &mut r_evs, "offer_ready", Duration::from_secs(15))?;
        assert_eq!(offer.get("is_text").and_then(Value::as_bool), Some(true));
        assert_eq!(totaldrop_win_receive_accept_text(rsid), FFI_OK);
        let fail = wait_for_event(rsid, &mut r_evs, "failed", Duration::from_secs(15))?;
        assert_eq!(
            fail.get("kind").and_then(Value::as_str),
            Some("text_damaged")
        );
        assert_eq!(
            fail.get("l10n_key").and_then(Value::as_str),
            Some("errorTextDamaged")
        );
        assert_eq!(fail.get("cause").and_then(Value::as_str), Some(""));
        assert!(
            fail.get("cause_detail").is_none() || fail.get("cause_detail") == Some(&Value::Null)
        );
        assert_eq!(
            fail.get("technical_english").and_then(Value::as_str),
            Some("the text failed its check")
        );
        let _ = totaldrop_win_session_destroy(rsid);
    }

    // 2. Post-handshake AEAD tag tamper on sealed Control::Offer -> errorOther + Cause::Unknown + "message failed authentication".
    let (tx, rx) = tokio::sync::oneshot::channel();
    let url_clone = srv.url.clone();
    TEST_RUNTIME.spawn(async move {
        let _ = run_fault_sender(url_clone, SenderFault::TamperOfferAeadTag, tx).await;
    });
    let code_str = TEST_RUNTIME.block_on(rx)?;
    let code_c = c_str(&code_str)?;
    // SAFETY: Live CStrings.
    let rsid = unsafe {
        totaldrop_win_receive_connect_start(cfg.as_ptr(), code_c.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    let mut r_evs = Vec::new();
    let fail = wait_for_event(rsid, &mut r_evs, "failed", Duration::from_secs(15))?;
    assert_eq!(
        fail.get("l10n_key").and_then(Value::as_str),
        Some("errorOther")
    );
    assert_eq!(fail.get("cause").and_then(Value::as_str), Some(""));
    assert!(fail.get("cause_detail").is_none() || fail.get("cause_detail") == Some(&Value::Null));
    assert!(
        fail.get("technical_english")
            .and_then(Value::as_str)
            .is_some_and(|t| t.contains("message failed authentication")),
        "expected authentication failure detail in {fail}"
    );
    let _ = totaldrop_win_session_destroy(rsid);
    Ok(())
}

#[test]
fn shutdown_drains_active_sessions_within_bound_and_remains_reusable() -> TestResult {
    let _guard = SHUTDOWN_GATE.write().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let cfg = c_str(&make_cfg_json(&srv.url, "", false))?;
    let en = c_str("en-US")?;
    let txt = c_str("waiting sender to be drained by shutdown")?;

    // Start a waiting sender that will never receive a peer.
    // SAFETY: Live CStrings.
    let sid = unsafe {
        totaldrop_win_send_text_start(cfg.as_ptr(), txt.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    assert_ne!(sid, 0);
    let mut evs = Vec::new();
    let _ = wait_for_event(sid, &mut evs, "waiting", Duration::from_secs(10))?;

    let started = Instant::now();
    assert_eq!(totaldrop_win_shutdown(100), FFI_OK);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "shutdown(100) exceeded upper bound: {:?}",
        started.elapsed()
    );

    // Handle was removed by shutdown.
    assert_eq!(totaldrop_win_session_cancel(sid), FFI_ERR_INVALID_HANDLE);

    // Repeat shutdown(1500) when idle returns almost immediately (< 500 ms).
    let idle_start = Instant::now();
    assert_eq!(totaldrop_win_shutdown(1500), FFI_OK);
    assert!(idle_start.elapsed() < Duration::from_millis(500));

    // Static runtime stays usable for subsequent sessions!
    // SAFETY: Live CStrings.
    let sid2 = unsafe {
        totaldrop_win_send_text_start(cfg.as_ptr(), txt.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    assert_ne!(sid2, 0);
    let mut evs2 = Vec::new();
    let _ = wait_for_event(sid2, &mut evs2, "code_ready", Duration::from_secs(10))?;
    assert_eq!(totaldrop_win_session_destroy(sid2), FFI_OK);
    assert_eq!(totaldrop_win_shutdown(1500), FFI_OK);
    Ok(())
}

#[test]
fn read_only_destination_emits_storage_permission_error_on_unix() -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Skip if running as uid 0 where chmod 0555 does not block writes.
        let tmp = TempDirGuard::new("ro-dest")?;
        let ro_dir = tmp.path().join("readonly");
        std::fs::create_dir_all(&ro_dir)?;
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o555))?;
        let probe = ro_dir.join(".perm-probe");
        let is_actually_readonly = std::fs::write(&probe, b"x").is_err();
        let _ = std::fs::remove_file(&probe);
        if !is_actually_readonly {
            let _ = std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755));
            return Ok(());
        }

        let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
        let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
        let cfg = c_str(&make_cfg_json(&srv.url, "", false))?;
        let en = c_str("en-US")?;
        let src_file = tmp.path().join("hello.txt");
        std::fs::write(&src_file, b"hello")?;
        let paths_c = c_str(&serde_json::to_string(&vec![
            src_file.to_string_lossy().into_owned(),
        ])?)?;

        // SAFETY: Live CStrings.
        let s = unsafe {
            totaldrop_win_send_files_start(cfg.as_ptr(), paths_c.as_ptr(), en.as_ptr(), en.as_ptr())
        };
        let mut s_evs = Vec::new();
        let c = wait_for_event(s, &mut s_evs, "code_ready", Duration::from_secs(10))?;
        let code_c = c_str(
            c.pointer("/code/display_english")
                .and_then(Value::as_str)
                .ok_or("missing code")?,
        )?;
        // SAFETY: Live CStrings.
        let r = unsafe {
            totaldrop_win_receive_connect_start(
                cfg.as_ptr(),
                code_c.as_ptr(),
                en.as_ptr(),
                en.as_ptr(),
            )
        };
        let mut r_evs = Vec::new();
        let _ = wait_for_event(r, &mut r_evs, "offer_ready", Duration::from_secs(15))?;
        let ro_c = c_str(&ro_dir.to_string_lossy())?;
        // SAFETY: Live CString.
        let ro_rc = unsafe { totaldrop_win_receive_accept_files(r, ro_c.as_ptr()) };
        assert_eq!(ro_rc, FFI_OK);
        let fail = wait_for_event(r, &mut r_evs, "failed", Duration::from_secs(10))?;
        assert_eq!(
            fail.get("l10n_key").and_then(Value::as_str),
            Some("errorStorage")
        );
        assert_eq!(
            fail.get("cause").and_then(Value::as_str),
            Some("causeNoPermission")
        );
        let _ = totaldrop_win_session_destroy(s);
        let _ = totaldrop_win_session_destroy(r);
        let _ = std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755));
    }
    let _ = ptr::null::<c_char>();
    Ok(())
}

struct LoopbackCanary {
    url: String,
    accepted: Arc<AtomicU64>,
    abort: tokio::task::AbortHandle,
}

impl Drop for LoopbackCanary {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl LoopbackCanary {
    fn start() -> Result<Self, Box<dyn StdError>> {
        let accepted = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&accepted);
        let (url, abort) = TEST_RUNTIME.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let local = listener.local_addr()?;
            let url = format!("ws://{local}");
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
            });
            Ok::<_, std::io::Error>((url, task.abort_handle()))
        })?;
        Ok(Self {
            url,
            accepted,
            abort,
        })
    }
}

#[test]
fn malformed_relay_urls_fail_offline_before_contacting_rendezvous_canary() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let canary = LoopbackCanary::start()?;
    let tmp = TempDirGuard::new("bad-relay")?;
    let src_file = tmp.path().join("payload.txt");
    std::fs::write(&src_file, b"offline relay validation check")?;

    let paths_c = c_str(&serde_json::to_string(&vec![
        src_file.to_string_lossy().into_owned(),
    ])?)?;
    let txt_c = c_str("offline relay validation text")?;
    let code_c = c_str("7-harbor-rocket")?;
    let en = c_str("en-US")?;

    const MALFORMED_RELAY_URLS: [&str; 13] = [
        "wss://host:443:443",
        "wss://user@example.invalid",
        "ws://192.168.1.5:4000",
        "http://127.0.0.1:4000",
        "https://example.invalid",
        "not-a-url",
        "wss://",
        "wss:///",
        "ws://127.0.0.2:4000",
        "ws://0.0.0.0:4000",
        "WSS://example.invalid",
        "wss://example.invalid /bad",
        "wss://:443",
    ];

    for bad_relay in MALFORMED_RELAY_URLS {
        for privacy_relay_only in [false, true] {
            let cfg_c = c_str(&make_cfg_json(&canary.url, bad_relay, privacy_relay_only))?;

            // 1. totaldrop_win_send_text_start
            // SAFETY: All pointers are live NUL-terminated CStrings.
            let text_sid = unsafe {
                totaldrop_win_send_text_start(
                    cfg_c.as_ptr(),
                    txt_c.as_ptr(),
                    en.as_ptr(),
                    en.as_ptr(),
                )
            };
            assert_ne!(text_sid, 0);
            let mut text_evs = Vec::new();
            let text_fail =
                wait_for_event(text_sid, &mut text_evs, "failed", Duration::from_secs(2))?;
            assert_eq!(
                text_fail.get("kind").and_then(Value::as_str),
                Some("bad_server"),
                "send_text bad_relay={bad_relay:?} priv={privacy_relay_only}: {text_fail}"
            );
            assert_eq!(
                text_fail.get("l10n_key").and_then(Value::as_str),
                Some("errorBadServer"),
                "send_text bad_relay={bad_relay:?} priv={privacy_relay_only}: {text_fail}"
            );
            assert_eq!(totaldrop_win_session_destroy(text_sid), FFI_OK);

            // 2. totaldrop_win_send_files_start
            // SAFETY: All pointers are live NUL-terminated CStrings.
            let files_sid = unsafe {
                totaldrop_win_send_files_start(
                    cfg_c.as_ptr(),
                    paths_c.as_ptr(),
                    en.as_ptr(),
                    en.as_ptr(),
                )
            };
            assert_ne!(files_sid, 0);
            let mut files_evs = Vec::new();
            let files_fail =
                wait_for_event(files_sid, &mut files_evs, "failed", Duration::from_secs(2))?;
            assert_eq!(
                files_fail.get("kind").and_then(Value::as_str),
                Some("bad_server"),
                "send_files bad_relay={bad_relay:?} priv={privacy_relay_only}: {files_fail}"
            );
            assert_eq!(
                files_fail.get("l10n_key").and_then(Value::as_str),
                Some("errorBadServer"),
                "send_files bad_relay={bad_relay:?} priv={privacy_relay_only}: {files_fail}"
            );
            assert_eq!(totaldrop_win_session_destroy(files_sid), FFI_OK);

            // 3. totaldrop_win_receive_connect_start
            // SAFETY: All pointers are live NUL-terminated CStrings.
            let recv_sid = unsafe {
                totaldrop_win_receive_connect_start(
                    cfg_c.as_ptr(),
                    code_c.as_ptr(),
                    en.as_ptr(),
                    en.as_ptr(),
                )
            };
            assert_ne!(recv_sid, 0);
            let mut recv_evs = Vec::new();
            let recv_fail =
                wait_for_event(recv_sid, &mut recv_evs, "failed", Duration::from_secs(2))?;
            assert_eq!(
                recv_fail.get("kind").and_then(Value::as_str),
                Some("bad_server"),
                "receive_connect bad_relay={bad_relay:?} priv={privacy_relay_only}: {recv_fail}"
            );
            assert_eq!(
                recv_fail.get("l10n_key").and_then(Value::as_str),
                Some("errorBadServer"),
                "receive_connect bad_relay={bad_relay:?} priv={privacy_relay_only}: {recv_fail}"
            );
            assert_eq!(totaldrop_win_session_destroy(recv_sid), FFI_OK);
        }
    }

    // Confirm zero TCP connections reached the loopback rendezvous canary across all 78 calls.
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        canary.accepted.load(Ordering::SeqCst),
        0,
        "loopback rendezvous canary accepted unexpected connections for malformed relay_server URLs"
    );

    // Confirm core-rejected rendezvous_server URLs still preserve totaldrop-core's technical_english.
    let http_rdv_cfg = c_str(&make_cfg_json("http://127.0.0.1:4000", "", false))?;
    // SAFETY: All pointers are live NUL-terminated CStrings.
    let http_sid = unsafe {
        totaldrop_win_send_text_start(
            http_rdv_cfg.as_ptr(),
            txt_c.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    assert_ne!(http_sid, 0);
    let mut http_evs = Vec::new();
    let http_fail = wait_for_event(http_sid, &mut http_evs, "failed", Duration::from_secs(2))?;
    assert_eq!(
        http_fail.get("kind").and_then(Value::as_str),
        Some("bad_server")
    );
    assert_eq!(
        http_fail.get("l10n_key").and_then(Value::as_str),
        Some("errorBadServer")
    );
    assert!(
        http_fail
            .get("technical_english")
            .and_then(Value::as_str)
            .is_some_and(|t| t.contains("must start with wss://")),
        "expected core technical_english for http:// rendezvous_server: {http_fail}"
    );
    assert_eq!(totaldrop_win_session_destroy(http_sid), FFI_OK);

    Ok(())
}

struct ExpectedCounts {
    files: u64,
    dirs: u64,
    total_bytes: u64,
    skipped: u64,
}

fn run_count_parity_loopback(
    srv: &MockRendezvous,
    send_paths: &[PathBuf],
    dest_dir: &Path,
    expected: ExpectedCounts,
) -> Result<(Value, Value), Box<dyn StdError>> {
    std::fs::create_dir_all(dest_dir)?;

    let cfg = c_str(&make_cfg_json(&srv.url, "", false))?;
    let path_strings: Vec<String> = send_paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let paths_json = c_str(&serde_json::to_string(&path_strings)?)?;
    let en = c_str("en-US")?;

    // SAFETY: All pointers are live NUL-terminated CStrings.
    let send_sid = unsafe {
        totaldrop_win_send_files_start(cfg.as_ptr(), paths_json.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    assert_ne!(send_sid, 0);

    let mut send_events = Vec::new();
    let code_ev = wait_for_event(
        send_sid,
        &mut send_events,
        "code_ready",
        Duration::from_secs(10),
    )?;
    assert_eq!(
        code_ev.get("is_text").and_then(Value::as_bool),
        Some(false),
        "expected is_text == false in code_ready: {code_ev}"
    );
    assert_eq!(
        code_ev.get("files").and_then(Value::as_u64),
        Some(expected.files),
        "unexpected files in code_ready: {code_ev}"
    );
    assert_eq!(
        code_ev.get("dirs").and_then(Value::as_u64),
        Some(expected.dirs),
        "unexpected dirs in code_ready: {code_ev}"
    );
    assert_eq!(
        code_ev.get("total_bytes").and_then(Value::as_u64),
        Some(expected.total_bytes),
        "unexpected total_bytes in code_ready: {code_ev}"
    );
    assert_eq!(
        code_ev.get("skipped").and_then(Value::as_u64),
        Some(expected.skipped),
        "unexpected skipped in code_ready: {code_ev}"
    );

    let code_str = code_ev
        .pointer("/code/display_english")
        .and_then(Value::as_str)
        .ok_or("missing display_english in code_ready")?
        .to_owned();
    let code_c = c_str(&code_str)?;

    // SAFETY: All pointers are live NUL-terminated CStrings.
    let recv_sid = unsafe {
        totaldrop_win_receive_connect_start(cfg.as_ptr(), code_c.as_ptr(), en.as_ptr(), en.as_ptr())
    };
    assert_ne!(recv_sid, 0);

    let mut recv_events = Vec::new();
    let offer_ev = wait_for_event(
        recv_sid,
        &mut recv_events,
        "offer_ready",
        Duration::from_secs(15),
    )?;
    assert_eq!(
        offer_ev.get("is_text").and_then(Value::as_bool),
        Some(false),
        "expected is_text == false in offer_ready: {offer_ev}"
    );
    assert_eq!(
        code_ev.get("files"),
        offer_ev.get("files"),
        "code_ready.files must match offer_ready.files: code={code_ev} offer={offer_ev}"
    );
    assert_eq!(
        offer_ev.get("files").and_then(Value::as_u64),
        Some(expected.files),
        "unexpected files in offer_ready: {offer_ev}"
    );
    assert_eq!(
        code_ev.get("dirs"),
        offer_ev.get("dirs"),
        "code_ready.dirs must match offer_ready.dirs: code={code_ev} offer={offer_ev}"
    );
    assert_eq!(
        offer_ev.get("dirs").and_then(Value::as_u64),
        Some(expected.dirs),
        "unexpected dirs in offer_ready: {offer_ev}"
    );
    assert_eq!(
        code_ev.get("total_bytes"),
        offer_ev.get("total_bytes"),
        "code_ready.total_bytes must match offer_ready.total_bytes: code={code_ev} offer={offer_ev}"
    );
    assert_eq!(
        offer_ev.get("total_bytes").and_then(Value::as_u64),
        Some(expected.total_bytes),
        "unexpected total_bytes in offer_ready: {offer_ev}"
    );

    let recv_words = offer_ev
        .get("verification_words")
        .and_then(Value::as_array)
        .ok_or("missing offer verification_words")?
        .clone();
    assert_eq!(recv_words.len(), 4);

    let send_conn = wait_for_event(
        send_sid,
        &mut send_events,
        "connected",
        Duration::from_secs(10),
    )?;
    let send_words = send_conn
        .get("verification_words")
        .and_then(Value::as_array)
        .ok_or("missing sender verification_words")?;
    assert_eq!(send_words, &recv_words);

    let dest_c = c_str(&dest_dir.to_string_lossy())?;
    // SAFETY: `dest_c` is a live NUL-terminated CString.
    let accept_rc = unsafe { totaldrop_win_receive_accept_files(recv_sid, dest_c.as_ptr()) };
    assert_eq!(accept_rc, FFI_OK);

    let recv_done = wait_for_event(recv_sid, &mut recv_events, "done", Duration::from_secs(20))?;
    let send_done = wait_for_event(send_sid, &mut send_events, "done", Duration::from_secs(20))?;

    assert_eq!(
        recv_done.get("files_ok").and_then(Value::as_u64),
        Some(expected.files)
    );
    assert_eq!(
        recv_done.get("files_failed").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        recv_done.get("bytes").and_then(Value::as_u64),
        Some(expected.total_bytes)
    );
    assert_eq!(
        send_done.get("files_ok").and_then(Value::as_u64),
        Some(expected.files)
    );
    assert_eq!(
        send_done.get("files_failed").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        send_done.get("bytes").and_then(Value::as_u64),
        Some(expected.total_bytes)
    );

    assert_eq!(totaldrop_win_session_destroy(send_sid), FFI_OK);
    assert_eq!(totaldrop_win_session_destroy(recv_sid), FFI_OK);

    Ok((code_ev, offer_ev))
}

#[test]
fn loopback_code_ready_matches_offer_ready_for_nested_directory() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let tmp = TempDirGuard::new("parity-nested")?;

    // (a1) Nested directory with 2 dirs + 3 files (root + 1 subdir) -> files == 3, dirs == 2.
    let bundle = tmp.path().join("src1").join("bundle");
    let bundle_sub = bundle.join("sub");
    std::fs::create_dir_all(&bundle_sub)?;
    let empty_bytes: &[u8] = b"";
    let report_bytes: &[u8] = b"TotalDrop nested report payload 2026\n";
    let third_bytes = vec![0xABu8; 4096];
    std::fs::write(bundle.join("empty.txt"), empty_bytes)?;
    std::fs::write(bundle.join("report-2026.txt"), report_bytes)?;
    std::fs::write(bundle_sub.join("third.bin"), &third_bytes)?;

    let total_a1 = u64::try_from(empty_bytes.len())?
        .saturating_add(u64::try_from(report_bytes.len())?)
        .saturating_add(u64::try_from(third_bytes.len())?);
    let dest1 = tmp.path().join("dest1");
    let (_code1, offer1) = run_count_parity_loopback(
        &srv,
        &[bundle],
        &dest1,
        ExpectedCounts {
            files: 3,
            dirs: 2,
            total_bytes: total_a1,
            skipped: 0,
        },
    )?;
    assert_eq!(offer1.get("top_level"), Some(&json!(["bundle"])));
    assert_eq!(
        blake3::hash(&std::fs::read(dest1.join("bundle").join("empty.txt"))?),
        blake3::hash(empty_bytes)
    );
    assert_eq!(
        blake3::hash(&std::fs::read(
            dest1.join("bundle").join("report-2026.txt")
        )?),
        blake3::hash(report_bytes)
    );
    assert_eq!(
        blake3::hash(&std::fs::read(
            dest1.join("bundle").join("sub").join("third.bin")
        )?),
        blake3::hash(&third_bytes)
    );

    // (a2) Nested directory with 2 subdirs + 3 files -> files == 3, dirs == 3.
    let pack = tmp.path().join("src2").join("pack");
    let sub1 = pack.join("sub1");
    let sub2 = pack.join("sub2");
    std::fs::create_dir_all(&sub1)?;
    std::fs::create_dir_all(&sub2)?;
    let a_bytes: &[u8] = b"root-a";
    let b_bytes: &[u8] = b"nested-sub1-b";
    let c_bytes = vec![0xCDu8; 1024];
    std::fs::write(pack.join("a.txt"), a_bytes)?;
    std::fs::write(sub1.join("b.txt"), b_bytes)?;
    std::fs::write(sub2.join("c.bin"), &c_bytes)?;

    let total_a2 = u64::try_from(a_bytes.len())?
        .saturating_add(u64::try_from(b_bytes.len())?)
        .saturating_add(u64::try_from(c_bytes.len())?);
    let dest2 = tmp.path().join("dest2");
    let (_code2, offer2) = run_count_parity_loopback(
        &srv,
        &[pack],
        &dest2,
        ExpectedCounts {
            files: 3,
            dirs: 3,
            total_bytes: total_a2,
            skipped: 0,
        },
    )?;
    assert_eq!(offer2.get("top_level"), Some(&json!(["pack"])));
    assert_eq!(
        blake3::hash(&std::fs::read(dest2.join("pack").join("a.txt"))?),
        blake3::hash(a_bytes)
    );
    assert_eq!(
        blake3::hash(&std::fs::read(
            dest2.join("pack").join("sub1").join("b.txt")
        )?),
        blake3::hash(b_bytes)
    );
    assert_eq!(
        blake3::hash(&std::fs::read(
            dest2.join("pack").join("sub2").join("c.bin")
        )?),
        blake3::hash(&c_bytes)
    );

    Ok(())
}

#[test]
fn loopback_code_ready_matches_offer_ready_for_empty_directories_and_files() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let tmp = TempDirGuard::new("parity-empty-dirs")?;

    // (b1) Nested empty subdirectories + regular file -> files == 1, dirs == 4.
    let pack = tmp.path().join("src1").join("pack");
    std::fs::create_dir_all(pack.join("empty_sub"))?;
    std::fs::create_dir_all(pack.join("nested_empty").join("leaf_empty"))?;
    let doc_bytes: &[u8] = b"with empty subdirs";
    std::fs::write(pack.join("doc.txt"), doc_bytes)?;

    let dest1 = tmp.path().join("dest1");
    let (_code1, _offer1) = run_count_parity_loopback(
        &srv,
        &[pack],
        &dest1,
        ExpectedCounts {
            files: 1,
            dirs: 4,
            total_bytes: u64::try_from(doc_bytes.len())?,
            skipped: 0,
        },
    )?;
    assert!(dest1.join("pack").join("empty_sub").is_dir());
    assert!(
        dest1
            .join("pack")
            .join("nested_empty")
            .join("leaf_empty")
            .is_dir()
    );
    assert_eq!(
        blake3::hash(&std::fs::read(dest1.join("pack").join("doc.txt"))?),
        blake3::hash(doc_bytes)
    );

    // (b2) Top-level empty directory + top-level regular file -> files == 1, dirs == 1.
    let src2 = tmp.path().join("src2");
    let standalone_empty = src2.join("standalone_empty");
    std::fs::create_dir_all(&standalone_empty)?;
    let top_file = src2.join("top_file.txt");
    let top_bytes: &[u8] = b"top-level sibling file";
    std::fs::write(&top_file, top_bytes)?;

    let dest2 = tmp.path().join("dest2");
    let (_code2, offer2) = run_count_parity_loopback(
        &srv,
        &[standalone_empty, top_file],
        &dest2,
        ExpectedCounts {
            files: 1,
            dirs: 1,
            total_bytes: u64::try_from(top_bytes.len())?,
            skipped: 0,
        },
    )?;
    assert_eq!(
        offer2.get("top_level"),
        Some(&json!(["standalone_empty", "top_file.txt"]))
    );
    assert!(dest2.join("standalone_empty").is_dir());
    assert_eq!(
        blake3::hash(&std::fs::read(dest2.join("top_file.txt"))?),
        blake3::hash(top_bytes)
    );

    // (b3) Pure single empty directory -> files == 0, dirs == 1, total_bytes == 0.
    let only_empty = tmp.path().join("src3").join("only_empty");
    std::fs::create_dir_all(&only_empty)?;

    let dest3 = tmp.path().join("dest3");
    let (_code3, offer3) = run_count_parity_loopback(
        &srv,
        &[only_empty],
        &dest3,
        ExpectedCounts {
            files: 0,
            dirs: 1,
            total_bytes: 0,
            skipped: 0,
        },
    )?;
    assert_eq!(offer3.get("top_level"), Some(&json!(["only_empty"])));
    assert!(dest3.join("only_empty").is_dir());

    Ok(())
}

#[cfg(unix)]
#[test]
fn loopback_code_ready_matches_offer_ready_with_skipped_symlinks_on_unix() -> TestResult {
    use std::os::unix::fs::symlink;

    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let tmp = TempDirGuard::new("parity-symlinks")?;

    // External targets outside the transferred tree (must never be followed).
    let ext_dir = tmp.path().join("external");
    let ext_populated = ext_dir.join("ext_dir");
    std::fs::create_dir_all(ext_populated.join("ext_sub"))?;
    let ext_secret = ext_dir.join("secret.txt");
    std::fs::write(&ext_secret, vec![0xEEu8; 128])?;
    std::fs::write(
        ext_populated.join("hidden.txt"),
        b"must never be followed 001",
    )?;
    std::fs::write(
        ext_populated.join("ext_sub").join("deep.txt"),
        b"deep hidden",
    )?;

    // (c1) Regular files/dirs + symlink-to-file + symlink-to-populated-dir + dangling symlink.
    let bundle = tmp.path().join("src1").join("bundle");
    let sub = bundle.join("sub");
    std::fs::create_dir_all(&sub)?;
    let regular_bytes: &[u8] = b"regular file one";
    let inner_bytes: &[u8] = b"inner binary payload 12345";
    std::fs::write(bundle.join("regular.txt"), regular_bytes)?;
    std::fs::write(sub.join("inner.bin"), inner_bytes)?;
    symlink(&ext_secret, bundle.join("link_to_file"))?;
    symlink(&ext_populated, bundle.join("link_to_dir"))?;
    symlink(
        tmp.path().join("does-not-exist-anywhere"),
        sub.join("dangling_link"),
    )?;

    let total_c1 =
        u64::try_from(regular_bytes.len())?.saturating_add(u64::try_from(inner_bytes.len())?);
    let dest1 = tmp.path().join("dest1");
    let (_code1, _offer1) = run_count_parity_loopback(
        &srv,
        &[bundle],
        &dest1,
        ExpectedCounts {
            files: 2,
            dirs: 2,
            total_bytes: total_c1,
            skipped: 3,
        },
    )?;
    assert_eq!(
        blake3::hash(&std::fs::read(dest1.join("bundle").join("regular.txt"))?),
        blake3::hash(regular_bytes)
    );
    assert_eq!(
        blake3::hash(&std::fs::read(
            dest1.join("bundle").join("sub").join("inner.bin")
        )?),
        blake3::hash(inner_bytes)
    );
    assert!(std::fs::symlink_metadata(dest1.join("bundle").join("link_to_file")).is_err());
    assert!(std::fs::symlink_metadata(dest1.join("bundle").join("link_to_dir")).is_err());
    assert!(
        std::fs::symlink_metadata(dest1.join("bundle").join("sub").join("dangling_link")).is_err()
    );

    // (c2) Directory containing ONLY symlinks -> files == 0, dirs == 1, total_bytes == 0, skipped == 2.
    let only_links = tmp.path().join("src2").join("only_links");
    std::fs::create_dir_all(&only_links)?;
    symlink(&ext_secret, only_links.join("link_a"))?;
    symlink(
        tmp.path().join("still-missing-target"),
        only_links.join("link_dangling"),
    )?;

    let dest2 = tmp.path().join("dest2");
    let (_code2, _offer2) = run_count_parity_loopback(
        &srv,
        &[only_links],
        &dest2,
        ExpectedCounts {
            files: 0,
            dirs: 1,
            total_bytes: 0,
            skipped: 2,
        },
    )?;
    assert!(dest2.join("only_links").is_dir());
    assert!(std::fs::symlink_metadata(dest2.join("only_links").join("link_a")).is_err());
    assert!(std::fs::symlink_metadata(dest2.join("only_links").join("link_dangling")).is_err());

    Ok(())
}

#[test]
fn loopback_code_ready_matches_offer_ready_for_single_file() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let srv = MockRendezvous::start("127.0.0.1:0", RendezvousFault::None)?;
    let tmp = TempDirGuard::new("parity-single")?;

    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir)?;
    let single_file = src_dir.join("single.dat");
    let payload = vec![0x55u8; 2048];
    std::fs::write(&single_file, &payload)?;

    let dest = tmp.path().join("dest");
    let (_code, offer) = run_count_parity_loopback(
        &srv,
        &[single_file],
        &dest,
        ExpectedCounts {
            files: 1,
            dirs: 0,
            total_bytes: u64::try_from(payload.len())?,
            skipped: 0,
        },
    )?;
    assert_eq!(offer.get("top_level"), Some(&json!(["single.dat"])));
    assert_eq!(
        blake3::hash(&std::fs::read(dest.join("single.dat"))?),
        blake3::hash(&payload)
    );

    Ok(())
}

#[test]
fn receive_connect_start_bounds_unknown_word_and_sanitizes_technical_english() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let cfg = c_str(&make_cfg_json("ws://127.0.0.1:4000", "", false))?;
    let en = c_str("en-US")?;

    // 20 KiB unknown word containing Bidi RLO and ANSI ESC must fail offline with
    // bounded, sanitized technical_english (< 256 bytes, zero raw hidden chars).
    let huge_code = c_str(&format!("7-harbor-\x1b\u{202E}{}", "x".repeat(20_000)))?;
    // SAFETY: All four pointers are live NUL-terminated CStrings.
    let sid = unsafe {
        totaldrop_win_receive_connect_start(
            cfg.as_ptr(),
            huge_code.as_ptr(),
            en.as_ptr(),
            en.as_ptr(),
        )
    };
    assert_ne!(sid, 0);
    let mut evs = Vec::new();
    let fail = wait_for_event(sid, &mut evs, "failed", Duration::from_secs(5))?;
    assert_eq!(
        fail.get("l10n_key").and_then(Value::as_str),
        Some("errorInvalidCode")
    );
    let tech = fail
        .get("technical_english")
        .and_then(Value::as_str)
        .ok_or("missing technical_english")?;
    assert!(
        tech.len() < 256,
        "expected bounded technical_english (< 256 bytes), got {} bytes",
        tech.len()
    );
    assert!(
        tech.contains("..."),
        "expected truncated preview '...' in {tech:?}"
    );
    assert!(
        !tech.chars().any(totaldrop_l10n::is_hidden),
        "leaked raw hidden char in technical_english: {tech:?}"
    );
    assert_eq!(totaldrop_win_session_destroy(sid), FFI_OK);
    Ok(())
}

#[test]
fn send_files_start_rejects_bad_rendezvous_url_before_disk_scan() -> TestResult {
    let _guard = SHUTDOWN_GATE.read().map_err(|_| "lock poisoned")?;
    let en = c_str("en-US")?;
    let missing_path = std::env::temp_dir().join(format!(
        "totaldrop-nonexistent-early-url-check-{}.bin",
        std::process::id()
    ));
    let paths_c = c_str(&serde_json::to_string(&vec![
        missing_path.to_string_lossy().into_owned(),
    ])?)?;

    for (bad_url, expected_substr) in [
        ("http://127.0.0.1:4000", "must start with wss://"),
        (
            "ws://localhost@evil.example",
            "the server address must not contain a user name",
        ),
        (
            "ws://192.168.1.5:4000",
            "unencrypted ws:// is only allowed for a server on this machine",
        ),
        ("wss://", "invalid server address"),
    ] {
        let cfg = c_str(&make_cfg_json(bad_url, "", false))?;
        // SAFETY: All four pointers are live NUL-terminated CStrings.
        let sid = unsafe {
            totaldrop_win_send_files_start(cfg.as_ptr(), paths_c.as_ptr(), en.as_ptr(), en.as_ptr())
        };
        assert_ne!(sid, 0);
        let mut evs = Vec::new();
        let fail = wait_for_event(sid, &mut evs, "failed", Duration::from_secs(5))?;
        assert_eq!(
            fail.get("kind").and_then(Value::as_str),
            Some("bad_server"),
            "expected bad_server before disk scan for {bad_url:?}, got {fail}"
        );
        assert_eq!(
            fail.get("l10n_key").and_then(Value::as_str),
            Some("errorBadServer"),
            "expected errorBadServer before disk scan for {bad_url:?}, got {fail}"
        );
        assert!(
            fail.get("technical_english")
                .and_then(Value::as_str)
                .is_some_and(|t| t.contains(expected_substr)),
            "expected {expected_substr:?} in technical_english for {bad_url:?}, got {fail}"
        );
        assert_eq!(totaldrop_win_session_destroy(sid), FFI_OK);
    }

    Ok(())
}
