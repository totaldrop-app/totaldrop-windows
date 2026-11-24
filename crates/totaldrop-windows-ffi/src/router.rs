// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Monotonic `u64` handle registry and state helpers for Phase 3 WinUI 3
//! single-window Named Pipe IPC routing (`WinUiWindowRouter`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use serde::Deserialize;
use totaldrop_windows_bridge::{
    ActivationError, RouterDecision, WinUiBridgeMessage, WinUiWindowRouter, WindowsActivityState,
    WindowsLocalizer,
};

use crate::{FFI_ERR_INTERNAL, FFI_ERR_INVALID_HANDLE, FFI_OK};

static NEXT_ROUTER_ID: AtomicU64 = AtomicU64::new(1);

static ROUTERS: LazyLock<Mutex<HashMap<u64, Arc<Mutex<WinUiWindowRouter>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Errors returned by router handle registry lookups and router operations.
pub(crate) enum RouterCallError {
    InvalidHandle,
    Poisoned,
    Activation(ActivationError),
}

/// FFI deserialization adapter for [`WindowsActivityState`] allowing omitted
/// optional fields (`code`, `done_bytes`, `total_bytes`) while still rejecting
/// unknown `"state"` tags or wrong field types.
#[derive(Debug, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum FfiActivityState {
    Idle,
    PreparingSend,
    WaitingForPeer {
        #[serde(default)]
        code: String,
    },
    ConnectingReceive {
        #[serde(default)]
        code: String,
    },
    OfferPromptPending,
    Transferring {
        #[serde(default)]
        done_bytes: u64,
        #[serde(default)]
        total_bytes: u64,
    },
    ShowingTextNote,
}

impl FfiActivityState {
    pub(crate) fn into_bridge_state(self) -> WindowsActivityState {
        match self {
            Self::Idle => WindowsActivityState::Idle,
            Self::PreparingSend => WindowsActivityState::PreparingSend,
            Self::WaitingForPeer { code } => WindowsActivityState::WaitingForPeer { code },
            Self::ConnectingReceive { code } => WindowsActivityState::ConnectingReceive { code },
            Self::OfferPromptPending => WindowsActivityState::OfferPromptPending,
            Self::Transferring {
                done_bytes,
                total_bytes,
            } => WindowsActivityState::Transferring {
                done_bytes,
                total_bytes,
            },
            Self::ShowingTextNote => WindowsActivityState::ShowingTextNote,
        }
    }
}

/// Maps an [`ActivationError`] to its canonical `l10n_key` for the 4-field
/// C ABI error envelope.
pub(crate) const fn activation_error_l10n_key(err: &ActivationError) -> &'static str {
    match err {
        ActivationError::EmptyPath
        | ActivationError::ControlCharacter
        | ActivationError::PathTooLong { .. }
        | ActivationError::NotAbsoluteWindowsPath
        | ActivationError::DeviceNamespaceForbidden
        | ActivationError::DotTraversalSegment
        | ActivationError::ForbiddenSegmentCharacter(_)
        | ActivationError::TrailingDotOrSpace
        | ActivationError::TooManyItems { .. }
        | ActivationError::EmptyExplorerSelection => "errorStorage",
        ActivationError::InvalidUri(uri_err) => uri_err.l10n_key(),
        ActivationError::EnvelopeTooLarge { .. }
        | ActivationError::MalformedIpcFrame
        | ActivationError::UnsupportedSchemaVersion(_)
        | ActivationError::InvalidJson(_)
        | ActivationError::MalformedCommandLine => "errorOther",
    }
}

fn next_router_id() -> u64 {
    loop {
        let id = NEXT_ROUTER_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

fn lookup_router(router_id: u64) -> Result<Arc<Mutex<WinUiWindowRouter>>, RouterCallError> {
    if router_id == 0 {
        return Err(RouterCallError::InvalidHandle);
    }
    let guard = ROUTERS.lock().map_err(|_| RouterCallError::Poisoned)?;
    guard
        .get(&router_id)
        .cloned()
        .ok_or(RouterCallError::InvalidHandle)
}

pub(crate) fn create_router(
    session_id: u32,
    localizer: WindowsLocalizer,
    app_version: &str,
    animations_enabled: bool,
) -> u64 {
    let router = WinUiWindowRouter::new(session_id, localizer, app_version, animations_enabled);
    let id = next_router_id();
    let Ok(mut guard) = ROUTERS.lock() else {
        return 0;
    };
    guard.insert(id, Arc::new(Mutex::new(router)));
    id
}

pub(crate) fn ingest_ipc_bytes(
    router_id: u64,
    chunk: &[u8],
) -> Result<Vec<RouterDecision>, RouterCallError> {
    let entry = lookup_router(router_id)?;
    let mut router = entry.lock().map_err(|_| RouterCallError::Poisoned)?;
    router
        .ingest_ipc_bytes(chunk)
        .map_err(RouterCallError::Activation)
}

pub(crate) fn finish_ipc_eof(router_id: u64) -> Result<(), RouterCallError> {
    let entry = lookup_router(router_id)?;
    let mut router = entry.lock().map_err(|_| RouterCallError::Poisoned)?;
    router.finish_ipc_eof().map_err(RouterCallError::Activation)
}

pub(crate) fn update_locale(
    router_id: u64,
    localizer: WindowsLocalizer,
) -> Result<WinUiBridgeMessage, RouterCallError> {
    let entry = lookup_router(router_id)?;
    let mut router = entry.lock().map_err(|_| RouterCallError::Poisoned)?;
    Ok(router.update_locale(localizer))
}

pub(crate) fn set_animations(
    router_id: u64,
    enabled: bool,
) -> Result<WinUiBridgeMessage, RouterCallError> {
    let entry = lookup_router(router_id)?;
    let mut router = entry.lock().map_err(|_| RouterCallError::Poisoned)?;
    Ok(router.set_animations_enabled(enabled))
}

pub(crate) fn set_activity(
    router_id: u64,
    activity: WindowsActivityState,
) -> Result<WinUiBridgeMessage, RouterCallError> {
    let entry = lookup_router(router_id)?;
    let mut router = entry.lock().map_err(|_| RouterCallError::Poisoned)?;
    Ok(router.set_activity(activity))
}

pub(crate) fn drain_ndjson(router_id: u64) -> Result<String, RouterCallError> {
    let entry = lookup_router(router_id)?;
    let mut router = entry.lock().map_err(|_| RouterCallError::Poisoned)?;
    router.drain_ndjson().map_err(RouterCallError::Activation)
}

pub(crate) fn destroy_router(router_id: u64) -> i32 {
    if router_id == 0 {
        return FFI_ERR_INVALID_HANDLE;
    }
    let Ok(mut guard) = ROUTERS.lock() else {
        return FFI_ERR_INTERNAL;
    };
    if guard.remove(&router_id).is_some() {
        FFI_OK
    } else {
        FFI_ERR_INVALID_HANDLE
    }
}
