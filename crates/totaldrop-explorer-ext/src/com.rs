// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Win32 COM server (`DllMain`, `DllGetClassObject`, `DllCanUnloadNow`,
//! `IClassFactory`, and stateless `IExplorerCommand`) for Windows 11 File
//! Explorer integration (`totaldrop_explorer_ext.dll`, ADR 0016).

use std::ffi::c_void;
use std::mem::size_of;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use totaldrop_windows_bridge::activation::{
    ActivationError, ExplorerLaunchTransport, plan_explorer_invocation, session_named_pipe_path,
};
use windows_sys::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, CloseHandle, E_FAIL, E_INVALIDARG,
    E_NOINTERFACE, E_NOTIMPL, E_OUTOFMEMORY, E_POINTER, ERROR_PIPE_BUSY, GENERIC_WRITE,
    GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE, S_FALSE, S_OK,
};
use windows_sys::Win32::Globalization::{
    GetThreadPreferredUILanguages, GetUserPreferredUILanguages, MUI_LANGUAGE_NAME,
    MUI_MERGE_SYSTEM_FALLBACK, MUI_MERGE_USER_FALLBACK,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    WriteFile,
};
use windows_sys::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleFileNameW, GetModuleHandleExW,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcessId, PROCESS_INFORMATION, STARTUPINFOW, Sleep,
};
use windows_sys::Win32::UI::Shell::{ECF_DEFAULT, ECS_ENABLED, ECS_HIDDEN, SIGDN_FILESYSPATH};
use windows_sys::core::{BOOL, GUID, HRESULT, IID_IUnknown, IUnknown_Vtbl, PCWSTR, PWSTR};

use crate::{
    CLSID_TOTALDROP_EXPLORER_COMMAND_U128, HRESULT_ERROR_BUFFER_OVERFLOW,
    MAX_EXPLORER_SELECTION_ITEMS, format_icon_resource_spec, hresult_from_win32,
    parse_mui_multi_sz, prepare_explorer_envelope, resolve_verb_title, sibling_app_exe_path,
};

/// `CLSID` of TotalDrop's File Explorer `IExplorerCommand` server
/// (`{8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0}`).
pub const CLSID_TOTALDROP_EXPLORER_COMMAND: GUID =
    GUID::from_u128(CLSID_TOTALDROP_EXPLORER_COMMAND_U128);

/// Standard COM `IID_IClassFactory` (`{00000001-0000-0000-C000-000000000046}`).
pub const IID_ICLASS_FACTORY: GUID = GUID::from_u128(0x0000_0001_0000_0000_c000_0000_0000_0046);

/// Standard Shell `IID_IExplorerCommand` (`{A08CE4D0-FA25-44AB-B57C-C7B1C323E0B9}`).
pub const IID_IEXPLORER_COMMAND: GUID = GUID::from_u128(0xa08c_e4d0_fa25_44ab_b57c_c7b1_c323_e0b9);

/// Standard Shell `IID_IShellItemArray` (`{B63EA76D-1F85-456F-A19C-48159EFA858B}`).
pub const IID_ISHELL_ITEM_ARRAY: GUID = GUID::from_u128(0xb63e_a76d_1f85_456f_a19c_4815_9efa_858b);

/// Standard Shell `IID_IShellItem` (`{43826D1E-E718-42EE-BC55-A1E261C37BFE}`).
pub const IID_ISHELL_ITEM: GUID = GUID::from_u128(0x4382_6d1e_e718_42ee_bc55_a1e2_61c3_7bfe);

static MODULE_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static MODULE_REF_COUNT: AtomicU32 = AtomicU32::new(0);

/// Compares two Win32 [`GUID`] values for byte-for-byte equality.
#[must_use]
pub const fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1
        && a.data2 == b.data2
        && a.data3 == b.data3
        && u64::from_ne_bytes(a.data4) == u64::from_ne_bytes(b.data4)
}

fn saturating_add_ref(counter: &AtomicU32) -> u32 {
    match counter.try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
        cur.checked_add(1)
    }) {
        Ok(prev) => prev.saturating_add(1),
        Err(cur) => cur,
    }
}

fn increment_module_ref() {
    let _ = saturating_add_ref(&MODULE_REF_COUNT);
}

fn decrement_module_ref() {
    let _ = MODULE_REF_COUNT.try_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
        cur.checked_sub(1)
    });
}

fn guard_hresult<F>(f: F) -> HRESULT
where
    F: FnOnce() -> HRESULT,
{
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(E_FAIL)
}

/// COM vtable layout for `IClassFactory` (`unknwnbase.h`, slots 0..=4).
#[repr(C)]
pub struct IClassFactoryVtbl {
    /// Inherited `IUnknown` slots (0: `QueryInterface`, 1: `AddRef`, 2: `Release`).
    pub base: IUnknown_Vtbl,
    /// Slot 3: `IClassFactory::CreateInstance`.
    pub create_instance: unsafe extern "system" fn(
        this: *mut c_void,
        punk_outer: *mut c_void,
        riid: *const GUID,
        ppv_object: *mut *mut c_void,
    ) -> HRESULT,
    /// Slot 4: `IClassFactory::LockServer`.
    pub lock_server: unsafe extern "system" fn(this: *mut c_void, f_lock: BOOL) -> HRESULT,
}

/// COM vtable layout for `IExplorerCommand` (`shobjidl_core.idl`, slots 0..=10).
#[repr(C)]
pub struct IExplorerCommandVtbl {
    /// Inherited `IUnknown` slots (0..=2).
    pub base: IUnknown_Vtbl,
    /// Slot 3: `IExplorerCommand::GetTitle`.
    pub get_title: unsafe extern "system" fn(
        this: *mut c_void,
        psi_item_array: *mut IShellItemArray,
        ppsz_name: *mut PWSTR,
    ) -> HRESULT,
    /// Slot 4: `IExplorerCommand::GetIcon`.
    pub get_icon: unsafe extern "system" fn(
        this: *mut c_void,
        psi_item_array: *mut IShellItemArray,
        ppsz_icon: *mut PWSTR,
    ) -> HRESULT,
    /// Slot 5: `IExplorerCommand::GetToolTip`.
    pub get_tool_tip: unsafe extern "system" fn(
        this: *mut c_void,
        psi_item_array: *mut IShellItemArray,
        ppsz_infotip: *mut PWSTR,
    ) -> HRESULT,
    /// Slot 6: `IExplorerCommand::GetCanonicalName`.
    pub get_canonical_name:
        unsafe extern "system" fn(this: *mut c_void, pguid_command_name: *mut GUID) -> HRESULT,
    /// Slot 7: `IExplorerCommand::GetState`.
    pub get_state: unsafe extern "system" fn(
        this: *mut c_void,
        psi_item_array: *mut IShellItemArray,
        f_ok_to_be_slow: BOOL,
        p_cmd_state: *mut i32,
    ) -> HRESULT,
    /// Slot 8: `IExplorerCommand::Invoke`.
    pub invoke: unsafe extern "system" fn(
        this: *mut c_void,
        psi_item_array: *mut IShellItemArray,
        pbc: *mut c_void,
    ) -> HRESULT,
    /// Slot 9: `IExplorerCommand::GetFlags`.
    pub get_flags: unsafe extern "system" fn(this: *mut c_void, p_flags: *mut i32) -> HRESULT,
    /// Slot 10: `IExplorerCommand::EnumSubCommands`.
    pub enum_sub_commands:
        unsafe extern "system" fn(this: *mut c_void, pp_enum: *mut *mut c_void) -> HRESULT,
}

/// COM interface pointer wrapper for `IShellItemArray`.
#[repr(C)]
pub struct IShellItemArray {
    /// Pointer to the `IShellItemArray` COM vtable.
    pub vtbl: *const IShellItemArrayVtbl,
}

/// COM vtable layout for `IShellItemArray` (`shobjidl_core.idl`, slots 0..=9).
#[repr(C)]
pub struct IShellItemArrayVtbl {
    /// Inherited `IUnknown` slots (0..=2).
    pub base: IUnknown_Vtbl,
    /// Slot 3: `IShellItemArray::BindToHandler`.
    pub bind_to_handler: unsafe extern "system" fn(
        this: *mut c_void,
        pbc: *mut c_void,
        bhid: *const GUID,
        riid: *const GUID,
        ppv_out: *mut *mut c_void,
    ) -> HRESULT,
    /// Slot 4: `IShellItemArray::GetPropertyStore`.
    pub get_property_store: unsafe extern "system" fn(
        this: *mut c_void,
        flags: i32,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> HRESULT,
    /// Slot 5: `IShellItemArray::GetPropertyDescriptionList`.
    pub get_property_description_list: unsafe extern "system" fn(
        this: *mut c_void,
        key_type: *const c_void,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> HRESULT,
    /// Slot 6: `IShellItemArray::GetAttributes`.
    pub get_attributes: unsafe extern "system" fn(
        this: *mut c_void,
        attrib_flags: i32,
        sfgao_mask: u32,
        psfgao_attribs: *mut u32,
    ) -> HRESULT,
    /// Slot 7: `IShellItemArray::GetCount`.
    pub get_count: unsafe extern "system" fn(this: *mut c_void, pdw_num_items: *mut u32) -> HRESULT,
    /// Slot 8: `IShellItemArray::GetItemAt`.
    pub get_item_at: unsafe extern "system" fn(
        this: *mut c_void,
        dw_index: u32,
        ppsi: *mut *mut IShellItem,
    ) -> HRESULT,
    /// Slot 9: `IShellItemArray::EnumItems`.
    pub enum_items: unsafe extern "system" fn(
        this: *mut c_void,
        ppenum_shell_items: *mut *mut c_void,
    ) -> HRESULT,
}

/// COM interface pointer wrapper for `IShellItem`.
#[repr(C)]
pub struct IShellItem {
    /// Pointer to the `IShellItem` COM vtable.
    pub vtbl: *const IShellItemVtbl,
}

/// COM vtable layout for `IShellItem` (`shobjidl_core.idl`, slots 0..=7).
#[repr(C)]
pub struct IShellItemVtbl {
    /// Inherited `IUnknown` slots (0..=2).
    pub base: IUnknown_Vtbl,
    /// Slot 3: `IShellItem::BindToHandler`.
    pub bind_to_handler: unsafe extern "system" fn(
        this: *mut c_void,
        pbc: *mut c_void,
        bhid: *const GUID,
        riid: *const GUID,
        ppv_out: *mut *mut c_void,
    ) -> HRESULT,
    /// Slot 4: `IShellItem::GetParent`.
    pub get_parent:
        unsafe extern "system" fn(this: *mut c_void, ppsi: *mut *mut IShellItem) -> HRESULT,
    /// Slot 5: `IShellItem::GetDisplayName`.
    pub get_display_name: unsafe extern "system" fn(
        this: *mut c_void,
        sigdn_name: i32,
        ppsz_name: *mut PWSTR,
    ) -> HRESULT,
    /// Slot 6: `IShellItem::GetAttributes`.
    pub get_attributes: unsafe extern "system" fn(
        this: *mut c_void,
        sfgao_mask: u32,
        psfgao_attribs: *mut u32,
    ) -> HRESULT,
    /// Slot 7: `IShellItem::Compare`.
    pub compare: unsafe extern "system" fn(
        this: *mut c_void,
        psi: *mut IShellItem,
        hint: u32,
        pi_order: *mut i32,
    ) -> HRESULT,
}

/// RAII guard ensuring `IShellItem::Release` runs on every exit path.
struct ShellItemGuard(NonNull<IShellItem>);

impl Drop for ShellItemGuard {
    fn drop(&mut self) {
        let raw = self.0.as_ptr();
        // SAFETY: `raw` is a live COM `IShellItem` pointer returned by
        // `IShellItemArray::GetItemAt` with a non-null vtable.
        unsafe {
            let vtbl = (*raw).vtbl;
            if !vtbl.is_null() {
                let _ = ((*vtbl).base.Release)(raw.cast());
            }
        }
    }
}

/// RAII guard ensuring a Win32 `HANDLE` is closed on every exit path.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` is a valid owned Win32 kernel handle.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

// ---------------------------------------------------------------------------
// IClassFactory COM Object

#[repr(C)]
struct TotalDropClassFactory {
    // First #[repr(C)] field: COM interface vtable pointer read through raw ABI pointers.
    _vtbl: *const IClassFactoryVtbl,
    ref_count: AtomicU32,
}

static CLASS_FACTORY_VTBL: IClassFactoryVtbl = IClassFactoryVtbl {
    base: IUnknown_Vtbl {
        QueryInterface: factory_query_interface,
        AddRef: factory_add_ref,
        Release: factory_release,
    },
    create_instance: factory_create_instance,
    lock_server: factory_lock_server,
};

impl TotalDropClassFactory {
    fn new_raw() -> *mut Self {
        increment_module_ref();
        Box::into_raw(Box::new(Self {
            _vtbl: &CLASS_FACTORY_VTBL,
            ref_count: AtomicU32::new(1),
        }))
    }
}

impl Drop for TotalDropClassFactory {
    fn drop(&mut self) {
        decrement_module_ref();
    }
}

unsafe extern "system" fn factory_query_interface(
    this: *mut c_void,
    riid: *const GUID,
    ppv_object: *mut *mut c_void,
) -> HRESULT {
    guard_hresult(|| {
        if ppv_object.is_null() {
            return E_POINTER;
        }
        // SAFETY: Caller passed a valid writable `ppv_object` out-pointer.
        unsafe { *ppv_object = ptr::null_mut() };
        if this.is_null() || riid.is_null() {
            return E_INVALIDARG;
        }
        // SAFETY: `riid` is non-null and points to a valid `GUID`.
        let iid = unsafe { &*riid };
        if guid_eq(iid, &IID_IUnknown) || guid_eq(iid, &IID_ICLASS_FACTORY) {
            // SAFETY: `this` is a live `TotalDropClassFactory`.
            let _ = unsafe { factory_add_ref(this) };
            // SAFETY: `ppv_object` was validated non-null above.
            unsafe { *ppv_object = this };
            S_OK
        } else {
            E_NOINTERFACE
        }
    })
}

unsafe extern "system" fn factory_add_ref(this: *mut c_void) -> u32 {
    if this.is_null() {
        return 0;
    }
    // SAFETY: `this` points to a live heap-allocated `TotalDropClassFactory`.
    let factory = unsafe { &*this.cast::<TotalDropClassFactory>() };
    saturating_add_ref(&factory.ref_count)
}

unsafe extern "system" fn factory_release(this: *mut c_void) -> u32 {
    if this.is_null() {
        return 0;
    }
    let ptr_typed = this.cast::<TotalDropClassFactory>();
    // SAFETY: `ptr_typed` points to a live `TotalDropClassFactory`.
    let prev = unsafe { &*ptr_typed }
        .ref_count
        .fetch_sub(1, Ordering::AcqRel);
    if prev == 1 {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: Reference count reached zero; this is the final owner.
            let owned = unsafe { Box::from_raw(ptr_typed) };
            drop(owned);
        }));
        0
    } else {
        prev.saturating_sub(1)
    }
}

unsafe extern "system" fn factory_create_instance(
    _this: *mut c_void,
    punk_outer: *mut c_void,
    riid: *const GUID,
    ppv_object: *mut *mut c_void,
) -> HRESULT {
    guard_hresult(|| {
        if ppv_object.is_null() {
            return E_POINTER;
        }
        // SAFETY: Caller passed a valid writable `ppv_object` out-pointer.
        unsafe { *ppv_object = ptr::null_mut() };
        if !punk_outer.is_null() {
            return CLASS_E_NOAGGREGATION;
        }
        if riid.is_null() {
            return E_INVALIDARG;
        }

        let cmd = TotalDropExplorerCommand::new_raw();
        // SAFETY: `cmd` is freshly allocated with refcount 1; `riid` and
        // `ppv_object` were validated non-null above.
        let hr = unsafe { cmd_query_interface(cmd.cast(), riid, ppv_object) };
        // SAFETY: Releases the initial creation reference (keeping refcount 1
        // on `QueryInterface` success, or destroying `cmd` cleanly on failure).
        let _ = unsafe { cmd_release(cmd.cast()) };
        hr
    })
}

unsafe extern "system" fn factory_lock_server(_this: *mut c_void, f_lock: BOOL) -> HRESULT {
    guard_hresult(|| {
        if f_lock != 0 {
            increment_module_ref();
        } else {
            decrement_module_ref();
        }
        S_OK
    })
}

// ---------------------------------------------------------------------------
// Stateless IExplorerCommand COM Object (Win11 double-instantiation safe)

#[repr(C)]
struct TotalDropExplorerCommand {
    // First #[repr(C)] field: COM interface vtable pointer read through raw ABI pointers.
    _vtbl: *const IExplorerCommandVtbl,
    ref_count: AtomicU32,
}

static EXPLORER_COMMAND_VTBL: IExplorerCommandVtbl = IExplorerCommandVtbl {
    base: IUnknown_Vtbl {
        QueryInterface: cmd_query_interface,
        AddRef: cmd_add_ref,
        Release: cmd_release,
    },
    get_title: cmd_get_title,
    get_icon: cmd_get_icon,
    get_tool_tip: cmd_get_tool_tip,
    get_canonical_name: cmd_get_canonical_name,
    get_state: cmd_get_state,
    invoke: cmd_invoke,
    get_flags: cmd_get_flags,
    enum_sub_commands: cmd_enum_sub_commands,
};

impl TotalDropExplorerCommand {
    fn new_raw() -> *mut Self {
        increment_module_ref();
        Box::into_raw(Box::new(Self {
            _vtbl: &EXPLORER_COMMAND_VTBL,
            ref_count: AtomicU32::new(1),
        }))
    }
}

impl Drop for TotalDropExplorerCommand {
    fn drop(&mut self) {
        decrement_module_ref();
    }
}

unsafe extern "system" fn cmd_query_interface(
    this: *mut c_void,
    riid: *const GUID,
    ppv_object: *mut *mut c_void,
) -> HRESULT {
    guard_hresult(|| {
        if ppv_object.is_null() {
            return E_POINTER;
        }
        // SAFETY: Caller passed a valid writable `ppv_object` out-pointer.
        unsafe { *ppv_object = ptr::null_mut() };
        if this.is_null() || riid.is_null() {
            return E_INVALIDARG;
        }
        // SAFETY: `riid` is non-null and points to a valid `GUID`.
        let iid = unsafe { &*riid };
        if guid_eq(iid, &IID_IUnknown) || guid_eq(iid, &IID_IEXPLORER_COMMAND) {
            // SAFETY: `this` is a live `TotalDropExplorerCommand`.
            let _ = unsafe { cmd_add_ref(this) };
            // SAFETY: `ppv_object` was validated non-null above.
            unsafe { *ppv_object = this };
            S_OK
        } else {
            E_NOINTERFACE
        }
    })
}

unsafe extern "system" fn cmd_add_ref(this: *mut c_void) -> u32 {
    if this.is_null() {
        return 0;
    }
    // SAFETY: `this` points to a live `TotalDropExplorerCommand`.
    let cmd = unsafe { &*this.cast::<TotalDropExplorerCommand>() };
    saturating_add_ref(&cmd.ref_count)
}

unsafe extern "system" fn cmd_release(this: *mut c_void) -> u32 {
    if this.is_null() {
        return 0;
    }
    let ptr_typed = this.cast::<TotalDropExplorerCommand>();
    // SAFETY: `ptr_typed` points to a live `TotalDropExplorerCommand`.
    let prev = unsafe { &*ptr_typed }
        .ref_count
        .fetch_sub(1, Ordering::AcqRel);
    if prev == 1 {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: Reference count reached zero; this is the final owner.
            let owned = unsafe { Box::from_raw(ptr_typed) };
            drop(owned);
        }));
        0
    } else {
        prev.saturating_sub(1)
    }
}

unsafe extern "system" fn cmd_get_title(
    _this: *mut c_void,
    _psi_item_array: *mut IShellItemArray,
    ppsz_name: *mut PWSTR,
) -> HRESULT {
    guard_hresult(|| {
        if ppsz_name.is_null() {
            return E_POINTER;
        }
        // SAFETY: Caller passed a valid writable `ppsz_name` out-pointer.
        unsafe { *ppsz_name = ptr::null_mut() };

        let preferred = query_preferred_ui_languages();
        let title = resolve_verb_title(&preferred);
        match alloc_co_task_mem_wstr(&title) {
            Ok(wstr) => {
                // SAFETY: `ppsz_name` was validated non-null above.
                unsafe { *ppsz_name = wstr };
                S_OK
            }
            Err(hr) => hr,
        }
    })
}

unsafe extern "system" fn cmd_get_icon(
    _this: *mut c_void,
    _psi_item_array: *mut IShellItemArray,
    ppsz_icon: *mut PWSTR,
) -> HRESULT {
    guard_hresult(|| {
        if ppsz_icon.is_null() {
            return E_POINTER;
        }
        // SAFETY: Caller passed a valid writable `ppsz_icon` out-pointer.
        unsafe { *ppsz_icon = ptr::null_mut() };

        let Some(module_path) = resolve_current_module_path() else {
            return E_FAIL;
        };
        let icon_spec = format_icon_resource_spec(&module_path);
        match alloc_co_task_mem_wstr(&icon_spec) {
            Ok(wstr) => {
                // SAFETY: `ppsz_icon` was validated non-null above.
                unsafe { *ppsz_icon = wstr };
                S_OK
            }
            Err(hr) => hr,
        }
    })
}

unsafe extern "system" fn cmd_get_tool_tip(
    _this: *mut c_void,
    _psi_item_array: *mut IShellItemArray,
    ppsz_infotip: *mut PWSTR,
) -> HRESULT {
    guard_hresult(|| {
        if ppsz_infotip.is_null() {
            return E_POINTER;
        }
        // SAFETY: Caller passed a valid writable `ppsz_infotip` out-pointer.
        unsafe { *ppsz_infotip = ptr::null_mut() };
        E_NOTIMPL
    })
}

unsafe extern "system" fn cmd_get_canonical_name(
    _this: *mut c_void,
    pguid_command_name: *mut GUID,
) -> HRESULT {
    guard_hresult(|| {
        if pguid_command_name.is_null() {
            return E_POINTER;
        }
        // SAFETY: Caller passed a valid writable `GUID` out-pointer.
        unsafe { *pguid_command_name = CLSID_TOTALDROP_EXPLORER_COMMAND };
        S_OK
    })
}

unsafe extern "system" fn cmd_get_state(
    _this: *mut c_void,
    psi_item_array: *mut IShellItemArray,
    _f_ok_to_be_slow: BOOL,
    p_cmd_state: *mut i32,
) -> HRESULT {
    guard_hresult(|| {
        if p_cmd_state.is_null() {
            return E_POINTER;
        }
        let state = match read_shell_item_count(psi_item_array) {
            Ok(count) if count > 0 => ECS_ENABLED,
            _ => ECS_HIDDEN,
        };
        // SAFETY: Caller passed a valid writable `p_cmd_state` out-pointer.
        unsafe { *p_cmd_state = state };
        S_OK
    })
}

unsafe extern "system" fn cmd_invoke(
    _this: *mut c_void,
    psi_item_array: *mut IShellItemArray,
    _pbc: *mut c_void,
) -> HRESULT {
    guard_hresult(|| {
        if psi_item_array.is_null() {
            return E_INVALIDARG;
        }
        let count = match read_shell_item_count(psi_item_array) {
            Ok(n) => n,
            Err(hr) => return hr,
        };
        if count == 0 {
            return S_OK;
        }
        if (count as usize) > MAX_EXPLORER_SELECTION_ITEMS {
            return HRESULT_ERROR_BUFFER_OVERFLOW;
        }

        let paths = match collect_shell_item_paths(psi_item_array, count) {
            Ok(list) => list,
            Err(hr) => return hr,
        };
        if paths.is_empty() {
            return S_OK;
        }

        // SAFETY: `GetCurrentProcessId` is always safe to call.
        let pid = unsafe { GetCurrentProcessId() };
        let envelope = match prepare_explorer_envelope(&paths, Some(pid)) {
            Ok(env) => env,
            Err(
                ActivationError::TooManyItems { .. } | ActivationError::EnvelopeTooLarge { .. },
            ) => {
                return HRESULT_ERROR_BUFFER_OVERFLOW;
            }
            Err(_) => return E_INVALIDARG,
        };

        let ipc_frame = match envelope.encode_ipc_frame() {
            Ok(frame) => frame,
            Err(ActivationError::EnvelopeTooLarge { .. }) => {
                return HRESULT_ERROR_BUFFER_OVERFLOW;
            }
            Err(_) => return E_FAIL,
        };

        let session_id = current_windows_session_id(pid);
        let pipe_path = session_named_pipe_path(session_id);

        // 1. Warm single-instance Named Pipe handoff first.
        if try_send_ipc_frame_once(&pipe_path, &ipc_frame, true) {
            return S_OK;
        }

        // 2. Cold start fallback via sibling totaldrop-winui.exe (never cmd.exe/ShellExecute).
        let Some(module_path) = resolve_current_module_path() else {
            return E_FAIL;
        };
        let Some(exe_path) = sibling_app_exe_path(&module_path) else {
            return E_FAIL;
        };

        let transport = match plan_explorer_invocation(&exe_path, &envelope, session_id, false) {
            Ok(plan) => plan,
            Err(
                ActivationError::TooManyItems { .. } | ActivationError::EnvelopeTooLarge { .. },
            ) => {
                return HRESULT_ERROR_BUFFER_OVERFLOW;
            }
            Err(_) => return E_FAIL,
        };

        match transport {
            ExplorerLaunchTransport::DirectCommandLine { command_line, .. } => {
                launch_process_no_shell(&exe_path, &command_line)
            }
            ExplorerLaunchTransport::NamedPipeIpc {
                pipe_path: target_pipe,
                cold_start_command_line,
                ipc_frame: planned_frame,
            } => {
                if !cold_start_command_line.is_empty() {
                    let launch_hr = launch_process_no_shell(&exe_path, &cold_start_command_line);
                    if launch_hr < 0 {
                        return launch_hr;
                    }
                }
                // Enforce a true 5-second wall-clock deadline while waiting for
                // the cold-started window to open its Named Pipe (so repeated
                // ERROR_PIPE_BUSY waits cannot stretch handoff past 5 seconds).
                const COLD_START_PIPE_TIMEOUT: Duration = Duration::from_secs(5);
                let started = Instant::now();
                loop {
                    if try_send_ipc_frame_once(&target_pipe, &planned_frame, true) {
                        return S_OK;
                    }
                    if started.elapsed() >= COLD_START_PIPE_TIMEOUT {
                        return E_FAIL;
                    }
                    // SAFETY: `Sleep` suspends the caller thread briefly on cold-start handoff.
                    unsafe { Sleep(50) };
                }
            }
        }
    })
}

unsafe extern "system" fn cmd_get_flags(_this: *mut c_void, p_flags: *mut i32) -> HRESULT {
    guard_hresult(|| {
        if p_flags.is_null() {
            return E_POINTER;
        }
        // SAFETY: Caller passed a valid writable `p_flags` out-pointer.
        unsafe { *p_flags = ECF_DEFAULT };
        S_OK
    })
}

unsafe extern "system" fn cmd_enum_sub_commands(
    _this: *mut c_void,
    pp_enum: *mut *mut c_void,
) -> HRESULT {
    guard_hresult(|| {
        if !pp_enum.is_null() {
            // SAFETY: Caller passed a valid writable `pp_enum` out-pointer.
            unsafe { *pp_enum = ptr::null_mut() };
        }
        E_NOTIMPL
    })
}

// ---------------------------------------------------------------------------
// Win32 Helpers

fn to_utf16_nul(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn alloc_co_task_mem_wstr(text: &str) -> Result<PWSTR, HRESULT> {
    let utf16 = to_utf16_nul(text);
    let Some(byte_len) = utf16.len().checked_mul(size_of::<u16>()) else {
        return Err(E_OUTOFMEMORY);
    };
    // SAFETY: `CoTaskMemAlloc` allocates COM task memory freed by the shell via `CoTaskMemFree`.
    let raw = unsafe { CoTaskMemAlloc(byte_len) }.cast::<u16>();
    if raw.is_null() {
        return Err(E_OUTOFMEMORY);
    }
    // SAFETY: `raw` has space for `utf16.len()` `u16` elements and does not overlap `utf16`.
    unsafe { ptr::copy_nonoverlapping(utf16.as_ptr(), raw, utf16.len()) };
    Ok(raw)
}

fn read_co_task_mem_wstr_and_free(pwstr: PWSTR) -> Option<String> {
    if pwstr.is_null() {
        return None;
    }
    // Bounded UTF-16 scan up to Win32 extended-path ceiling (32,768 code units).
    let mut len: usize = 0;
    const MAX_SCAN_UNITS: usize = 32_768;
    while len < MAX_SCAN_UNITS {
        // SAFETY: `pwstr` is a NUL-terminated COM string allocated by `IShellItem::GetDisplayName`.
        let unit = unsafe { *pwstr.add(len) };
        if unit == 0 {
            break;
        }
        len = len.saturating_add(1);
    }
    // SAFETY: `pwstr` contains `len` valid `u16` code units prior to the NUL terminator.
    let slice = unsafe { std::slice::from_raw_parts(pwstr, len) };
    let decoded = String::from_utf16_lossy(slice);
    // SAFETY: `pwstr` was allocated by COM (`IShellItem::GetDisplayName`) and must be freed once.
    unsafe { CoTaskMemFree(pwstr.cast()) };
    Some(decoded)
}

fn query_mui_languages_with(
    query: unsafe extern "system" fn(u32, *mut u32, PWSTR, *mut u32) -> BOOL,
    flags: u32,
) -> Vec<String> {
    let mut num_langs: u32 = 0;
    let mut buf_len: u32 = 0;
    // SAFETY: Standard two-pass Win32 MUI query with null buffer to measure required `u16` length.
    let ok_size = unsafe { query(flags, &mut num_langs, ptr::null_mut(), &mut buf_len) };
    if ok_size == 0 || buf_len == 0 {
        return Vec::new();
    }
    let capped_len = (buf_len as usize).min(4096);
    let mut buf = vec![0u16; capped_len];
    let Ok(mut out_len) = u32::try_from(buf.len()) else {
        return Vec::new();
    };
    // SAFETY: `buf` has capacity `out_len` `u16` code units.
    let ok_fill = unsafe { query(flags, &mut num_langs, buf.as_mut_ptr(), &mut out_len) };
    if ok_fill == 0 {
        return Vec::new();
    }
    let valid_len = (out_len as usize).min(buf.len());
    match buf.get(..valid_len) {
        Some(slice) => parse_mui_multi_sz(slice),
        None => Vec::new(),
    }
}

fn query_preferred_ui_languages() -> Vec<String> {
    let thread_flags = MUI_LANGUAGE_NAME | MUI_MERGE_USER_FALLBACK | MUI_MERGE_SYSTEM_FALLBACK;
    let thread_langs = query_mui_languages_with(GetThreadPreferredUILanguages, thread_flags);
    if !thread_langs.is_empty() {
        return thread_langs;
    }
    query_mui_languages_with(GetUserPreferredUILanguages, MUI_LANGUAGE_NAME)
}

fn resolve_current_module_handle() -> HMODULE {
    let stored = MODULE_HANDLE.load(Ordering::Acquire);
    if !stored.is_null() {
        return stored;
    }
    let mut module: HMODULE = ptr::null_mut();
    let anchor: extern "system" fn() -> HRESULT = DllCanUnloadNow;
    let fn_addr: PCWSTR = (anchor as *const ()).cast::<u16>();
    // SAFETY: `fn_addr` points to a code address inside this module;
    // `GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT` does not alter refcount.
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            fn_addr,
            &mut module,
        )
    };
    if ok != 0 { module } else { ptr::null_mut() }
}

fn resolve_current_module_path() -> Option<String> {
    let hmodule = resolve_current_module_handle();
    if hmodule.is_null() {
        return None;
    }
    let mut capacity: usize = 260;
    const MAX_CAP: usize = 32_768;
    loop {
        let mut buf = vec![0u16; capacity];
        let Ok(buf_len) = u32::try_from(buf.len()) else {
            return None;
        };
        // SAFETY: `buf` holds `buf_len` writable `u16` elements for `GetModuleFileNameW`.
        let copied = unsafe { GetModuleFileNameW(hmodule, buf.as_mut_ptr(), buf_len) } as usize;
        if copied == 0 {
            return None;
        }
        if copied < capacity {
            let slice = buf.get(..copied)?;
            return Some(String::from_utf16_lossy(slice));
        }
        if capacity >= MAX_CAP {
            return None;
        }
        capacity = capacity.saturating_mul(2).min(MAX_CAP);
    }
}

fn read_shell_item_count(psi_item_array: *mut IShellItemArray) -> Result<u32, HRESULT> {
    if psi_item_array.is_null() {
        return Err(E_INVALIDARG);
    }
    // SAFETY: `psi_item_array` is non-null; verify its COM vtable pointer before dereferencing.
    let vtbl = unsafe { (*psi_item_array).vtbl };
    if vtbl.is_null() {
        return Err(E_POINTER);
    }
    let mut count: u32 = 0;
    // SAFETY: Invoking `IShellItemArray::GetCount` (vtable slot 7) on a live shell array.
    let hr = unsafe { ((*vtbl).get_count)(psi_item_array.cast(), &mut count) };
    if hr < 0 { Err(hr) } else { Ok(count) }
}

fn collect_shell_item_paths(
    psi_item_array: *mut IShellItemArray,
    count: u32,
) -> Result<Vec<String>, HRESULT> {
    if psi_item_array.is_null() {
        return Err(E_INVALIDARG);
    }
    // SAFETY: `psi_item_array` is non-null; verify its COM vtable pointer.
    let array_vtbl = unsafe { (*psi_item_array).vtbl };
    if array_vtbl.is_null() {
        return Err(E_POINTER);
    }

    let mut paths = Vec::with_capacity((count as usize).min(MAX_EXPLORER_SELECTION_ITEMS));
    for index in 0..count {
        let mut raw_item: *mut IShellItem = ptr::null_mut();
        // SAFETY: Invoking `IShellItemArray::GetItemAt` (vtable slot 8).
        let hr =
            unsafe { ((*array_vtbl).get_item_at)(psi_item_array.cast(), index, &mut raw_item) };
        if hr < 0 {
            return Err(hr);
        }
        let Some(item_nn) = NonNull::new(raw_item) else {
            continue;
        };
        let _guard = ShellItemGuard(item_nn);
        // SAFETY: `item_nn` is a live `IShellItem` guarded by `ShellItemGuard`.
        let item_vtbl = unsafe { (*item_nn.as_ptr()).vtbl };
        if item_vtbl.is_null() {
            continue;
        }
        let mut pwstr: PWSTR = ptr::null_mut();
        // SAFETY: Invoking `IShellItem::GetDisplayName(SIGDN_FILESYSPATH)` (vtable slot 5).
        let name_hr = unsafe {
            ((*item_vtbl).get_display_name)(item_nn.as_ptr().cast(), SIGDN_FILESYSPATH, &mut pwstr)
        };
        if name_hr >= 0
            && let Some(path) = read_co_task_mem_wstr_and_free(pwstr)
            && !path.is_empty()
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn current_windows_session_id(pid: u32) -> u32 {
    let mut session_id: u32 = 0;
    // SAFETY: `ProcessIdToSessionId` writes into the valid `session_id` out-pointer.
    let ok = unsafe { ProcessIdToSessionId(pid, &mut session_id) };
    if ok != 0 { session_id } else { 0 }
}

fn try_send_ipc_frame_once(pipe_path: &str, frame: &[u8], retry_on_busy: bool) -> bool {
    let pipe_w = to_utf16_nul(pipe_path);
    let flags = SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;

    let mut handle = open_pipe_for_write(&pipe_w, flags);
    if handle == INVALID_HANDLE_VALUE && retry_on_busy {
        // SAFETY: `GetLastError` reads thread-local Win32 error state.
        let last_err = unsafe { GetLastError() };
        if last_err == ERROR_PIPE_BUSY {
            // SAFETY: `pipe_w` is a NUL-terminated UTF-16 pipe name.
            let waited = unsafe { WaitNamedPipeW(pipe_w.as_ptr(), 1000) };
            if waited != 0 {
                handle = open_pipe_for_write(&pipe_w, flags);
            }
        }
    }
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return false;
    }

    let _guard = HandleGuard(handle);
    let mut offset: usize = 0;
    while offset < frame.len() {
        let Some(remaining) = frame.get(offset..) else {
            break;
        };
        let to_write = u32::try_from(remaining.len()).unwrap_or(u32::MAX);
        let mut written: u32 = 0;
        // SAFETY: `handle` is an open Named Pipe handle and `remaining` holds `to_write` readable bytes.
        let ok = unsafe {
            WriteFile(
                handle,
                remaining.as_ptr(),
                to_write,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 || written == 0 {
            return false;
        }
        offset = offset.saturating_add(written as usize);
    }

    // SAFETY: `handle` is a live Named Pipe handle; flushing ensures frame delivery before close.
    let _ = unsafe { FlushFileBuffers(handle) };
    true
}

fn open_pipe_for_write(pipe_w: &[u16], flags: u32) -> HANDLE {
    // SAFETY: `pipe_w` is a NUL-terminated UTF-16 path.
    unsafe {
        CreateFileW(
            pipe_w.as_ptr(),
            GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            flags,
            ptr::null_mut(),
        )
    }
}

fn launch_process_no_shell(exe_path: &str, command_line: &str) -> HRESULT {
    let exe_w = to_utf16_nul(exe_path);
    let mut cmd_w = to_utf16_nul(command_line);
    let startup = STARTUPINFOW {
        cb: u32::try_from(size_of::<STARTUPINFOW>()).unwrap_or(0),
        ..STARTUPINFOW::default()
    };
    let mut proc_info = PROCESS_INFORMATION::default();

    // SAFETY: `exe_w` and mutable `cmd_w` are NUL-terminated UTF-16 buffers;
    // `startup` and `proc_info` are valid stack structs. `CreateProcessW` is
    // invoked directly on `totaldrop-winui.exe` — never via `cmd.exe`.
    let ok = unsafe {
        CreateProcessW(
            exe_w.as_ptr(),
            cmd_w.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            0,
            ptr::null(),
            ptr::null(),
            &startup,
            &mut proc_info,
        )
    };
    if ok == 0 {
        // SAFETY: `GetLastError` reads thread-local Win32 error state.
        let win_err = unsafe { GetLastError() };
        return if win_err == 0 {
            E_FAIL
        } else {
            hresult_from_win32(win_err)
        };
    }

    let _proc_guard = HandleGuard(proc_info.hProcess);
    let _thread_guard = HandleGuard(proc_info.hThread);
    S_OK
}

// ---------------------------------------------------------------------------
// Standard Win32 In-Proc / Surrogate COM DLL Exports

/// Standard Win32 DLL entry point storing the module `HMODULE` for
/// `IExplorerCommand::GetIcon`.
///
/// # Safety
///
/// Invoked exclusively by the Windows loader according to the `DllMain` ABI.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    hinst_dll: HMODULE,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    catch_unwind(AssertUnwindSafe(|| {
        if fdw_reason == DLL_PROCESS_ATTACH {
            // `DisableThreadLibraryCalls` is intentionally omitted because this
            // DLL links the static MSVC CRT (`+crt-static` / `libcmt`), which
            // requires `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` notifications
            // to allocate and reclaim per-thread CRT TLS state cleanly.
            MODULE_HANDLE.store(hinst_dll, Ordering::Release);
        }
        1
    }))
    .unwrap_or(0)
}

/// Standard COM class factory export returning `IClassFactory` for
/// [`CLSID_TOTALDROP_EXPLORER_COMMAND`].
///
/// # Safety
///
/// `rclsid`, `riid`, and `ppv` must either be null (validated and rejected with
/// `E_POINTER` / `E_INVALIDARG`) or point to valid COM arguments for the
/// duration of this call.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    guard_hresult(|| {
        if ppv.is_null() {
            return E_POINTER;
        }
        // SAFETY: Caller passed a valid writable `ppv` out-pointer.
        unsafe { *ppv = ptr::null_mut() };
        if rclsid.is_null() || riid.is_null() {
            return E_INVALIDARG;
        }
        // SAFETY: `rclsid` is non-null and points to a valid `GUID`.
        let clsid = unsafe { &*rclsid };
        if !guid_eq(clsid, &CLSID_TOTALDROP_EXPLORER_COMMAND) {
            return CLASS_E_CLASSNOTAVAILABLE;
        }

        let factory = TotalDropClassFactory::new_raw();
        // SAFETY: `factory` is freshly allocated with refcount 1; `riid` and
        // `ppv` were validated non-null above.
        let hr = unsafe { factory_query_interface(factory.cast(), riid, ppv) };
        // SAFETY: Releases initial creation reference.
        let _ = unsafe { factory_release(factory.cast()) };
        hr
    })
}

/// Standard COM unload query returning `S_OK` when zero live COM objects or
/// server locks remain, and `S_FALSE` otherwise.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    catch_unwind(AssertUnwindSafe(|| {
        if MODULE_REF_COUNT.load(Ordering::Acquire) == 0 {
            S_OK
        } else {
            S_FALSE
        }
    }))
    .unwrap_or(S_FALSE)
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;
    use std::path::PathBuf;

    use windows_sys::Win32::Globalization::SetThreadPreferredUILanguages;
    use windows_sys::Win32::UI::Shell::ExtractIconExW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, HICON};

    use super::*;

    type TestResult = Result<(), Box<dyn StdError>>;

    #[repr(C)]
    struct MockShellItemArray {
        // First #[repr(C)] field: COM interface vtable pointer read through raw ABI pointers.
        _vtbl: *const IShellItemArrayVtbl,
        count: u32,
    }

    static MOCK_ARRAY_VTBL: IShellItemArrayVtbl = IShellItemArrayVtbl {
        base: IUnknown_Vtbl {
            QueryInterface: mock_qi,
            AddRef: mock_addref,
            Release: mock_release,
        },
        bind_to_handler: mock_bind_to_handler,
        get_property_store: mock_get_property_store,
        get_property_description_list: mock_get_property_description_list,
        get_attributes: mock_get_attributes,
        get_count: mock_get_count,
        get_item_at: mock_get_item_at,
        enum_items: mock_enum_items,
    };

    unsafe extern "system" fn mock_qi(
        _this: *mut c_void,
        _riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> HRESULT {
        if !ppv.is_null() {
            // SAFETY: Test mock out-pointer.
            unsafe { *ppv = ptr::null_mut() };
        }
        E_NOINTERFACE
    }

    unsafe extern "system" fn mock_addref(_this: *mut c_void) -> u32 {
        1
    }

    unsafe extern "system" fn mock_release(_this: *mut c_void) -> u32 {
        1
    }

    unsafe extern "system" fn mock_bind_to_handler(
        _this: *mut c_void,
        _pbc: *mut c_void,
        _bhid: *const GUID,
        _riid: *const GUID,
        _ppv: *mut *mut c_void,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_get_property_store(
        _this: *mut c_void,
        _flags: i32,
        _riid: *const GUID,
        _ppv: *mut *mut c_void,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_get_property_description_list(
        _this: *mut c_void,
        _key: *const c_void,
        _riid: *const GUID,
        _ppv: *mut *mut c_void,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_get_attributes(
        _this: *mut c_void,
        _flags: i32,
        _mask: u32,
        _attribs: *mut u32,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_get_count(this: *mut c_void, pdw: *mut u32) -> HRESULT {
        if this.is_null() || pdw.is_null() {
            return E_POINTER;
        }
        // SAFETY: `this` is a valid `MockShellItemArray` created by test code.
        let mock = unsafe { &*this.cast::<MockShellItemArray>() };
        // SAFETY: `pdw` is a valid writable out-pointer.
        unsafe { *pdw = mock.count };
        S_OK
    }

    unsafe extern "system" fn mock_get_item_at(
        _this: *mut c_void,
        _idx: u32,
        ppsi: *mut *mut IShellItem,
    ) -> HRESULT {
        if !ppsi.is_null() {
            // SAFETY: Test mock out-pointer.
            unsafe { *ppsi = ptr::null_mut() };
        }
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_enum_items(
        _this: *mut c_void,
        _ppenum: *mut *mut c_void,
    ) -> HRESULT {
        E_NOTIMPL
    }

    struct ThreadMuiRestore;
    impl Drop for ThreadMuiRestore {
        fn drop(&mut self) {
            // SAFETY: Clears thread preferred UI languages back to default.
            let _ = unsafe { SetThreadPreferredUILanguages(0, ptr::null(), ptr::null_mut()) };
        }
    }

    #[test]
    fn com_factory_double_instantiation_error_contracts_and_10001_cap() -> TestResult {
        // Error contract checks on DllGetClassObject.
        // SAFETY: Explicit null-pointer contract checks.
        let hr_null_ppv = unsafe {
            DllGetClassObject(
                &CLSID_TOTALDROP_EXPLORER_COMMAND,
                &IID_ICLASS_FACTORY,
                ptr::null_mut(),
            )
        };
        assert_eq!(hr_null_ppv, E_POINTER);

        let mut out: *mut c_void = ptr::null_mut();
        // SAFETY: Explicit null-CLSID contract check.
        let hr_null_clsid =
            unsafe { DllGetClassObject(ptr::null(), &IID_ICLASS_FACTORY, &mut out) };
        assert_eq!(hr_null_clsid, E_INVALIDARG);

        let bogus_clsid = GUID::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
        // SAFETY: Unknown CLSID must return CLASS_E_CLASSNOTAVAILABLE.
        let hr_bogus = unsafe { DllGetClassObject(&bogus_clsid, &IID_ICLASS_FACTORY, &mut out) };
        assert_eq!(hr_bogus, CLASS_E_CLASSNOTAVAILABLE);

        // Obtain IClassFactory.
        // SAFETY: Valid COM arguments.
        let hr_factory = unsafe {
            DllGetClassObject(
                &CLSID_TOTALDROP_EXPLORER_COMMAND,
                &IID_ICLASS_FACTORY,
                &mut out,
            )
        };
        assert_eq!(hr_factory, S_OK);
        assert!(!out.is_null());
        assert_eq!(DllCanUnloadNow(), S_FALSE);

        // SAFETY: `out` is a live `TotalDropClassFactory` returned by `DllGetClassObject`.
        let factory_vtbl = unsafe { &*(*out.cast::<*const IClassFactoryVtbl>()) };

        // Aggregation rejected with CLASS_E_NOAGGREGATION.
        let mut agg_out: *mut c_void = ptr::null_mut();
        // SAFETY: Non-null `punk_outer` tests CLASS_E_NOAGGREGATION.
        let hr_agg = unsafe {
            (factory_vtbl.create_instance)(out, out, &IID_IEXPLORER_COMMAND, &mut agg_out)
        };
        assert_eq!(hr_agg, CLASS_E_NOAGGREGATION);

        // Null ppv rejected with E_POINTER; null riid rejected with E_INVALIDARG.
        // SAFETY: Explicit null-pointer contract checks.
        let hr_ci_null_ppv = unsafe {
            (factory_vtbl.create_instance)(
                out,
                ptr::null_mut(),
                &IID_IEXPLORER_COMMAND,
                ptr::null_mut(),
            )
        };
        assert_eq!(hr_ci_null_ppv, E_POINTER);

        // SAFETY: Explicit null-riid contract check.
        let hr_ci_null_riid = unsafe {
            (factory_vtbl.create_instance)(out, ptr::null_mut(), ptr::null(), &mut agg_out)
        };
        assert_eq!(hr_ci_null_riid, E_INVALIDARG);

        // Windows 11 double instantiation: create two independent IExplorerCommand instances.
        let mut cmd1: *mut c_void = ptr::null_mut();
        let mut cmd2: *mut c_void = ptr::null_mut();
        // SAFETY: Valid COM instantiation calls.
        let hr_cmd1 = unsafe {
            (factory_vtbl.create_instance)(out, ptr::null_mut(), &IID_IEXPLORER_COMMAND, &mut cmd1)
        };
        assert_eq!(hr_cmd1, S_OK);

        // SAFETY: Second independent COM instance.
        let hr_cmd2 = unsafe {
            (factory_vtbl.create_instance)(out, ptr::null_mut(), &IID_IEXPLORER_COMMAND, &mut cmd2)
        };
        assert_eq!(hr_cmd2, S_OK);
        assert_ne!(cmd1, cmd2);

        // SAFETY: `cmd1` is a live `TotalDropExplorerCommand`.
        let cmd_vtbl = unsafe { &*(*cmd1.cast::<*const IExplorerCommandVtbl>()) };

        // GetCanonicalName matches CLSID.
        let mut canonical = GUID::default();
        // SAFETY: `canonical` is a valid writable `GUID`.
        let hr_canonical = unsafe { (cmd_vtbl.get_canonical_name)(cmd1, &mut canonical) };
        assert_eq!(hr_canonical, S_OK);
        assert!(guid_eq(&canonical, &CLSID_TOTALDROP_EXPLORER_COMMAND));

        // GetFlags == ECF_DEFAULT, GetToolTip == E_NOTIMPL, EnumSubCommands == E_NOTIMPL.
        let mut flags: i32 = -1;
        // SAFETY: Valid out-pointer.
        let hr_flags = unsafe { (cmd_vtbl.get_flags)(cmd1, &mut flags) };
        assert_eq!(hr_flags, S_OK);
        assert_eq!(flags, ECF_DEFAULT);

        let mut tip: PWSTR = ptr::null_mut();
        // SAFETY: Valid out-pointer.
        let hr_tip = unsafe { (cmd_vtbl.get_tool_tip)(cmd1, ptr::null_mut(), &mut tip) };
        assert_eq!(hr_tip, E_NOTIMPL);

        let mut sub: *mut c_void = ptr::null_mut();
        // SAFETY: Valid out-pointer.
        let hr_sub = unsafe { (cmd_vtbl.enum_sub_commands)(cmd1, &mut sub) };
        assert_eq!(hr_sub, E_NOTIMPL);

        // GetIcon returns "<path>,-101".
        let mut icon_wstr: PWSTR = ptr::null_mut();
        // SAFETY: Valid out-pointer.
        let hr_icon = unsafe { (cmd_vtbl.get_icon)(cmd1, ptr::null_mut(), &mut icon_wstr) };
        assert_eq!(hr_icon, S_OK);
        let icon_spec =
            read_co_task_mem_wstr_and_free(icon_wstr).ok_or("GetIcon returned null string")?;
        assert!(
            icon_spec.ends_with(",-101"),
            "unexpected icon spec: {icon_spec}"
        );

        // GetTitle honors SetThreadPreferredUILanguages.
        {
            let _restore = ThreadMuiRestore;
            let mut tr_multi: Vec<u16> = "tr-TR".encode_utf16().collect();
            tr_multi.push(0);
            tr_multi.push(0);
            let mut set_count: u32 = 0;
            // SAFETY: `tr_multi` is double-NUL-terminated UTF-16.
            let _ = unsafe {
                SetThreadPreferredUILanguages(MUI_LANGUAGE_NAME, tr_multi.as_ptr(), &mut set_count)
            };
            let mut title_wstr: PWSTR = ptr::null_mut();
            // SAFETY: Valid out-pointer.
            let hr_title = unsafe { (cmd_vtbl.get_title)(cmd1, ptr::null_mut(), &mut title_wstr) };
            assert_eq!(hr_title, S_OK);
            let title = read_co_task_mem_wstr_and_free(title_wstr)
                .ok_or("GetTitle returned null string")?;
            assert_eq!(title, resolve_verb_title(["tr-TR"]));
        }

        // GetState: null/0 -> ECS_HIDDEN, 1 -> ECS_ENABLED.
        let mut state: i32 = -1;
        // SAFETY: Null selection array must return ECS_HIDDEN.
        let hr_state_null = unsafe { (cmd_vtbl.get_state)(cmd1, ptr::null_mut(), 0, &mut state) };
        assert_eq!(hr_state_null, S_OK);
        assert_eq!(state, ECS_HIDDEN);

        let mut mock_one = MockShellItemArray {
            _vtbl: &MOCK_ARRAY_VTBL,
            count: 1,
        };
        // SAFETY: `mock_one` is a valid mock `IShellItemArray`.
        let hr_state_one = unsafe {
            (cmd_vtbl.get_state)(cmd1, ptr::from_mut(&mut mock_one).cast(), 0, &mut state)
        };
        assert_eq!(hr_state_one, S_OK);
        assert_eq!(state, ECS_ENABLED);

        // Invoke: null -> E_INVALIDARG, 10,001 items -> 0x8007006F.
        // SAFETY: Null selection array contract check.
        let hr_invoke_null = unsafe { (cmd_vtbl.invoke)(cmd1, ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(hr_invoke_null, E_INVALIDARG);

        let mut mock_overflow = MockShellItemArray {
            _vtbl: &MOCK_ARRAY_VTBL,
            count: 10_001,
        };
        // SAFETY: `mock_overflow` tests immediate 10,001 cap rejection.
        let hr_overflow = unsafe {
            (cmd_vtbl.invoke)(
                cmd1,
                ptr::from_mut(&mut mock_overflow).cast(),
                ptr::null_mut(),
            )
        };
        assert_eq!(hr_overflow, HRESULT_ERROR_BUFFER_OVERFLOW);

        // Release both commands and factory; DllCanUnloadNow returns S_OK.
        // SAFETY: Releases each live COM object once.
        unsafe {
            let _ = (cmd_vtbl.base.Release)(cmd1);
            let _ = (cmd_vtbl.base.Release)(cmd2);
            let _ = (factory_vtbl.base.Release)(out);
        }
        assert_eq!(DllCanUnloadNow(), S_OK);
        Ok(())
    }

    #[test]
    fn extract_icon_ex_loads_embedded_kose_ico() -> TestResult {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let ico_path = manifest_dir
            .join("..")
            .join("..")
            .join("ui-winui3-fluent2")
            .join("Assets")
            .join("TotalDrop.ico");
        let ico_str = ico_path.to_str().ok_or("non-UTF-8 TotalDrop.ico path")?;
        let ico_w = to_utf16_nul(ico_str);
        let mut large: HICON = ptr::null_mut();
        let mut small: HICON = ptr::null_mut();
        // SAFETY: `ico_w` is NUL-terminated UTF-16; `large` and `small` are valid out-pointers.
        let extracted = unsafe { ExtractIconExW(ico_w.as_ptr(), 0, &mut large, &mut small, 1) };
        assert!(extracted >= 1, "ExtractIconExW failed for TotalDrop.ico");
        // SAFETY: Destroy any returned icon handles.
        unsafe {
            if !large.is_null() {
                let _ = DestroyIcon(large);
            }
            if !small.is_null() {
                let _ = DestroyIcon(small);
            }
        }
        Ok(())
    }
}
