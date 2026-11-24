// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opaque-box COM E2E test harness for `totaldrop_explorer_ext.dll` (`F16`,
//! `T3-09`, `T4-07`).
//!
//! - On Windows (`windows-ci` / `Invoke-WindowsE2E.ps1`), exercises the real
//!   COM vtables (`DllGetClassObject`, `DllCanUnloadNow`, `IClassFactory`,
//!   `IExplorerCommand`), Win32 `ExtractIconExW` for `RT_GROUP_ICON 101`,
//!   MUI thread language switching (`SetThreadPreferredUILanguages`), and a
//!   live same-user Named Pipe server on
//!   `\\.\pipe\LOCAL\app.totaldrop.TotalDrop.v1.<SessionId>`.
//! - When `TOTALDROP_EXPLORER_EXT_DLL` is set on Windows, tests load the
//!   compiled `totaldrop_explorer_ext.dll` dynamically via `LoadLibraryW` +
//!   `GetProcAddress` (pure opaque-box DLL testing).
//! - On non-Windows hosts (Linux devbox), runs cross-platform sanity checks
//!   over the pure-Rust selection, icon-spec, and 5-locale verb-title APIs so
//!   `cargo test --workspace --locked` compiles and verifies cleanly everywhere.

use std::error::Error as StdError;

use totaldrop_explorer_ext::{
    CLSID_TOTALDROP_EXPLORER_COMMAND_STR, HRESULT_ERROR_BUFFER_OVERFLOW,
    MAX_EXPLORER_SELECTION_ITEMS, format_icon_resource_spec, prepare_explorer_envelope,
    resolve_verb_title,
};

type TestResult = Result<(), Box<dyn StdError>>;

#[test]
fn explorer_ext_cross_platform_clsid_icon_and_5_locale_golden_parity() -> TestResult {
    assert_eq!(
        CLSID_TOTALDROP_EXPLORER_COMMAND_STR,
        "8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0"
    );
    assert_eq!(HRESULT_ERROR_BUFFER_OVERFLOW, 0x8007_006F_u32 as i32);
    assert_eq!(
        format_icon_resource_spec(r"C:\App\totaldrop_explorer_ext.dll"),
        r"C:\App\totaldrop_explorer_ext.dll,-101"
    );

    let golden = [
        ("en", "Send with TotalDrop"),
        ("tr", "TotalDrop ile gönder"),
        ("ar", "إرسال باستخدام TotalDrop"),
        ("ja", "TotalDrop で送信"),
        ("zh-Hant", "用 TotalDrop 傳送"),
    ];
    for (tag, expected) in golden {
        let actual = resolve_verb_title(&[tag.to_owned()]);
        assert_eq!(actual, expected, "verb title mismatch for locale {tag}");
    }

    let ok_10k: Vec<String> = (0..MAX_EXPLORER_SELECTION_ITEMS)
        .map(|i| format!(r"C:\t\f{i:04}.txt"))
        .collect();
    assert!(prepare_explorer_envelope(&ok_10k, Some(1)).is_ok());

    let bad_10001: Vec<String> = (0..MAX_EXPLORER_SELECTION_ITEMS.saturating_add(1))
        .map(|i| format!(r"C:\t\f{i:05}.txt"))
        .collect();
    assert!(prepare_explorer_envelope(&bad_10001, Some(1)).is_err());
    Ok(())
}

#[cfg(windows)]
mod win_com_e2e {
    use std::error::Error as StdError;
    use std::ffi::c_void;
    use std::path::PathBuf;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::sync::{LazyLock, Mutex};
    use std::thread;
    use std::time::Duration;

    use totaldrop_explorer_ext::com::{
        CLSID_TOTALDROP_EXPLORER_COMMAND, DllCanUnloadNow as StaticDllCanUnloadNow,
        DllGetClassObject as StaticDllGetClassObject, IClassFactoryVtbl, IExplorerCommandVtbl,
        IID_ICLASS_FACTORY, IID_IEXPLORER_COMMAND, IShellItem, IShellItemArray,
        IShellItemArrayVtbl, IShellItemVtbl, guid_eq,
    };
    use totaldrop_explorer_ext::{HRESULT_ERROR_BUFFER_OVERFLOW, MAX_EXPLORER_SELECTION_ITEMS};
    use totaldrop_windows_bridge::activation::{ActivationPayload, session_named_pipe_path};
    use totaldrop_windows_bridge::ipc_router::IpcFrameDecoder;
    use windows_sys::Win32::Foundation::{
        CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, CloseHandle, E_FAIL, E_INVALIDARG,
        E_NOINTERFACE, E_NOTIMPL, E_POINTER, ERROR_PIPE_CONNECTED, FreeLibrary, GENERIC_WRITE,
        GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE, S_FALSE, S_OK,
    };
    use windows_sys::Win32::Globalization::{MUI_LANGUAGE_NAME, SetThreadPreferredUILanguages};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, OPEN_EXISTING, PIPE_ACCESS_INBOUND, ReadFile,
    };
    use windows_sys::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::UI::Shell::{
        ECF_DEFAULT, ECS_ENABLED, ECS_HIDDEN, ExtractIconExW, SIGDN_FILESYSPATH,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, HICON};
    use windows_sys::core::{GUID, HRESULT, IID_IUnknown, IUnknown_Vtbl, PWSTR};

    type TestResult = Result<(), Box<dyn StdError>>;

    type RawFarProc = unsafe extern "system" fn() -> isize;
    type FnDllGetClassObject =
        unsafe extern "system" fn(*const GUID, *const GUID, *mut *mut c_void) -> HRESULT;
    type FnDllCanUnloadNow = unsafe extern "system" fn() -> HRESULT;

    static COM_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

    struct LoadedComServer {
        module: Option<HMODULE>,
        dll_get_class_object: FnDllGetClassObject,
        dll_can_unload_now: FnDllCanUnloadNow,
    }

    impl LoadedComServer {
        fn open() -> Result<Self, Box<dyn StdError>> {
            if let Ok(dll_raw) = std::env::var("TOTALDROP_EXPLORER_EXT_DLL")
                && !dll_raw.trim().is_empty()
            {
                let wide = to_utf16_nul(dll_raw.trim());
                // SAFETY: `wide` is a NUL-terminated UTF-16 DLL path.
                let module = unsafe { LoadLibraryW(wide.as_ptr()) };
                if module.is_null() {
                    return Err(format!(
                        "LoadLibraryW failed for TOTALDROP_EXPLORER_EXT_DLL={dll_raw:?}"
                    )
                    .into());
                }
                // SAFETY: `module` is a live loaded DLL handle and symbol names are NUL-terminated ASCII.
                let gco = unsafe { GetProcAddress(module, c"DllGetClassObject".as_ptr().cast()) };
                // SAFETY: `module` is a live loaded DLL handle and symbol name is NUL-terminated ASCII.
                let cun = unsafe { GetProcAddress(module, c"DllCanUnloadNow".as_ptr().cast()) };
                let (Some(gco_fn), Some(cun_fn)) = (gco, cun) else {
                    // SAFETY: Freeing `module` on symbol lookup failure.
                    let _ = unsafe { FreeLibrary(module) };
                    return Err(
                        "totaldrop_explorer_ext.dll missing DllGetClassObject/DllCanUnloadNow"
                            .into(),
                    );
                };
                // SAFETY: Standard Win32 COM DLL exported signatures (`DllGetClassObject` & `DllCanUnloadNow`).
                let dll_get_class_object =
                    unsafe { std::mem::transmute::<RawFarProc, FnDllGetClassObject>(gco_fn) };
                // SAFETY: Standard Win32 COM DLL exported signature (`DllCanUnloadNow`).
                let dll_can_unload_now =
                    unsafe { std::mem::transmute::<RawFarProc, FnDllCanUnloadNow>(cun_fn) };
                return Ok(Self {
                    module: Some(module),
                    dll_get_class_object,
                    dll_can_unload_now,
                });
            }
            Ok(Self {
                module: None,
                dll_get_class_object: StaticDllGetClassObject,
                dll_can_unload_now: StaticDllCanUnloadNow,
            })
        }

        fn create_factory(&self) -> Result<ComObjectGuard<IClassFactoryVtbl>, Box<dyn StdError>> {
            let mut raw: *mut c_void = ptr::null_mut();
            // SAFETY: Valid COM arguments for `DllGetClassObject`.
            let hr = unsafe {
                (self.dll_get_class_object)(
                    &CLSID_TOTALDROP_EXPLORER_COMMAND,
                    &IID_ICLASS_FACTORY,
                    &mut raw,
                )
            };
            if hr != S_OK || raw.is_null() {
                return Err(format!("DllGetClassObject failed: 0x{:08x}", hr as u32).into());
            }
            Ok(ComObjectGuard {
                ptr: raw,
                _marker: std::marker::PhantomData,
            })
        }

        fn can_unload_now(&self) -> HRESULT {
            // SAFETY: Calling `DllCanUnloadNow` on the live COM server.
            unsafe { (self.dll_can_unload_now)() }
        }
    }

    impl Drop for LoadedComServer {
        fn drop(&mut self) {
            if let Some(m) = self.module
                && !m.is_null()
            {
                // SAFETY: `m` was returned by `LoadLibraryW`.
                let _ = unsafe { FreeLibrary(m) };
            }
        }
    }

    struct ComObjectGuard<V> {
        ptr: *mut c_void,
        _marker: std::marker::PhantomData<*const V>,
    }

    impl<V> ComObjectGuard<V> {
        fn raw(&self) -> *mut c_void {
            self.ptr
        }

        fn vtbl(&self) -> &V {
            // SAFETY: COM object starts with a non-null vtable pointer of type `*const V`.
            unsafe { &*(*self.ptr.cast::<*const V>()) }
        }
    }

    impl<V> Drop for ComObjectGuard<V> {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                // SAFETY: Every COM vtable begins with `IUnknown_Vtbl` (`Release` is slot 2).
                unsafe {
                    let iunk = &*(*self.ptr.cast::<*const IUnknown_Vtbl>());
                    let _ = (iunk.Release)(self.ptr);
                }
            }
        }
    }

    impl ComObjectGuard<IClassFactoryVtbl> {
        fn create_explorer_command(
            &self,
        ) -> Result<ComObjectGuard<IExplorerCommandVtbl>, Box<dyn StdError>> {
            let mut raw: *mut c_void = ptr::null_mut();
            // SAFETY: Calling `IClassFactory::CreateInstance` on a live factory.
            let hr = unsafe {
                (self.vtbl().create_instance)(
                    self.ptr,
                    ptr::null_mut(),
                    &IID_IEXPLORER_COMMAND,
                    &mut raw,
                )
            };
            if hr != S_OK || raw.is_null() {
                return Err(format!("CreateInstance failed: 0x{:08x}", hr as u32).into());
            }
            Ok(ComObjectGuard {
                ptr: raw,
                _marker: std::marker::PhantomData,
            })
        }
    }

    fn to_utf16_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn take_co_task_mem_wstr(pwstr: PWSTR) -> Result<String, Box<dyn StdError>> {
        if pwstr.is_null() {
            return Err("COM method returned NULL PWSTR".into());
        }
        let mut len = 0usize;
        // SAFETY: `pwstr` is a NUL-terminated UTF-16 string allocated via `CoTaskMemAlloc`.
        unsafe {
            while *pwstr.add(len) != 0 {
                len = len.saturating_add(1);
            }
            let slice = std::slice::from_raw_parts(pwstr, len);
            let out = String::from_utf16_lossy(slice);
            CoTaskMemFree(pwstr.cast());
            Ok(out)
        }
    }

    struct ThreadMuiRestore;
    impl Drop for ThreadMuiRestore {
        fn drop(&mut self) {
            // SAFETY: Resets thread UI languages back to process/user default.
            let _ = unsafe { SetThreadPreferredUILanguages(0, ptr::null(), ptr::null_mut()) };
        }
    }

    // --- Real Mock IShellItem & IShellItemArray returning UTF-16 NTFS paths ---

    #[repr(C)]
    struct MockShellItem {
        // First #[repr(C)] field: COM interface vtable pointer read through raw ABI pointers.
        _vtbl: *const IShellItemVtbl,
        ref_count: AtomicU32,
        path_w: Option<Vec<u16>>,
    }

    static MOCK_ITEM_VTBL: IShellItemVtbl = IShellItemVtbl {
        base: IUnknown_Vtbl {
            QueryInterface: mock_qi,
            AddRef: mock_item_addref,
            Release: mock_item_release,
        },
        bind_to_handler: mock_item_bind,
        get_parent: mock_item_parent,
        get_display_name: mock_item_display_name,
        get_attributes: mock_item_attrs,
        compare: mock_item_compare,
    };

    unsafe extern "system" fn mock_qi(
        _this: *mut c_void,
        _riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> HRESULT {
        if !ppv.is_null() {
            // SAFETY: Valid COM out-pointer.
            unsafe { *ppv = ptr::null_mut() };
        }
        E_NOINTERFACE
    }

    unsafe extern "system" fn mock_item_addref(this: *mut c_void) -> u32 {
        // SAFETY: `this` is a heap-allocated `MockShellItem`.
        let item = unsafe { &*this.cast::<MockShellItem>() };
        item.ref_count
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }

    unsafe extern "system" fn mock_item_release(this: *mut c_void) -> u32 {
        // SAFETY: `this` is a heap-allocated `MockShellItem`.
        let item = unsafe { &*this.cast::<MockShellItem>() };
        let prev = item.ref_count.fetch_sub(1, Ordering::AcqRel);
        let rem = prev.saturating_sub(1);
        if rem == 0 {
            // SAFETY: Last COM reference dropped; free `Box<MockShellItem>`.
            let _ = unsafe { Box::from_raw(this.cast::<MockShellItem>()) };
        }
        rem
    }

    unsafe extern "system" fn mock_item_bind(
        _this: *mut c_void,
        _pbc: *mut c_void,
        _bhid: *const GUID,
        _riid: *const GUID,
        _ppv: *mut *mut c_void,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_item_parent(
        _this: *mut c_void,
        _ppsi: *mut *mut IShellItem,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_item_display_name(
        this: *mut c_void,
        sigdn: i32,
        ppsz_name: *mut PWSTR,
    ) -> HRESULT {
        if ppsz_name.is_null() {
            return E_POINTER;
        }
        if sigdn != SIGDN_FILESYSPATH || this.is_null() {
            return E_INVALIDARG;
        }
        // SAFETY: `this` is a valid `MockShellItem`.
        let item = unsafe { &*this.cast::<MockShellItem>() };
        let Some(path_w) = &item.path_w else {
            // SAFETY: `ppsz_name` was validated non-null above.
            unsafe { *ppsz_name = ptr::null_mut() };
            return E_FAIL;
        };
        let byte_len = path_w.len().saturating_mul(2);
        // SAFETY: `CoTaskMemAlloc` allocates a COM-owned UTF-16 buffer freed by caller.
        let mem = unsafe { CoTaskMemAlloc(byte_len) }.cast::<u16>();
        if mem.is_null() {
            return E_POINTER;
        }
        // SAFETY: `mem` holds `path_w.len()` writable `u16` elements.
        unsafe {
            ptr::copy_nonoverlapping(path_w.as_ptr(), mem, path_w.len());
            *ppsz_name = mem;
        }
        S_OK
    }

    unsafe extern "system" fn mock_item_attrs(
        _this: *mut c_void,
        _mask: u32,
        _out: *mut u32,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_item_compare(
        _this: *mut c_void,
        _psi: *mut IShellItem,
        _hint: u32,
        _out: *mut i32,
    ) -> HRESULT {
        E_NOTIMPL
    }

    #[repr(C)]
    struct MockShellItemArray {
        // First #[repr(C)] field: COM interface vtable pointer read through raw ABI pointers.
        _vtbl: *const IShellItemArrayVtbl,
        items: Vec<Option<String>>,
        override_count: Option<u32>,
    }

    static MOCK_ARRAY_VTBL: IShellItemArrayVtbl = IShellItemArrayVtbl {
        base: IUnknown_Vtbl {
            QueryInterface: mock_qi,
            AddRef: mock_array_noop_ref,
            Release: mock_array_noop_ref,
        },
        bind_to_handler: mock_item_bind,
        get_property_store: mock_array_prop_store,
        get_property_description_list: mock_array_prop_desc,
        get_attributes: mock_array_attrs,
        get_count: mock_array_get_count,
        get_item_at: mock_array_get_item_at,
        enum_items: mock_array_enum_items,
    };

    unsafe extern "system" fn mock_array_noop_ref(_this: *mut c_void) -> u32 {
        1
    }

    unsafe extern "system" fn mock_array_prop_store(
        _this: *mut c_void,
        _flags: i32,
        _riid: *const GUID,
        _ppv: *mut *mut c_void,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_array_prop_desc(
        _this: *mut c_void,
        _key: *const c_void,
        _riid: *const GUID,
        _ppv: *mut *mut c_void,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_array_attrs(
        _this: *mut c_void,
        _flags: i32,
        _mask: u32,
        _out: *mut u32,
    ) -> HRESULT {
        E_NOTIMPL
    }

    unsafe extern "system" fn mock_array_get_count(this: *mut c_void, pdw: *mut u32) -> HRESULT {
        if this.is_null() || pdw.is_null() {
            return E_POINTER;
        }
        // SAFETY: `this` is a valid `MockShellItemArray`.
        let arr = unsafe { &*this.cast::<MockShellItemArray>() };
        let count = arr
            .override_count
            .unwrap_or_else(|| u32::try_from(arr.items.len()).unwrap_or(u32::MAX));
        // SAFETY: `pdw` is a writable out-pointer.
        unsafe { *pdw = count };
        S_OK
    }

    unsafe extern "system" fn mock_array_get_item_at(
        this: *mut c_void,
        idx: u32,
        ppsi: *mut *mut IShellItem,
    ) -> HRESULT {
        if this.is_null() || ppsi.is_null() {
            return E_POINTER;
        }
        // SAFETY: `this` is a valid `MockShellItemArray`.
        let arr = unsafe { &*this.cast::<MockShellItemArray>() };
        let path_w = match arr.items.get(idx as usize) {
            Some(Some(p)) => Some(to_utf16_nul(p)),
            Some(None) => None,
            None => Some(to_utf16_nul(&format!(r"C:\t\f{idx:04}.txt"))),
        };
        let boxed = Box::new(MockShellItem {
            _vtbl: &MOCK_ITEM_VTBL,
            ref_count: AtomicU32::new(1),
            path_w,
        });
        // SAFETY: Caller owns the returned COM reference and will call `Release`.
        unsafe { *ppsi = Box::into_raw(boxed).cast::<IShellItem>() };
        S_OK
    }

    unsafe extern "system" fn mock_array_enum_items(
        _this: *mut c_void,
        _ppenum: *mut *mut c_void,
    ) -> HRESULT {
        E_NOTIMPL
    }

    impl MockShellItemArray {
        fn new(paths: Vec<String>) -> Self {
            Self {
                _vtbl: &MOCK_ARRAY_VTBL,
                items: paths.into_iter().map(Some).collect(),
                override_count: None,
            }
        }

        fn with_mixed_items(items: Vec<Option<String>>) -> Self {
            Self {
                _vtbl: &MOCK_ARRAY_VTBL,
                items,
                override_count: None,
            }
        }

        fn with_virtual_count(count: u32) -> Self {
            Self {
                _vtbl: &MOCK_ARRAY_VTBL,
                items: Vec::new(),
                override_count: Some(count),
            }
        }

        fn as_ptr(&mut self) -> *mut IShellItemArray {
            (self as *mut Self).cast::<IShellItemArray>()
        }
    }

    fn current_session_id() -> u32 {
        // SAFETY: Win32 `GetCurrentProcessId` & `ProcessIdToSessionId`.
        let pid = unsafe { GetCurrentProcessId() };
        let mut sid: u32 = 0;
        // SAFETY: `sid` is a valid writable out-pointer.
        let ok = unsafe { ProcessIdToSessionId(pid, &mut sid) };
        if ok != 0 { sid } else { 0 }
    }

    fn expected_extended_path(raw: &str) -> String {
        if let Some(rest) = raw.strip_prefix(r"\\?\") {
            if let Some(unc_tail) = rest
                .strip_prefix(r"UNC\")
                .or_else(|| rest.strip_prefix(r"unc\"))
            {
                return format!(r"\\?\UNC\{unc_tail}");
            }
            let mut chars = rest.chars();
            if let (Some(drive), Some(':')) = (chars.next(), chars.next())
                && drive.is_ascii_alphabetic()
            {
                return format!(r"\\?\{}:{}", drive.to_ascii_uppercase(), chars.as_str());
            }
            return format!(r"\\?\{rest}");
        }
        if let Some(unc_rest) = raw.strip_prefix(r"\\") {
            return format!(r"\\?\UNC\{unc_rest}");
        }
        let mut chars = raw.chars();
        if let (Some(drive), Some(':')) = (chars.next(), chars.next())
            && drive.is_ascii_alphabetic()
        {
            return format!(r"\\?\{}:{}", drive.to_ascii_uppercase(), chars.as_str());
        }
        format!(r"\\?\{raw}")
    }

    struct SingleShotPipeServer {
        pipe_path_w: Vec<u16>,
        handle: Option<thread::JoinHandle<Result<Vec<u8>, String>>>,
    }

    impl SingleShotPipeServer {
        fn spawn() -> Result<Self, Box<dyn StdError>> {
            let pipe_path = session_named_pipe_path(current_session_id());
            let pipe_w = to_utf16_nul(&pipe_path);
            // SAFETY: Creating an inbound byte-mode Named Pipe rejecting remote clients.
            let handle: HANDLE = unsafe {
                CreateNamedPipeW(
                    pipe_w.as_ptr(),
                    PIPE_ACCESS_INBOUND,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    65_536,
                    65_536,
                    5_000,
                    ptr::null(),
                )
            };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return Err(format!("CreateNamedPipeW failed for {pipe_path}").into());
            }
            let raw_addr = handle as usize;
            let jh = thread::spawn(move || -> Result<Vec<u8>, String> {
                let h = raw_addr as HANDLE;
                // SAFETY: `ConnectNamedPipe` waits for the client on `h`.
                let conn = unsafe { ConnectNamedPipe(h, ptr::null_mut()) };
                if conn == 0 {
                    // SAFETY: `GetLastError` reads thread-local Win32 error code.
                    let err = unsafe { GetLastError() };
                    if err != ERROR_PIPE_CONNECTED {
                        // SAFETY: Closing owned handle on failure.
                        let _ = unsafe { CloseHandle(h) };
                        return Err(format!("ConnectNamedPipe failed with Win32 error {err}"));
                    }
                }
                let mut received = Vec::new();
                let mut buf = [0u8; 16_384];
                loop {
                    let mut nread: u32 = 0;
                    // SAFETY: Reading from connected Named Pipe into live stack buffer.
                    let ok = unsafe {
                        ReadFile(
                            h,
                            buf.as_mut_ptr(),
                            u32::try_from(buf.len()).unwrap_or(16_384),
                            &mut nread,
                            ptr::null_mut(),
                        )
                    };
                    if ok == 0 || nread == 0 {
                        break;
                    }
                    if let Some(chunk) = buf.get(..nread as usize) {
                        received.extend_from_slice(chunk);
                    }
                }
                // SAFETY: Disconnect & close owned pipe handle.
                unsafe {
                    let _ = DisconnectNamedPipe(h);
                    let _ = CloseHandle(h);
                }
                Ok(received)
            });
            thread::sleep(Duration::from_millis(30));
            Ok(Self {
                pipe_path_w: pipe_w,
                handle: Some(jh),
            })
        }

        fn finish(mut self) -> Result<Vec<u8>, Box<dyn StdError>> {
            let jh = self
                .handle
                .take()
                .ok_or("SingleShotPipeServer already joined")?;
            let bytes = jh.join().map_err(|_| "pipe thread panicked")??;
            Ok(bytes)
        }
    }

    impl Drop for SingleShotPipeServer {
        fn drop(&mut self) {
            if let Some(jh) = self.handle.take() {
                // SAFETY: Unblock a server thread still waiting in `ConnectNamedPipe` by opening
                // and immediately closing a client handle to the same pipe path.
                let wake = unsafe {
                    CreateFileW(
                        self.pipe_path_w.as_ptr(),
                        GENERIC_WRITE,
                        0,
                        ptr::null(),
                        OPEN_EXISTING,
                        0,
                        ptr::null_mut(),
                    )
                };
                if wake != INVALID_HANDLE_VALUE && !wake.is_null() {
                    // SAFETY: Closing the wakeup client handle opened above.
                    let _ = unsafe { CloseHandle(wake) };
                }
                let _ = jh.join();
            }
        }
    }

    fn verify_extracted_icon(icon_spec: &str) -> TestResult {
        assert!(
            icon_spec.ends_with(",-101"),
            "expected GetIcon spec ending in ',-101', got {icon_spec:?}"
        );
        let dll_part = icon_spec
            .strip_suffix(",-101")
            .ok_or("missing ,-101 suffix")?;
        if std::env::var("TOTALDROP_EXPLORER_EXT_DLL").is_ok_and(|v| !v.trim().is_empty()) {
            let dll_w = to_utf16_nul(dll_part);
            let mut large_icon: HICON = ptr::null_mut();
            let mut small_icon: HICON = ptr::null_mut();
            // SAFETY: `ExtractIconExW` with negative resource ID `-101` extracts RT_GROUP_ICON 101.
            let extracted = unsafe {
                ExtractIconExW(dll_w.as_ptr(), -101, &mut large_icon, &mut small_icon, 1)
            };
            let has_icon = extracted >= 1 && (!large_icon.is_null() || !small_icon.is_null());
            if !large_icon.is_null() {
                // SAFETY: Destroying icon returned by `ExtractIconExW`.
                let _ = unsafe { DestroyIcon(large_icon) };
            }
            if !small_icon.is_null() {
                // SAFETY: Destroying icon returned by `ExtractIconExW`.
                let _ = unsafe { DestroyIcon(small_icon) };
            }
            assert!(
                has_icon,
                "ExtractIconExW failed to load RT_GROUP_ICON 101 from {dll_part:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn t1_f16_02_com_inproc_explorer_command_happy_path() -> TestResult {
        let _guard = COM_TEST_LOCK.lock().map_err(|_| "COM_TEST_LOCK poisoned")?;
        let srv = LoadedComServer::open()?;
        let factory = srv.create_factory()?;
        let cmd = factory.create_explorer_command()?;

        let mut canonical = GUID::from_u128(0);
        // SAFETY: Valid COM call on live `IExplorerCommand`.
        let hr_cn = unsafe { (cmd.vtbl().get_canonical_name)(cmd.raw(), &mut canonical) };
        assert_eq!(hr_cn, S_OK);
        assert!(guid_eq(&canonical, &CLSID_TOTALDROP_EXPLORER_COMMAND));

        let _mui_restore = ThreadMuiRestore;
        let en_multi = to_utf16_nul("en-US\0");
        // SAFETY: Pin English UI language so `GetTitle` deterministically returns English.
        let _ = unsafe {
            SetThreadPreferredUILanguages(MUI_LANGUAGE_NAME, en_multi.as_ptr(), ptr::null_mut())
        };

        let mut title_ptr: PWSTR = ptr::null_mut();
        // SAFETY: Valid COM call on live `IExplorerCommand`.
        let hr_title =
            unsafe { (cmd.vtbl().get_title)(cmd.raw(), ptr::null_mut(), &mut title_ptr) };
        assert_eq!(hr_title, S_OK);
        assert_eq!(take_co_task_mem_wstr(title_ptr)?, "Send with TotalDrop");

        let mut icon_ptr: PWSTR = ptr::null_mut();
        // SAFETY: Valid COM call on live `IExplorerCommand`.
        let hr_icon = unsafe { (cmd.vtbl().get_icon)(cmd.raw(), ptr::null_mut(), &mut icon_ptr) };
        assert_eq!(hr_icon, S_OK);
        let icon_spec = take_co_task_mem_wstr(icon_ptr)?;
        verify_extracted_icon(&icon_spec)?;

        let mut arr1 = MockShellItemArray::new(vec![r"C:\tmp\one.txt".to_owned()]);
        let mut state: i32 = -1;
        // SAFETY: Valid COM call on live `IExplorerCommand` + `MockShellItemArray`.
        let hr_state = unsafe { (cmd.vtbl().get_state)(cmd.raw(), arr1.as_ptr(), 0, &mut state) };
        assert_eq!(hr_state, S_OK);
        assert_eq!(state, ECS_ENABLED);

        let mut flags: i32 = -1;
        // SAFETY: Valid COM call on live `IExplorerCommand`.
        let hr_flags = unsafe { (cmd.vtbl().get_flags)(cmd.raw(), &mut flags) };
        assert_eq!(hr_flags, S_OK);
        assert_eq!(flags, ECF_DEFAULT);
        Ok(())
    }

    #[test]
    fn t1_f16_04_com_invoke_streams_framed_envelope_over_current_user_pipe() -> TestResult {
        let _guard = COM_TEST_LOCK.lock().map_err(|_| "COM_TEST_LOCK poisoned")?;
        let srv = LoadedComServer::open()?;
        let factory = srv.create_factory()?;
        let cmd = factory.create_explorer_command()?;

        let tmp_dir = std::env::temp_dir().join(format!(
            "td-com-f16-04-{}-{}",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&tmp_dir)?;
        let f1 = tmp_dir.join("alpha.txt");
        let f2 = tmp_dir.join("beta.bin");
        std::fs::write(&f1, b"alpha")?;
        std::fs::write(&f2, b"beta")?;

        let pipe_srv = SingleShotPipeServer::spawn()?;
        let mut arr = MockShellItemArray::new(vec![
            f1.to_string_lossy().into_owned(),
            f2.to_string_lossy().into_owned(),
        ]);
        // SAFETY: Valid COM `Invoke` against our live Named Pipe listener.
        let hr = unsafe { (cmd.vtbl().invoke)(cmd.raw(), arr.as_ptr(), ptr::null_mut()) };
        assert_eq!(hr, S_OK);

        let raw_bytes = pipe_srv.finish()?;
        let mut dec = IpcFrameDecoder::new();
        let envelopes = dec.push_bytes(&raw_bytes)?;
        dec.finish_eof()?;
        assert_eq!(envelopes.len(), 1);
        let env = envelopes.first().ok_or("missing envelope")?;
        match &env.payload {
            ActivationPayload::ExplorerSend { paths } => {
                assert_eq!(paths.len(), 2);
                let exp1 = expected_extended_path(&f1.to_string_lossy());
                let exp2 = expected_extended_path(&f2.to_string_lossy());
                assert_eq!(
                    paths.first().map(|p| p.extended_path()),
                    Some(exp1.as_str())
                );
                assert_eq!(paths.get(1).map(|p| p.extended_path()), Some(exp2.as_str()));
            }
            other => return Err(format!("expected ExplorerSend payload, got {other:?}").into()),
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
        Ok(())
    }

    #[test]
    fn t1_f16_05_com_double_instantiation_and_unload_refcount() -> TestResult {
        let _guard = COM_TEST_LOCK.lock().map_err(|_| "COM_TEST_LOCK poisoned")?;
        let srv = LoadedComServer::open()?;
        assert_eq!(srv.can_unload_now(), S_OK);

        let factory = srv.create_factory()?;
        assert_eq!(srv.can_unload_now(), S_FALSE);

        let cmd1 = factory.create_explorer_command()?;
        let cmd2 = factory.create_explorer_command()?;
        assert_eq!(srv.can_unload_now(), S_FALSE);

        let mut g1 = GUID::from_u128(0);
        let mut g2 = GUID::from_u128(0);
        // SAFETY: Valid COM calls on both concurrent instances.
        let hr_g1 = unsafe { (cmd1.vtbl().get_canonical_name)(cmd1.raw(), &mut g1) };
        assert_eq!(hr_g1, S_OK);
        // SAFETY: Valid COM calls on both concurrent instances.
        let hr_g2 = unsafe { (cmd2.vtbl().get_canonical_name)(cmd2.raw(), &mut g2) };
        assert_eq!(hr_g2, S_OK);
        assert!(guid_eq(&g1, &g2));

        let mut t1: PWSTR = ptr::null_mut();
        let mut t2: PWSTR = ptr::null_mut();
        // SAFETY: Valid COM calls on both concurrent instances.
        let hr_t1 = unsafe { (cmd1.vtbl().get_title)(cmd1.raw(), ptr::null_mut(), &mut t1) };
        assert_eq!(hr_t1, S_OK);
        // SAFETY: Valid COM calls on both concurrent instances.
        let hr_t2 = unsafe { (cmd2.vtbl().get_title)(cmd2.raw(), ptr::null_mut(), &mut t2) };
        assert_eq!(hr_t2, S_OK);
        assert_eq!(take_co_task_mem_wstr(t1)?, take_co_task_mem_wstr(t2)?);

        drop(factory);
        assert_eq!(srv.can_unload_now(), S_FALSE);
        drop(cmd1);
        assert_eq!(srv.can_unload_now(), S_FALSE);
        drop(cmd2);
        assert_eq!(srv.can_unload_now(), S_OK);
        Ok(())
    }

    #[test]
    fn t2_f16_01_com_10000_vs_10001_selection_cap() -> TestResult {
        let _guard = COM_TEST_LOCK.lock().map_err(|_| "COM_TEST_LOCK poisoned")?;
        let srv = LoadedComServer::open()?;
        let factory = srv.create_factory()?;
        let cmd = factory.create_explorer_command()?;

        // 10_001 items immediately rejected with 0x8007006F (ERROR_BUFFER_OVERFLOW)
        let mut arr_over = MockShellItemArray::with_virtual_count(
            u32::try_from(MAX_EXPLORER_SELECTION_ITEMS.saturating_add(1)).unwrap_or(10_001),
        );
        // SAFETY: Valid COM `Invoke` testing hard 10,000-item ceiling.
        let hr_over = unsafe { (cmd.vtbl().invoke)(cmd.raw(), arr_over.as_ptr(), ptr::null_mut()) };
        assert_eq!(hr_over, HRESULT_ERROR_BUFFER_OVERFLOW);

        // 10_000 items accepted and delivered over live Named Pipe IPC
        let pipe_srv = SingleShotPipeServer::spawn()?;
        let mut arr_ok = MockShellItemArray::with_virtual_count(
            u32::try_from(MAX_EXPLORER_SELECTION_ITEMS).unwrap_or(10_000),
        );
        // SAFETY: Valid COM `Invoke` delivering exact 10,000 items.
        let hr_ok = unsafe { (cmd.vtbl().invoke)(cmd.raw(), arr_ok.as_ptr(), ptr::null_mut()) };
        assert_eq!(hr_ok, S_OK);

        let raw_bytes = pipe_srv.finish()?;
        let mut dec = IpcFrameDecoder::new();
        let envelopes = dec.push_bytes(&raw_bytes)?;
        dec.finish_eof()?;
        assert_eq!(envelopes.len(), 1);
        match &envelopes.first().ok_or("missing envelope")?.payload {
            ActivationPayload::ExplorerSend { paths } => {
                assert_eq!(paths.len(), MAX_EXPLORER_SELECTION_ITEMS);
            }
            other => return Err(format!("unexpected payload: {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn t2_f16_04_com_null_pointer_aggregation_and_zero_items_defenses() -> TestResult {
        let _guard = COM_TEST_LOCK.lock().map_err(|_| "COM_TEST_LOCK poisoned")?;
        let srv = LoadedComServer::open()?;
        let factory = srv.create_factory()?;

        // CreateInstance with non-null outer -> CLASS_E_NOAGGREGATION
        let mut out: *mut c_void = ptr::null_mut();
        // SAFETY: Testing aggregation defense.
        let hr_agg = unsafe {
            (factory.vtbl().create_instance)(
                factory.raw(),
                factory.raw(),
                &IID_IEXPLORER_COMMAND,
                &mut out,
            )
        };
        assert_eq!(hr_agg, CLASS_E_NOAGGREGATION);

        let cmd = factory.create_explorer_command()?;
        // SAFETY: Null out-pointer checks across all IExplorerCommand methods.
        let hr_null_title =
            unsafe { (cmd.vtbl().get_title)(cmd.raw(), ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(hr_null_title, E_POINTER);
        // SAFETY: Null out-pointer check.
        let hr_null_icon =
            unsafe { (cmd.vtbl().get_icon)(cmd.raw(), ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(hr_null_icon, E_POINTER);
        // SAFETY: Null out-pointer check.
        let hr_null_state =
            unsafe { (cmd.vtbl().get_state)(cmd.raw(), ptr::null_mut(), 0, ptr::null_mut()) };
        assert_eq!(hr_null_state, E_POINTER);
        // SAFETY: Null out-pointer check.
        let hr_null_cn = unsafe { (cmd.vtbl().get_canonical_name)(cmd.raw(), ptr::null_mut()) };
        assert_eq!(hr_null_cn, E_POINTER);
        // SAFETY: Null selection check on Invoke.
        let hr_null_invoke =
            unsafe { (cmd.vtbl().invoke)(cmd.raw(), ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(hr_null_invoke, E_INVALIDARG);

        // GetState(0 items) -> ECS_HIDDEN (0x2)
        let mut arr0 = MockShellItemArray::new(Vec::new());
        let mut st0: i32 = -1;
        // SAFETY: Valid COM call on empty array.
        let hr_st0 = unsafe { (cmd.vtbl().get_state)(cmd.raw(), arr0.as_ptr(), 0, &mut st0) };
        assert_eq!(hr_st0, S_OK);
        assert_eq!(st0, ECS_HIDDEN);

        // GetToolTip & EnumSubCommands -> E_NOTIMPL
        let mut tip: PWSTR = ptr::null_mut();
        // SAFETY: Valid COM call.
        let hr_tip = unsafe { (cmd.vtbl().get_tool_tip)(cmd.raw(), ptr::null_mut(), &mut tip) };
        assert_eq!(hr_tip, E_NOTIMPL);
        let mut enum_out: *mut c_void = ptr::null_mut();
        // SAFETY: Valid COM call.
        let hr_enum = unsafe { (cmd.vtbl().enum_sub_commands)(cmd.raw(), &mut enum_out) };
        assert_eq!(hr_enum, E_NOTIMPL);
        Ok(())
    }

    #[test]
    fn t2_f16_05_com_unknown_clsid_and_refcount_tracking() -> TestResult {
        let _guard = COM_TEST_LOCK.lock().map_err(|_| "COM_TEST_LOCK poisoned")?;
        let srv = LoadedComServer::open()?;
        let zero_clsid = GUID::from_u128(0);
        let mut out: *mut c_void = ptr::null_mut();
        // SAFETY: Requesting unknown zero CLSID.
        let hr = unsafe { (srv.dll_get_class_object)(&zero_clsid, &IID_ICLASS_FACTORY, &mut out) };
        assert_eq!(hr, CLASS_E_CLASSNOTAVAILABLE);
        assert!(out.is_null());
        assert_eq!(srv.can_unload_now(), S_OK);

        let factory = srv.create_factory()?;
        let c1 = factory.create_explorer_command()?;
        let c2 = factory.create_explorer_command()?;
        drop(factory);
        assert_eq!(srv.can_unload_now(), S_FALSE);
        drop(c1);
        assert_eq!(srv.can_unload_now(), S_FALSE);
        drop(c2);
        assert_eq!(srv.can_unload_now(), S_OK);
        Ok(())
    }

    #[test]
    fn t3_09_com_multilang_title_and_icon_double_instantiation() -> TestResult {
        let _guard = COM_TEST_LOCK.lock().map_err(|_| "COM_TEST_LOCK poisoned")?;
        let _mui_restore = ThreadMuiRestore;
        let srv = LoadedComServer::open()?;
        let factory = srv.create_factory()?;
        let c1 = factory.create_explorer_command()?;
        let c2 = factory.create_explorer_command()?;

        let locales = [
            ("en-US", "Send with TotalDrop"),
            ("tr-TR", "TotalDrop ile gönder"),
            ("ar-SA", "إرسال باستخدام TotalDrop"),
            ("ja-JP", "TotalDrop で送信"),
            ("zh-TW", "用 TotalDrop 傳送"),
        ];
        for (mui_tag, expected_title) in locales {
            let mut multi: Vec<u16> = mui_tag.encode_utf16().collect();
            multi.push(0);
            multi.push(0);
            // SAFETY: Setting thread UI language to double-NUL-terminated MUI tag.
            let ok = unsafe {
                SetThreadPreferredUILanguages(MUI_LANGUAGE_NAME, multi.as_ptr(), ptr::null_mut())
            };
            assert_ne!(ok, 0, "SetThreadPreferredUILanguages failed for {mui_tag}");

            for inst in [&c1, &c2] {
                let mut tptr: PWSTR = ptr::null_mut();
                // SAFETY: Valid COM call on live instance.
                let hr_title =
                    unsafe { (inst.vtbl().get_title)(inst.raw(), ptr::null_mut(), &mut tptr) };
                assert_eq!(hr_title, S_OK);
                assert_eq!(take_co_task_mem_wstr(tptr)?, expected_title);

                let mut iptr: PWSTR = ptr::null_mut();
                // SAFETY: Valid COM call on live instance.
                let hr_icon =
                    unsafe { (inst.vtbl().get_icon)(inst.raw(), ptr::null_mut(), &mut iptr) };
                assert_eq!(hr_icon, S_OK);
                let spec = take_co_task_mem_wstr(iptr)?;
                verify_extracted_icon(&spec)?;
            }
        }
        Ok(())
    }

    #[test]
    fn t4_07_com_warm_250_real_ntfs_files_and_10001_cap() -> TestResult {
        let _guard = COM_TEST_LOCK.lock().map_err(|_| "COM_TEST_LOCK poisoned")?;
        let srv = LoadedComServer::open()?;
        let factory = srv.create_factory()?;
        let cmd = factory.create_explorer_command()?;

        let base = std::env::temp_dir().join(format!(
            "td-com-t4-07-{}-{}",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let special_dir = base.join("A & calc.exe").join("report (2026) ^ %TEMP%");
        std::fs::create_dir_all(&special_dir)?;

        let mut real_paths: Vec<String> = Vec::with_capacity(250);
        // 1. Special shell-metacharacter NTFS file
        let meta_file = special_dir.join("file_000.txt");
        std::fs::write(&meta_file, b"meta")?;
        real_paths.push(meta_file.to_string_lossy().into_owned());

        // 2. Real long NTFS file (> 260 UTF-16 chars, created via extended prefix)
        let mut long_dir: PathBuf = base.clone();
        for seg in 0..4 {
            long_dir.push(format!("long_segment_{seg:02}_{}", "x".repeat(45)));
        }
        let long_ext_dir = PathBuf::from(expected_extended_path(&long_dir.to_string_lossy()));
        std::fs::create_dir_all(&long_ext_dir)?;
        let long_file = long_dir.join("long_payload_001.txt");
        let long_ext_file = PathBuf::from(expected_extended_path(&long_file.to_string_lossy()));
        std::fs::write(&long_ext_file, b"long")?;
        let long_str = long_file.to_string_lossy().into_owned();
        assert!(long_str.encode_utf16().count() > 260);
        real_paths.push(long_str);

        // 3. Remaining 248 real NTFS files (total 250 -> > 30,000 UTF-16 when quoted)
        let batch_dir = base.join("batch_2026_real_ntfs_items_padding_directory_name");
        std::fs::create_dir_all(&batch_dir)?;
        for idx in 2..250 {
            let p = batch_dir.join(format!(
                "totaldrop_e2e_file_item_number_{idx:04}_payload.bin"
            ));
            std::fs::write(&p, b"ok")?;
            real_paths.push(p.to_string_lossy().into_owned());
        }
        assert_eq!(real_paths.len(), 250);

        let pipe_srv = SingleShotPipeServer::spawn()?;
        let mut arr250 = MockShellItemArray::new(real_paths.clone());
        // SAFETY: Valid COM `Invoke` streaming 250 real NTFS paths over Named Pipe.
        let hr = unsafe { (cmd.vtbl().invoke)(cmd.raw(), arr250.as_ptr(), ptr::null_mut()) };
        assert_eq!(hr, S_OK);

        let raw_bytes = pipe_srv.finish()?;
        let mut dec = IpcFrameDecoder::new();
        let envelopes = dec.push_bytes(&raw_bytes)?;
        dec.finish_eof()?;
        assert_eq!(envelopes.len(), 1);
        match &envelopes.first().ok_or("missing envelope")?.payload {
            ActivationPayload::ExplorerSend { paths } => {
                assert_eq!(paths.len(), 250);
                for (actual, expected_raw) in paths.iter().zip(real_paths.iter()) {
                    let expected_ext = expected_extended_path(expected_raw);
                    assert_eq!(actual.extended_path(), expected_ext);
                }
            }
            other => return Err(format!("unexpected payload: {other:?}").into()),
        }

        // 10_001 mock items refused cleanly with 0x8007006F
        let mut arr_over = MockShellItemArray::with_virtual_count(10_001);
        // SAFETY: Valid COM `Invoke` verifying hard item ceiling.
        let hr_over = unsafe { (cmd.vtbl().invoke)(cmd.raw(), arr_over.as_ptr(), ptr::null_mut()) };
        assert_eq!(hr_over, HRESULT_ERROR_BUFFER_OVERFLOW);

        let _ = std::fs::remove_dir_all(PathBuf::from(expected_extended_path(
            &base.to_string_lossy(),
        )));
        Ok(())
    }

    #[test]
    fn tier5_com_lock_server_query_interface_and_mixed_virtual_items() -> TestResult {
        let _guard = COM_TEST_LOCK.lock().map_err(|_| "COM_TEST_LOCK poisoned")?;
        let srv = LoadedComServer::open()?;
        let factory = srv.create_factory()?;

        // 1. Direct QueryInterface on IClassFactory & IExplorerCommand.
        let bogus_iid = GUID::from_u128(0xABCD_1234_5678_90EF_1111_2222_3333_4444);
        let mut qi_out: *mut c_void = ptr::null_mut();
        // SAFETY: Direct COM QueryInterface check for IID_IUnknown.
        let hr_f_unk = unsafe {
            (factory.vtbl().base.QueryInterface)(factory.raw(), &IID_IUnknown, &mut qi_out)
        };
        assert_eq!(hr_f_unk, S_OK);
        assert_eq!(qi_out, factory.raw());
        // SAFETY: Release extra QueryInterface reference.
        let _ = unsafe { (factory.vtbl().base.Release)(qi_out) };

        // SAFETY: Unsupported IID must return E_NOINTERFACE.
        let hr_f_bogus =
            unsafe { (factory.vtbl().base.QueryInterface)(factory.raw(), &bogus_iid, &mut qi_out) };
        assert_eq!(hr_f_bogus, E_NOINTERFACE);
        assert!(qi_out.is_null());

        let cmd = factory.create_explorer_command()?;
        // SAFETY: Direct COM QueryInterface on IExplorerCommand.
        let hr_c_icmd = unsafe {
            (cmd.vtbl().base.QueryInterface)(cmd.raw(), &IID_IEXPLORER_COMMAND, &mut qi_out)
        };
        assert_eq!(hr_c_icmd, S_OK);
        assert_eq!(qi_out, cmd.raw());
        // SAFETY: Release extra QueryInterface reference.
        let _ = unsafe { (cmd.vtbl().base.Release)(qi_out) };
        // SAFETY: Unsupported IID must return E_NOINTERFACE.
        let hr_c_bogus =
            unsafe { (cmd.vtbl().base.QueryInterface)(cmd.raw(), &bogus_iid, &mut qi_out) };
        assert_eq!(hr_c_bogus, E_NOINTERFACE);
        assert!(qi_out.is_null());

        // 2. Mixed valid + virtual (GetDisplayName returning E_FAIL) IShellItemArray over Named Pipe.
        let pipe_srv = SingleShotPipeServer::spawn()?;
        let mut mixed_arr = MockShellItemArray::with_mixed_items(vec![
            Some(r"C:\Users\Alice\keep_one.txt".to_owned()),
            None,
            Some(r"C:\Users\Alice\keep_two.txt".to_owned()),
        ]);
        // SAFETY: Valid COM Invoke with mixed valid & virtual shell items.
        let hr_inv = unsafe { (cmd.vtbl().invoke)(cmd.raw(), mixed_arr.as_ptr(), ptr::null_mut()) };
        assert_eq!(hr_inv, S_OK);
        let raw_bytes = pipe_srv.finish()?;
        let mut dec = IpcFrameDecoder::new();
        let envelopes = dec.push_bytes(&raw_bytes)?;
        dec.finish_eof()?;
        assert_eq!(envelopes.len(), 1);
        match &envelopes.first().ok_or("missing envelope")?.payload {
            ActivationPayload::ExplorerSend { paths } => {
                assert_eq!(paths.len(), 2);
                assert_eq!(
                    paths.first().map(|p| p.extended_path()),
                    Some(r"\\?\C:\Users\Alice\keep_one.txt")
                );
                assert_eq!(
                    paths.get(1).map(|p| p.extended_path()),
                    Some(r"\\?\C:\Users\Alice\keep_two.txt")
                );
            }
            other => return Err(format!("unexpected payload: {other:?}").into()),
        }

        // 3. IClassFactory::LockServer(TRUE) holds DllCanUnloadNow() == S_FALSE until LockServer(FALSE).
        // SAFETY: Lock server before releasing cmd.
        let hr_lock = unsafe { (factory.vtbl().lock_server)(factory.raw(), 1) };
        assert_eq!(hr_lock, S_OK);
        drop(cmd);
        assert_eq!(srv.can_unload_now(), S_FALSE);
        // SAFETY: Unlock server.
        let hr_unlock = unsafe { (factory.vtbl().lock_server)(factory.raw(), 0) };
        assert_eq!(hr_unlock, S_OK);
        assert_eq!(srv.can_unload_now(), S_FALSE);
        drop(factory);
        assert_eq!(srv.can_unload_now(), S_OK);
        Ok(())
    }
}
