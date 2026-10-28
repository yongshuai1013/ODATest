// Copyright (c) 2026 Illixion — MIT License (see LICENSE / NOTICE).
//
//! Apparition's anisette engine as a static library for ODATest (iOS 15):
//! Apple's Android ADI libraries (`libstoreservicescore.so` +
//! `libCoreADI.so`), loaded and run in-process by a from-scratch ELF
//! loader (`elf`), fed a Bionic-compatible "libc" by `shim`, and driven
//! through their obfuscated entry points by `adi`.
//!
//! The C FFI at the bottom is the only surface the Swift side uses.
//! Provisioning's network round-trip (sending the `cpim` to Apple and
//! receiving `ptm`/`tk`) stays on the Swift side; this crate only makes
//! the local calls.

/// The one error type for this crate: a human-readable message.
pub type Result<T> = std::result::Result<T, String>;

/// `bail!("...")` — early-return an error message. Replaces upstream's
/// rootcause macro, keeping the ported call sites unchanged in shape.
macro_rules! bail {
    ($($t:tt)*) => {
        return Err(format!($($t)*))
    };
}

/// `report!("...")` — an error message value (a `String`), for use in
/// `ok_or_else` / `map_err` closures in the ported code.
macro_rules! report {
    ($($t:tt)*) => {
        format!($($t)*)
    };
}

pub(crate) mod adi;
pub(crate) mod elf;
pub(crate) mod login;
pub(crate) mod shim;

// ---------------------------------------------------------------------
// C FFI
//
// Return codes shared by all entry points:
//    0  success
//    1  an output buffer was too small; the matching `*_len` out
//       parameter now holds the required size, so the caller can
//       retry with a bigger buffer (the two-pass pattern)
//   -1  not initialized (`apparition_adi_init` has not succeeded)
//   -2  invalid argument (null pointer, non-UTF-8 path, ...)
//   -3  the ADI engine reported an error; see `apparition_adi_last_error`
//
// `apparition_adi_login_code` is the exception: on success it returns
// the library's own login code verbatim (0 = provisioned); on an FFI
// level failure it returns `APPARITION_ADI_NOT_INITIALIZED` (-1) or
// `APPARITION_ADI_INTERNAL_ERROR` (i32::MIN) and sets the last error.

use std::ffi::{CStr, c_char};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use adi::Adi;

pub const APPARITION_OK: i32 = 0;
pub const APPARITION_BUFFER_TOO_SMALL: i32 = 1;
pub const APPARITION_NOT_INITIALIZED: i32 = -1;
pub const APPARITION_INVALID_ARGUMENT: i32 = -2;
pub const APPARITION_ADI_ERROR: i32 = -3;
pub const APPARITION_ADI_INTERNAL_ERROR: i32 = i32::MIN;

static ENGINE: OnceLock<Mutex<Option<Adi>>> = OnceLock::new();
pub(crate) static LAST_ERROR: Mutex<String> = Mutex::new(String::new());

pub(crate) fn engine() -> &'static Mutex<Option<Adi>> {
    ENGINE.get_or_init(|| Mutex::new(None))
}

fn set_last_error(message: &str) {
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = message.to_owned();
    }
}

pub(crate) fn fail(code: i32, message: &str) -> i32 {
    set_last_error(message);
    code
}

/// Copies `message` into the caller's error buffer, NUL-terminated and
/// truncated to fit. A null buffer or zero length is allowed (ignored).
pub(crate) unsafe fn write_error(err_buf: *mut c_char, err_len: usize, message: &str) {
    if err_buf.is_null() || err_len == 0 {
        return;
    }
    let bytes = message.as_bytes();
    let count = bytes.len().min(err_len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), err_buf as *mut u8, count);
        *err_buf.add(count) = 0;
    }
}

/// The two-pass output pattern: always reports the required length;
/// returns APPARITION_BUFFER_TOO_SMALL without copying when the
/// caller's buffer is absent or too small.
unsafe fn write_output(data: &[u8], buf: *mut u8, capacity: usize, out_len: *mut usize) -> i32 {
    if out_len.is_null() {
        return fail(APPARITION_INVALID_ARGUMENT, "null length out-parameter");
    }
    unsafe { *out_len = data.len() };
    if buf.is_null() || capacity < data.len() {
        return APPARITION_BUFFER_TOO_SMALL;
    }
    if !data.is_empty() {
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len()) };
    }
    APPARITION_OK
}

unsafe fn read_input(ptr: *const u8, len: usize) -> std::result::Result<&'static [u8], i32> {
    if ptr.is_null() && len > 0 {
        return Err(fail(APPARITION_INVALID_ARGUMENT, "null input pointer with nonzero length"));
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

unsafe fn read_c_str(ptr: *const c_char, what: &str) -> std::result::Result<&'static str, i32> {
    if ptr.is_null() {
        return Err(fail(APPARITION_INVALID_ARGUMENT, &format!("null {what}")));
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().map_err(|_| fail(APPARITION_INVALID_ARGUMENT, &format!("{what} isn't UTF-8")))
}

/// Runs `job` on the ADI thread of the initialized engine.
pub(crate) fn with_engine<R: Send + 'static>(job: impl FnOnce(&adi::Exports) -> R + Send + 'static) -> std::result::Result<R, i32> {
    let guard = engine().lock().map_err(|_| fail(APPARITION_ADI_ERROR, "the engine lock is poisoned"))?;
    let adi = guard.as_ref().ok_or(APPARITION_NOT_INITIALIZED)?;
    adi.run(job).map_err(|e| fail(APPARITION_ADI_ERROR, &e))
}

/// Loads the two libraries from disk, starts the ADI engine and points
/// it at `identifier` + `data_dir` (the folder that will hold `adi.pb`;
/// created if needed). Calling it again replaces the previous engine.
///
/// `err_buf`/`err_len`: on failure an error message is written here
/// (and also kept for `apparition_adi_last_error`).
#[no_mangle]
pub unsafe extern "C" fn apparition_adi_init(
    services_path: *const c_char,
    core_path: *const c_char,
    data_dir: *const c_char,
    identifier: *const c_char,
    err_buf: *mut c_char,
    err_len: usize,
) -> i32 {
    let run = |()| -> std::result::Result<(), i32> {
        let services_path = unsafe { read_c_str(services_path, "services_path") }?;
        let core_path = unsafe { read_c_str(core_path, "core_path") }?;
        let data_dir = unsafe { read_c_str(data_dir, "data_dir") }?;
        let identifier = unsafe { read_c_str(identifier, "identifier") }?;

        let services = std::fs::read(services_path)
            .map_err(|e| fail(APPARITION_ADI_ERROR, &format!("reading libstoreservicescore.so: {e}")))?;
        let core = std::fs::read(core_path)
            .map_err(|e| fail(APPARITION_ADI_ERROR, &format!("reading libCoreADI.so: {e}")))?;
        let folder = Path::new(data_dir);
        std::fs::create_dir_all(folder)
            .map_err(|e| fail(APPARITION_ADI_ERROR, &format!("creating the provisioning folder: {e}")))?;

        let adi = Adi::start(services, core, folder).map_err(|e| fail(APPARITION_ADI_ERROR, &e))?;
        let folder = folder.to_owned();
        let identifier = identifier.to_owned();
        adi.run(move |exports| exports.select(&identifier, &folder))
            .map_err(|e| fail(APPARITION_ADI_ERROR, &e))?
            .map_err(|e| fail(APPARITION_ADI_ERROR, &e))?;

        let mut guard = engine().lock().map_err(|_| fail(APPARITION_ADI_ERROR, "the engine lock is poisoned"))?;
        *guard = Some(adi);
        Ok(())
    };
    match run(()) {
        Ok(()) => APPARITION_OK,
        Err(code) => {
            let message = LAST_ERROR.lock().map(|slot| slot.clone()).unwrap_or_default();
            unsafe { write_error(err_buf, err_len, &message) };
            code
        }
    }
}

/// The library's login code for the selected identity: 0 when
/// provisioned, otherwise ADI's own reason code, returned verbatim.
/// FFI-level failures return -1 (not initialized) or i32::MIN.
#[no_mangle]
pub extern "C" fn apparition_adi_login_code() -> i32 {
    match with_engine(|exports| exports.login_code()) {
        Ok(code) => code,
        Err(code) => code,
    }
}

/// First half of provisioning: Apple's `spim` in, the `cpim` to send
/// back out through the caller's network code, plus the session handle
/// the second half needs. `out_cpim` follows the two-pass pattern.
#[no_mangle]
pub unsafe extern "C" fn apparition_adi_start_provisioning(
    spim_ptr: *const u8,
    spim_len: usize,
    out_session: *mut u32,
    out_cpim: *mut u8,
    out_cpim_capacity: usize,
    out_cpim_len: *mut usize,
) -> i32 {
    if out_session.is_null() {
        return fail(APPARITION_INVALID_ARGUMENT, "null session out-parameter");
    }
    let spim = match unsafe { read_input(spim_ptr, spim_len) } {
        Ok(spim) => spim.to_vec(),
        Err(code) => return code,
    };
    let started = with_engine(move |exports| exports.start_provisioning(&spim));
    match started {
        Ok(Ok((cpim, session))) => {
            unsafe { *out_session = session };
            unsafe { write_output(&cpim, out_cpim, out_cpim_capacity, out_cpim_len) }
        }
        Ok(Err(e)) => fail(APPARITION_ADI_ERROR, &e),
        Err(code) => code,
    }
}

/// Second half of provisioning: Apple's answer (`ptm`, `tk`) to the
/// `cpim`. On success the provisioning folder holds `adi.pb`.
#[no_mangle]
pub unsafe extern "C" fn apparition_adi_end_provisioning(
    session: u32,
    ptm_ptr: *const u8,
    ptm_len: usize,
    tk_ptr: *const u8,
    tk_len: usize,
) -> i32 {
    let ptm = match unsafe { read_input(ptm_ptr, ptm_len) } {
        Ok(ptm) => ptm.to_vec(),
        Err(code) => return code,
    };
    let tk = match unsafe { read_input(tk_ptr, tk_len) } {
        Ok(tk) => tk.to_vec(),
        Err(code) => return code,
    };
    match with_engine(move |exports| exports.end_provisioning(session, &ptm, &tk)) {
        Ok(Ok(())) => APPARITION_OK,
        Ok(Err(e)) => fail(APPARITION_ADI_ERROR, &e),
        Err(code) => code,
    }
}

/// Gives up on a provisioning session that won't be finished.
#[no_mangle]
pub extern "C" fn apparition_adi_abandon_provisioning(session: u32) -> i32 {
    match with_engine(move |exports| exports.abandon(session)) {
        Ok(()) => APPARITION_OK,
        Err(code) => code,
    }
}

/// A fresh machine ID (`X-Apple-I-MD-M`) and one-time password
/// (`X-Apple-I-MD`), as raw bytes. Both outputs follow the two-pass
/// pattern; both required lengths are always written.
#[no_mangle]
pub unsafe extern "C" fn apparition_adi_request_otp(
    out_mid: *mut u8,
    out_mid_capacity: usize,
    out_mid_len: *mut usize,
    out_otp: *mut u8,
    out_otp_capacity: usize,
    out_otp_len: *mut usize,
) -> i32 {
    let otp = match with_engine(|exports| exports.request_otp()) {
        Ok(Ok(otp)) => otp,
        Ok(Err(e)) => return fail(APPARITION_ADI_ERROR, &e),
        Err(code) => return code,
    };
    let mid = unsafe { write_output(&otp.machine_id, out_mid, out_mid_capacity, out_mid_len) };
    if mid != APPARITION_OK {
        return mid;
    }
    unsafe { write_output(&otp.one_time_password, out_otp, out_otp_capacity, out_otp_len) }
}

/// The most recent FFI error message, NUL-terminated (two-pass in
/// spirit: pass a generous buffer; the message is truncated to fit).
#[no_mangle]
pub unsafe extern "C" fn apparition_adi_last_error(err_buf: *mut c_char, err_len: usize) -> i32 {
    let message = LAST_ERROR.lock().map(|slot| slot.clone()).unwrap_or_default();
    unsafe { write_error(err_buf, err_len, &message) };
    APPARITION_OK
}
