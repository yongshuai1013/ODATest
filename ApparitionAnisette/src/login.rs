// "Their Rust login": Apparition's sign-in flow (core/src/lib.rs `sign_in`
// + core/src/claimed_platform.rs), re-implemented over this crate's local
// ADI engine instead of a remote v3 anisette server.
//
// The login itself is isideload 0.5.0 (Apparition's vendored copy in
// vendor/isideload, MIT, Copyright nab138 / Illixion for the vendored
// patches): GrandSlam SRP + 2FA + the Xcode token, unmodified. What is
// ours is only the AnisetteProvider: it serves OTPs from the in-process
// ADI engine (see adi.rs) and claims Android, because the anisette is
// made by Apple Music's Android libraries — the same reasoning as
// Apparition's ClaimedPlatform wrapper, except the claim is intrinsic to
// this provider (there is no server to ask), so no wrapper is needed.
//
// The claim follows Apparition's constants verbatim (claimed_platform.rs):
// sign-in claims Android; once signed in, the Xcode token and developer
// requests claim a Mac (`after_sign_in`), or Apple answers -80046. Their
// -22411 dance (an Android-claimed sign-in gets no 2FA step and no token
// until a pushed code is checked) is ported as well.

use std::ffi::{CStr, c_char, c_void};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use http::{HeaderMap, HeaderValue};
use isideload::anisette::{AnisetteClientInfo, AnisetteData, AnisetteDataResponse, AnisetteProvider};
use isideload::auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse};
use isideload::auth::grandslam::GrandSlam;
use isideload::dev::developer_session::DeveloperSession;
use isideload::dev::teams::TeamsApi;
use plist::Dictionary;
use plist_macro::plist;
use rootcause::prelude::*;
use sha2::{Digest, Sha256};

use crate::{fail, with_engine, write_error};

// MARK: - Diagnostics (stage markers + panic capture)
//
// The login runs across an FFI boundary, where a Rust panic aborts the
// process before Swift can see anything. Stage markers and the panic
// hook write to a file that survives the crash; the app sets its path
// with `apparition_set_diagnostic_log` and shows the contents on the
// next launch. `apparition_login*` also catch_unwinds, turning a panic
// in the sign-in flow into a normal error return whenever possible.

static DIAG_PATH: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);
static HOOK_ONCE: std::sync::Once = std::sync::Once::new();
static PROVIDER_ONCE: std::sync::Once = std::sync::Once::new();

/// reqwest in isideload is built `rustls-no-provider`: building a Client
/// panics ("No rustls crypto provider is configured") unless a provider
/// is installed process-wide first. Apparition's core does this on its
/// own init path; our FFI entry does it here. Errors (already installed)
/// are fine.
fn install_crypto_provider() {
    PROVIDER_ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub(crate) fn diag(stage: &str) {
    let guard = DIAG_PATH.lock().ok();
    let Some(Some(path)) = guard.as_ref().map(|g| g.as_ref()) else { return };
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{stage}");
    }
}

fn install_panic_hook() {
    HOOK_ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = info.payload().downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string payload>".to_string()
            };
            let location = info.location().map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column())).unwrap_or_else(|| "?".to_string());
            diag(&format!("PANIC: {payload} @ {location}"));
        }));
    });
}

#[no_mangle]
pub unsafe extern "C" fn apparition_set_diagnostic_log(path: *const c_char) {
    if path.is_null() {
        return;
    }
    if let Ok(text) = unsafe { CStr::from_ptr(path) }.to_str() {
        if let Ok(mut guard) = DIAG_PATH.lock() {
            *guard = Some(std::path::PathBuf::from(text));
        }
    }
}

/// An Android phone running Apple Music, for anisette made by Apple Music's Android libraries.
pub const ANDROID_CLIENT_INFO: &str = "<Pixel 8><Android; 14; UQ1A.240205.004><com.apple.AuthKit/1 (com.apple.android.music/4.9.6)>";
/// A Mac's AuthKit daemon, claimed after sign-in for the Xcode token.
pub const MAC_CLIENT_INFO: &str = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
pub const USER_AGENT: &str = "akd/1.0 CFNetwork/808.1.4";

const APPARITION_OK: i32 = 0;
const APPARITION_INVALID_ARGUMENT: i32 = -2;
const APPARITION_LOGIN_FAILED: i32 = 2;

fn android_info() -> AnisetteClientInfo {
    AnisetteClientInfo { client_info: ANDROID_CLIENT_INFO.to_string(), user_agent: USER_AGENT.to_string() }
}

fn mac_info() -> AnisetteClientInfo {
    AnisetteClientInfo { client_info: MAC_CLIENT_INFO.to_string(), user_agent: USER_AGENT.to_string() }
}

/// The code of the GrandSlam error behind `error` (-22411, -80045...), if one is.
/// (Same helper as Apparition's core.)
fn auth_code(error: &Report) -> Option<i64> {
    error.iter_reports().find_map(|cause| match cause.downcast_current_context::<isideload::SideloadError>()? {
        isideload::SideloadError::AuthWithMessage(code, _) => Some(*code),
        _ => None,
    })
}

/// Runs a job on the ADI engine thread; the engine must already be
/// initialized (and selected to this provider's identity) by
/// `apparition_adi_init`.
async fn engine_call<R, F>(job: F) -> std::result::Result<R, String>
where
    R: Send + 'static,
    F: FnOnce(&crate::adi::Exports) -> R + Send + 'static,
{
    tokio::task::spawn_blocking(move || with_engine(job).map_err(|code| format!("ADI engine call failed (ffi rc={code})")))
        .await
        .map_err(|e| format!("ADI engine task stopped: {e}"))?
}

/// An AnisetteProvider backed by the in-process ADI engine.
pub struct LocalAdiProvider {
    identifier_bytes: [u8; 16],
    /// Lowercase UUID string, as isideload's own state would produce.
    device_id: String,
}

impl LocalAdiProvider {
    fn md_lu_hex(&self) -> String {
        hex::encode(Sha256::digest(self.identifier_bytes))
    }

    fn provisioning_headers(&self) -> std::result::Result<HeaderMap, String> {
        let mut headers = HeaderMap::new();
        headers.insert("X-Apple-I-MD-LU", HeaderValue::from_str(&self.md_lu_hex()).map_err(|e| e.to_string())?);
        headers.insert("X-Mme-Device-Id", HeaderValue::from_str(&self.device_id).map_err(|e| e.to_string())?);
        Ok(headers)
    }
}

#[async_trait::async_trait]
impl AnisetteProvider for LocalAdiProvider {
    async fn get_anisette_data(&self) -> Result<AnisetteDataResponse, Report> {
        diag("stage: anisette requested (engine login_code probe)");
        let code = engine_call(|exports| exports.login_code()).await.map_err(|e| rootcause::report!("{e}"))?;
        if code != 0 {
            // -45061 is "not provisioned"; any other non-zero code gets the
            // same treatment — provision() will surface the real error if
            // the identity is broken in some other way.
            return Ok(AnisetteDataResponse::NeedsProvisioning);
        }
        let otp = engine_call(|exports| exports.request_otp()).await.map_err(|e| rootcause::report!("{e}"))?.map_err(|e| rootcause::report!("{e}"))?;
        diag("stage: engine OTP ok");
        Ok(AnisetteDataResponse::Data(AnisetteData::new(
            B64.encode(&otp.machine_id),
            B64.encode(&otp.one_time_password),
            "17106176".to_string(),
            ANDROID_CLIENT_INFO.to_string(),
            self.device_id.clone(),
            self.md_lu_hex(),
        )))
    }

    async fn get_client_info(&self) -> Result<AnisetteClientInfo, Report> {
        Ok(android_info())
    }

    async fn provision(&mut self, gs: &Arc<GrandSlam>, _force_recheck: bool) -> Result<(), Report> {
        diag("stage: provisioning start");
        // Same exchange as isideload's remote_v3 client performs against
        // Apple (its server half does the ADI calls; here they are local).
        let start_url = gs.get_url("midStartProvisioning")?;
        let end_url = gs.get_url("midFinishProvisioning")?;
        let headers = self.provisioning_headers().map_err(|e| rootcause::report!("{e}"))?;

        let body: Dictionary = plist!(dict {
            "Header": {},
            "Request": {}
        });
        let response = gs.plist_request(&start_url, &body, Some(headers.clone()), None).await.context("Failed to send start provisioning request")?;
        let spim_text = response.get("spim").and_then(|v| v.as_string()).ok_or_else(|| rootcause::report!("Start provisioning response missing spim"))?;
        let spim = B64.decode(spim_text).map_err(|e| rootcause::report!("spim isn't base64: {e}"))?;

        let (cpim, session) = engine_call(move |exports| exports.start_provisioning(&spim)).await.map_err(|e| rootcause::report!("{e}"))?.map_err(|e| rootcause::report!("{e}"))?;

        let body: Dictionary = plist!(dict {
            "Header": {},
            "Request": {
                "cpim": B64.encode(&cpim),
            }
        });
        let response = gs.plist_request(&end_url, &body, Some(headers), None).await.context("Failed to send end provisioning request")?;
        let ptm_text = response.get("ptm").and_then(|v| v.as_string()).ok_or_else(|| rootcause::report!("End provisioning response missing ptm"))?;
        let tk_text = response.get("tk").and_then(|v| v.as_string()).ok_or_else(|| rootcause::report!("End provisioning response missing tk"))?;
        let ptm = B64.decode(ptm_text).map_err(|e| rootcause::report!("ptm isn't base64: {e}"))?;
        let tk = B64.decode(tk_text).map_err(|e| rootcause::report!("tk isn't base64: {e}"))?;

        engine_call(move |exports| exports.end_provisioning(session, &ptm, &tk)).await.map_err(|e| rootcause::report!("{e}"))?.map_err(|e| rootcause::report!("{e}"))?;
        diag("stage: provisioning done");
        Ok(())
    }
}

// MARK: - 2FA bridge to Swift

/// Swift-side 2FA callback: receives the callback params as JSON, writes
/// back one action string: "code:<digits>", "sms:<number id>", "devices",
/// "resend" or "abort". Returns 0 when an action was written.
pub type TwoFactorCallback = unsafe extern "C" fn(ctx: *mut c_void, params_json: *const c_char, out_action: *mut c_char, out_action_cap: usize) -> i32;

struct CallbackBridge {
    cb: TwoFactorCallback,
    ctx: usize, // *mut c_void, ferried across threads
}

unsafe impl Send for CallbackBridge {}
unsafe impl Sync for CallbackBridge {}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn params_json(params: &TwoFactorCallbackParams) -> String {
    let numbers: Vec<String> = params
        .numbers
        .iter()
        .map(|n| {
            format!(
                "{{\"id\":{},\"last_two\":\"{}\",\"number_with_dial_code\":\"{}\"}}",
                n.id,
                json_escape(&n.last_two_digits),
                json_escape(&n.number_with_dial_code)
            )
        })
        .collect();
    let last_error = params.last_error.as_ref().map(|e| format!("\"{}\"", json_escape(e))).unwrap_or_else(|| "null".to_string());
    let selected = params.selected_number_id.map(|id| id.to_string()).unwrap_or_else(|| "null".to_string());
    format!(
        "{{\"unknown\":{},\"sms\":{},\"last_error\":{},\"selected_number_id\":{},\"numbers\":[{}]}}",
        params.unknown, params.sms, last_error, selected,
        numbers.join(",")
    )
}

impl CallbackBridge {
    fn ask(&self, params: TwoFactorCallbackParams) -> std::result::Result<TwoFactorCallbackResponse, String> {
        diag("stage: 2FA callback invoked");
        let json = params_json(&params);
        let c_json = std::ffi::CString::new(json).map_err(|_| "params JSON contains a NUL".to_string())?;
        let mut buf = vec![0u8; 512];
        let rc = unsafe { (self.cb)(self.ctx as *mut c_void, c_json.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len()) };
        if rc != 0 {
            return Ok(TwoFactorCallbackResponse::Abort);
        }
        let nul = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        let action = String::from_utf8_lossy(&buf[..nul]).into_owned();
        if let Some(code) = action.strip_prefix("code:") {
            Ok(TwoFactorCallbackResponse::SubmitCode(code.to_string()))
        } else if let Some(id) = action.strip_prefix("sms:") {
            id.parse::<u32>().map(TwoFactorCallbackResponse::SendSms).map_err(|_| format!("bad sms id in action: {action}"))
        } else {
            match action.as_str() {
                "devices" => Ok(TwoFactorCallbackResponse::SendToDevices),
                "resend" => Ok(TwoFactorCallbackResponse::ResendCode),
                _ => Ok(TwoFactorCallbackResponse::Abort),
            }
        }
    }
}

// MARK: - Callback provider (anisette supplied by Swift)
//
// A second provider whose anisette comes from the app itself — in ODATest
// that is AnisetteKit's Unicorn-emulated client (ODARunner's engine).
// This puts every login in the app on isideload, whatever generates the
// anisette. The provider claims whatever the app tells it to claim; the
// data itself is opaque to us.

/// Swift-side anisette callback. `kind` 0 = fetch headers JSON into
/// `out_json`: {"machine_id","one_time_password","routing_info",
/// "device_id","local_user_id"} (the X-Apple-I-MD-M / -MD / -MD-RINFO /
/// X-Mme-Device-Id / X-Apple-I-MD-LU values). Returns 0 on success, 1
/// when the anisette isn't provisioned, anything else on error.
/// `kind` 1 = (re)provision, then return 0.
pub type HeadersCallback = unsafe extern "C" fn(ctx: *mut c_void, kind: i32, out_json: *mut c_char, out_json_cap: usize) -> i32;

pub struct CallbackProvider {
    cb: HeadersCallback,
    ctx: usize, // *mut c_void, ferried across threads
    claim: AnisetteClientInfo,
}

unsafe impl Send for CallbackProvider {}
unsafe impl Sync for CallbackProvider {}

impl CallbackProvider {
    fn fetch(&self, kind: i32) -> std::result::Result<String, i32> {
        let mut buf = vec![0u8; 8192];
        let rc = unsafe { (self.cb)(self.ctx as *mut c_void, kind, buf.as_mut_ptr() as *mut c_char, buf.len()) };
        if rc != 0 {
            return Err(rc);
        }
        let nul = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        Ok(String::from_utf8_lossy(&buf[..nul]).into_owned())
    }
}

#[async_trait::async_trait]
impl AnisetteProvider for CallbackProvider {
    async fn get_anisette_data(&self) -> Result<AnisetteDataResponse, Report> {
        diag("stage: anisette requested (app headers callback)");
        let fetched = {
            let this = CallbackProvider { cb: self.cb, ctx: self.ctx, claim: self.claim.clone() };
            tokio::task::spawn_blocking(move || this.fetch(0)).await.map_err(|e| rootcause::report!("anisette callback task stopped: {e}"))?
        };
        let json = match fetched {
            Ok(json) => json,
            Err(1) => return Ok(AnisetteDataResponse::NeedsProvisioning),
            Err(rc) => return Err(rootcause::report!("anisette callback failed (rc={rc})")),
        };
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|e| rootcause::report!("anisette callback returned bad JSON: {e}"))?;
        let field = |name: &str| -> Result<String, Report> {
            value.get(name).and_then(|v| v.as_str()).map(|s| s.to_string()).ok_or_else(|| rootcause::report!("anisette JSON missing {name}"))
        };
        Ok(AnisetteDataResponse::Data(AnisetteData::new(
            field("machine_id")?,
            field("one_time_password")?,
            field("routing_info")?,
            self.claim.client_info.clone(),
            field("device_id")?,
            field("local_user_id")?,
        )))
    }

    async fn get_client_info(&self) -> Result<AnisetteClientInfo, Report> {
        Ok(self.claim.clone())
    }

    async fn provision(&mut self, _gs: &Arc<GrandSlam>, _force_recheck: bool) -> Result<(), Report> {
        let this = CallbackProvider { cb: self.cb, ctx: self.ctx, claim: self.claim.clone() };
        let done = tokio::task::spawn_blocking(move || this.fetch(1)).await.map_err(|e| rootcause::report!("anisette callback task stopped: {e}"))?;
        match done {
            Ok(_) => Ok(()),
            Err(rc) => Err(rootcause::report!("anisette (re)provisioning failed (rc={rc})")),
        }
    }
}

// MARK: - The sign-in flow

async fn sign_in<P>(email: &str, password: &str, provider: P, bridge: Arc<CallbackBridge>) -> Result<String, Report>
where
    P: AnisetteProvider + Send + Sync + 'static,
{
    let callback = move |params: TwoFactorCallbackParams| {
        let bridge = bridge.clone();
        async move {
            let ask = tokio::task::spawn_blocking(move || bridge.ask(params)).await.map_err(|e| rootcause::report!("2FA bridge task stopped: {e}"))?;
            ask.map_err(|e| rootcause::report!("{e}"))
        }
    };

    diag("stage: account build (URL bag) + SRP login");
    let mut account = AppleAccount::builder(email)
        .anisette_provider(provider)
        .login(password, callback.clone())
        .await
        .context("Apple ID sign-in failed")?;
    diag("stage: SRP login ok");

    // after_sign_in: the Xcode token (and developer requests made with it)
    // are claimed as a Mac when the sign-in claimed Android.
    let signing_in = account.grandslam_client.clone();
    account.grandslam_client = Arc::new(signing_in.claiming(mac_info()));

    let mut session = match DeveloperSession::from_account(&mut account).await {
        Ok(session) => {
            diag("stage: developer session ok (Xcode token)");
            session
        }
        Err(error) if auth_code(&error) == Some(-22411) => {
            diag("stage: -22411, second login with code_after_login");
            // An Android-claimed sign-in Apple doesn't trust yet: sign in
            // again with code_after_login so the pushed code gets checked,
            // then claim Mac again for the token.
            account.grandslam_client = signing_in.clone();
            account.code_after_login = true;
            account.login(password, callback).await.context("Second sign-in (code_after_login) failed")?;
            account.grandslam_client = Arc::new(signing_in.claiming(mac_info()));
            DeveloperSession::from_account(&mut account).await.context("Failed to open a developer session")?
        }
        Err(error) => return Err(error.context("Failed to open a developer session").into_dynamic()),
    };

    let teams = session.list_teams().await.context("Failed to list developer teams")?;
    diag("stage: teams listed");
    let mut summary = format!("登入成功（isideload）：SRP＋2FA 通過、Xcode token 已取得。Teams（{}）：", teams.len());
    for team in &teams {
        summary.push_str(&format!("\n• {}（{}）", team.name.clone().unwrap_or_else(|| "—".to_string()), team.team_id));
    }
    Ok(summary)
}

// MARK: - FFI

unsafe fn read_str(ptr: *const c_char, what: &str) -> std::result::Result<String, i32> {
    if ptr.is_null() {
        return Err(fail(APPARITION_INVALID_ARGUMENT, &format!("null {what}")));
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().map(|s| s.to_string()).map_err(|_| fail(APPARITION_INVALID_ARGUMENT, &format!("{what} isn't UTF-8")))
}

fn parse_uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(bytes)
}

fn finish<P>(
    email: &str,
    password: &str,
    provider: P,
    bridge: Arc<CallbackBridge>,
    out_summary: *mut c_char,
    out_summary_cap: usize,
    err_buf: *mut c_char,
    err_len: usize,
) -> i32
where
    P: AnisetteProvider + Send + Sync + 'static,
{
    install_panic_hook();
    install_crypto_provider();
    diag("stage: login entry");
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            unsafe { write_error(err_buf, err_len, &format!("failed to build the tokio runtime: {e}")) };
            return APPARITION_LOGIN_FAILED;
        }
    };
    diag("stage: tokio runtime built");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(sign_in(email, password, provider, bridge))));
    match outcome {
        Ok(Ok(summary)) => {
            unsafe { write_error(out_summary, out_summary_cap, &summary) };
            APPARITION_OK
        }
        Ok(Err(error)) => {
            let detail = match auth_code(&error) {
                Some(code) => format!("auth_code={code} — {error:?}"),
                None => format!("{error:?}"),
            };
            unsafe { write_error(err_buf, err_len, &detail) };
            APPARITION_LOGIN_FAILED
        }
        Err(payload) => {
            let message = if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_string()
            };
            diag(&format!("stage: panic caught at FFI boundary: {message}"));
            unsafe { write_error(err_buf, err_len, &format!("Rust panic（已攔截）: {message}")) };
            APPARITION_LOGIN_FAILED
        }
    }
}

/// Signs in with isideload (Apparition's vendored copy) using the local
/// ADI engine's anisette. The engine must already be initialized with
/// `apparition_adi_init` for the same identifier + data_dir.
///
/// On success returns 0 and writes a NUL-terminated summary (account +
/// teams) into `out_summary`. On failure returns 2 and writes the error
/// (prefixed with the GrandSlam auth code when there is one) into
/// `err_buf`. Invalid arguments return -2.
#[no_mangle]
pub unsafe extern "C" fn apparition_login(
    email: *const c_char,
    password: *const c_char,
    identifier_uuid: *const c_char,
    data_dir: *const c_char,
    two_factor_cb: TwoFactorCallback,
    two_factor_ctx: *mut c_void,
    out_summary: *mut c_char,
    out_summary_cap: usize,
    err_buf: *mut c_char,
    err_len: usize,
) -> i32 {
    let parsed = (|| -> std::result::Result<(String, String, LocalAdiProvider), i32> {
        let email = unsafe { read_str(email, "email") }?;
        let password = unsafe { read_str(password, "password") }?;
        let identifier_uuid = unsafe { read_str(identifier_uuid, "identifier_uuid") }?;
        let _data_dir = unsafe { read_str(data_dir, "data_dir") }?;
        let identifier_bytes = parse_uuid_bytes(&identifier_uuid)
            .ok_or_else(|| fail(APPARITION_INVALID_ARGUMENT, "identifier_uuid isn't a UUID"))?;
        let provider = LocalAdiProvider { identifier_bytes, device_id: identifier_uuid.to_lowercase() };
        Ok((email, password, provider))
    })();
    let (email, password, provider) = match parsed {
        Ok(values) => values,
        Err(code) => {
            let message = crate::LAST_ERROR.lock().map(|slot| slot.clone()).unwrap_or_default();
            unsafe { write_error(err_buf, err_len, &message) };
            return code;
        }
    };
    let bridge = Arc::new(CallbackBridge { cb: two_factor_cb, ctx: two_factor_ctx as usize });
    finish(&email, &password, provider, bridge, out_summary, out_summary_cap, err_buf, err_len)
}

/// Signs in with isideload using anisette supplied by the app through
/// `headers_cb` (see `CallbackProvider`), claiming `claim_client_info`.
/// Same return contract as `apparition_login`.
#[no_mangle]
pub unsafe extern "C" fn apparition_login_with_headers(
    email: *const c_char,
    password: *const c_char,
    claim_client_info: *const c_char,
    headers_cb: HeadersCallback,
    headers_ctx: *mut c_void,
    two_factor_cb: TwoFactorCallback,
    two_factor_ctx: *mut c_void,
    out_summary: *mut c_char,
    out_summary_cap: usize,
    err_buf: *mut c_char,
    err_len: usize,
) -> i32 {
    let parsed = (|| -> std::result::Result<(String, String, CallbackProvider), i32> {
        let email = unsafe { read_str(email, "email") }?;
        let password = unsafe { read_str(password, "password") }?;
        let claim = unsafe { read_str(claim_client_info, "claim_client_info") }?;
        let provider = CallbackProvider {
            cb: headers_cb,
            ctx: headers_ctx as usize,
            claim: AnisetteClientInfo { client_info: claim, user_agent: USER_AGENT.to_string() },
        };
        Ok((email, password, provider))
    })();
    let (email, password, provider) = match parsed {
        Ok(values) => values,
        Err(code) => {
            let message = crate::LAST_ERROR.lock().map(|slot| slot.clone()).unwrap_or_default();
            unsafe { write_error(err_buf, err_len, &message) };
            return code;
        }
    };
    let bridge = Arc::new(CallbackBridge { cb: two_factor_cb, ctx: two_factor_ctx as usize });
    finish(&email, &password, provider, bridge, out_summary, out_summary_cap, err_buf, err_len)
}
