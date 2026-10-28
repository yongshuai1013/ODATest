// apparition_anisette.h — ApparitionAnisette 靜態庫的 C 接口（手寫，與 src/lib.rs 的 FFI 一一對應）
//
// 來源：移植自 Apparition（MIT, Copyright (c) 2026 Illixion）的 anisette 實現。
// 回傳碼：0 成功；1 緩衝太小（out_len 已寫入所需長度，兩段式重試）；
// -1 未初始化；-2 參數錯誤；-3 ADI 引擎錯誤（詳情用 apparition_adi_last_error 取）。
#ifndef APPARITION_ANISETTE_H
#define APPARITION_ANISETTE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APPARITION_OK 0
#define APPARITION_BUFFER_TOO_SMALL 1
#define APPARITION_NOT_INITIALIZED (-1)
#define APPARITION_INVALID_ARGUMENT (-2)
#define APPARITION_ADI_ERROR (-3)

/// 載入兩支 .so、啟動 ADI 引擎並選定 identity（identifier＋data_dir，adi.pb 存放處）。
/// 重複呼叫會替換舊引擎。err_buf 於失敗時寫入錯誤訊息。
int32_t apparition_adi_init(const char *services_path, const char *core_path,
                            const char *data_dir, const char *identifier,
                            char *err_buf, size_t err_len);

/// 庫的 login code：0＝已佈建，其餘為 ADI 自家原因碼（原樣回傳）。
/// FFI 層失敗回 -1（未初始化）或 INT32_MIN。
int32_t apparition_adi_login_code(void);

/// 佈建第一段：Apple 的 spim 入，cpim＋session 出（out_cpim 兩段式）。
int32_t apparition_adi_start_provisioning(const uint8_t *spim_ptr, size_t spim_len,
                                          uint32_t *out_session,
                                          uint8_t *out_cpim, size_t out_cpim_capacity,
                                          size_t *out_cpim_len);

/// 佈建第二段：Apple 對 cpim 的回覆（ptm、tk）。成功後 data_dir 內有 adi.pb。
int32_t apparition_adi_end_provisioning(uint32_t session,
                                        const uint8_t *ptm_ptr, size_t ptm_len,
                                        const uint8_t *tk_ptr, size_t tk_len);

/// 放棄一個佈建 session。
int32_t apparition_adi_abandon_provisioning(uint32_t session);

/// 取一組新的 machine ID（X-Apple-I-MD-M）與 OTP（X-Apple-I-MD）原始位元組（皆兩段式）。
int32_t apparition_adi_request_otp(uint8_t *out_mid, size_t out_mid_capacity, size_t *out_mid_len,
                                   uint8_t *out_otp, size_t out_otp_capacity, size_t *out_otp_len);

/// 最近一次 FFI 錯誤訊息（NUL 結尾，過長截斷）。
int32_t apparition_adi_last_error(char *err_buf, size_t err_len);


/// 2FA callback for `apparition_login`: `params_json` describes the
/// prompt (unknown / sms / trusted numbers / last_error); write back one
/// NUL-terminated action string into `out_action`: "code:<digits>",
/// "sms:<number id>", "devices", "resend" or "abort". Return 0 on success.
typedef int32_t (*apparition_two_factor_callback)(void *ctx, const char *params_json, char *out_action, size_t out_action_cap);

/// Signs in with isideload (Apparition's vendoured copy) over the local
/// ADI engine's anisette; the engine must already be initialized with
/// `apparition_adi_init` for the same identifier + data_dir. Returns 0 on
/// success (summary in `out_summary`), 2 on sign-in failure (error in
/// `err_buf`, prefixed with the GrandSlam auth code when there is one),
/// -2 on invalid arguments.
int32_t apparition_login(const char *email, const char *password,
                         const char *identifier_uuid, const char *data_dir,
                         apparition_two_factor_callback two_factor_cb, void *two_factor_ctx,
                         char *out_summary, size_t out_summary_cap,
                         char *err_buf, size_t err_len);


/// Anisette callback for `apparition_login_with_headers`: kind 0 fetches
/// headers JSON ({"machine_id","one_time_password","routing_info",
/// "device_id","local_user_id"}) into `out_json` — return 0 on success,
/// 1 when the anisette isn't provisioned, anything else on error;
/// kind 1 (re)provisions and returns 0 on success.
typedef int32_t (*apparition_headers_callback)(void *ctx, int32_t kind, char *out_json, size_t out_json_cap);

/// Signs in with isideload using anisette supplied by the app through
/// `headers_cb`, claiming `claim_client_info`. Same return contract as
/// `apparition_login`.
int32_t apparition_login_with_headers(const char *email, const char *password,
                                      const char *claim_client_info,
                                      apparition_headers_callback headers_cb, void *headers_ctx,
                                      apparition_two_factor_callback two_factor_cb, void *two_factor_ctx,
                                      char *out_summary, size_t out_summary_cap,
                                      char *err_buf, size_t err_len);


/// Sets the file the Rust login writes stage markers and panic reports
/// to (it survives a crash, so the app can show it on next launch).
void apparition_set_diagnostic_log(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* APPARITION_ANISETTE_H */
