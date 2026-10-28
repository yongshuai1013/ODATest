import Foundation
import SwiftUI

/// isideload（Rust）登入的 2FA 橋：Rust 在背景線程呼叫 C 回調，回調把請求
/// 解析後掛到 UI（@Published request）並阻塞等使用者回應（信號量），再把
/// 動作字串寫回去："code:<碼>" / "sms:<號碼 id>" / "devices" / "resend" / "abort"。
final class RustTwoFactorBridge: ObservableObject {
    struct NumberOption: Identifiable {
        let id: UInt32
        let label: String
    }
    struct Request {
        var unknown: Bool
        var sms: Bool
        var lastError: String?
        var numbers: [NumberOption]
        var selectedID: UInt32?
    }

    @Published var request: Request?
    private let semaphore = DispatchSemaphore(value: 0)
    private var pendingAction = "abort"

    /// 在 Rust 線程上呼叫：阻塞直到使用者回應或逾時（300 秒）。
    func ask(paramsJSON: String) -> String {
        guard let data = paramsJSON.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return "abort"
        }
        var numbers: [NumberOption] = []
        if let arr = obj["numbers"] as? [[String: Any]] {
            for n in arr {
                let id = (n["id"] as? NSNumber)?.uint32Value ?? 0
                let label = (n["number_with_dial_code"] as? String) ?? "••\(n["last_two"] as? String ?? "")"
                numbers.append(NumberOption(id: id, label: label))
            }
        }
        let req = Request(
            unknown: (obj["unknown"] as? Bool) ?? false,
            sms: (obj["sms"] as? Bool) ?? false,
            lastError: obj["last_error"] as? String,
            numbers: numbers,
            selectedID: (obj["selected_number_id"] as? NSNumber)?.uint32Value
        )
        pendingAction = "abort"
        DispatchQueue.main.async { self.request = req }
        _ = semaphore.wait(timeout: .now() + 300)
        DispatchQueue.main.async { self.request = nil }
        return pendingAction
    }

    func respond(_ action: String) {
        pendingAction = action
        semaphore.signal()
    }
}

/// isideload 的 anisette 回調來源（Unicorn 版用）：handler 在 Rust 線程上
/// 被呼叫，kind 0 = 取 headers JSON、kind 1 = 重置後重新佈建。
/// 回 (rc, json)：rc 0 成功、1 未佈建、其他為錯誤。
final class RustHeadersSource {
    private let handler: (Int32) -> (Int32, String)
    init(handler: @escaping (Int32) -> (Int32, String)) { self.handler = handler }
    func fetch(kind: Int32) -> (Int32, String) { handler(kind) }
}

func writeRustCString(_ s: String, to dst: UnsafeMutablePointer<CChar>, cap: Int) {
    guard cap > 0 else { return }
    let bytes = Array(s.utf8)
    let n = min(bytes.count, cap - 1)
    for i in 0..<n { dst[i] = CChar(bitPattern: bytes[i]) }
    dst[n] = 0
}

/// Rust 登入成功 summary 的解析：第一行是總覽，其後 "• 名稱（id）" 是 teams。
func parseRustSummary(_ summary: String) -> (headline: String, teams: [(name: String, id: String)]) {
    let lines = summary.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    var teams: [(name: String, id: String)] = []
    for line in lines.dropFirst() where line.hasPrefix("• ") {
        let body = String(line.dropFirst(2))
        if let open = body.lastIndex(of: "（"), body.hasSuffix("）") {
            teams.append((name: String(body[..<open]), id: String(body[body.index(after: open)..<body.index(before: body.endIndex)])))
        }
    }
    return (lines.first ?? summary, teams)
}

// MARK: - C 回調（簽名對 apparition_anisette.h 的 typedef）

@_cdecl("odatest_rust_two_factor")
func odatest_rust_two_factor(ctx: UnsafeMutableRawPointer?, paramsJSON: UnsafePointer<CChar>?, outAction: UnsafeMutablePointer<CChar>?, outCap: Int) -> Int32 {
    guard let ctx, let paramsJSON, let outAction, outCap > 1 else { return -1 }
    let bridge = Unmanaged<RustTwoFactorBridge>.fromOpaque(ctx).takeUnretainedValue()
    let action = bridge.ask(paramsJSON: String(cString: paramsJSON))
    writeRustCString(action, to: outAction, cap: outCap)
    return 0
}

@_cdecl("odatest_rust_headers")
func odatest_rust_headers(ctx: UnsafeMutableRawPointer?, kind: Int32, outJSON: UnsafeMutablePointer<CChar>?, outCap: Int) -> Int32 {
    guard let ctx, let outJSON, outCap > 1 else { return -1 }
    let source = Unmanaged<RustHeadersSource>.fromOpaque(ctx).takeUnretainedValue()
    let (rc, json) = source.fetch(kind: kind)
    if rc == 0 { writeRustCString(json, to: outJSON, cap: outCap) }
    return rc
}

// MARK: - 2FA 面板（isideload 回調的參數形狀與 SideSign 不同，獨立一塊）

struct RustTwoFactorPanel: View {
    @ObservedObject var bridge: RustTwoFactorBridge
    let request: RustTwoFactorBridge.Request
    @State private var code: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("雙重認證（2FA・isideload）").font(.headline)
            if let err = request.lastError {
                Text("⚠️ \(err)").font(.subheadline).foregroundColor(.red)
            }
            if request.sms, let sel = request.selectedID,
               let num = request.numbers.first(where: { $0.id == sel }) {
                Text("驗證碼已用 SMS 傳到 \(num.label)，請輸入：").font(.subheadline)
            } else if request.unknown {
                Text("請選擇接收驗證碼的方式，或輸入已收到的驗證碼：").font(.subheadline)
            } else {
                Text("請輸入驗證碼（或選擇傳送方式）：").font(.subheadline)
            }
            HStack(spacing: 10) {
                TextField("6 位驗證碼", text: $code)
                    .keyboardType(.numberPad)
                    .textFieldStyle(.roundedBorder)
                Button("送出") {
                    let c = code.trimmingCharacters(in: .whitespaces)
                    code = ""
                    bridge.respond("code:\(c)")
                }
                .buttonStyle(.borderedProminent)
                .disabled(code.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            Button("信任裝置推送") { bridge.respond("devices") }
                .buttonStyle(.bordered)
            ForEach(request.numbers) { num in
                Button("SMS 簡訊 → \(num.label)") { bridge.respond("sms:\(num.id)") }
                    .buttonStyle(.bordered)
            }
            Button("重送驗證碼") { bridge.respond("resend") }
                .font(.subheadline)
            Button("取消登入") {
                code = ""
                bridge.respond("abort")
            }
            .font(.subheadline)
            .foregroundColor(.red)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }
}
