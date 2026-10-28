import SwiftUI
import SideSign

/// Apparition 引擎區（原生執行版 anisette）：與上方 Unicorn 版同場對照。
/// 變量開關：自稱 Android／Mac；引擎、庫、adi.pb 都與 ODA 目錄完全分開。
struct ApparitionSection: View {
    @StateObject private var runner = ApparitionRunner()
    @State private var code: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Divider()
            Text("Apparition 引擎（原生執行）").font(.title3).bold()
            statusPart
            if let req = runner.rustTwoFactor.request {
                RustTwoFactorPanel(bridge: runner.rustTwoFactor, request: req)
            } else if let req = runner.twoFactor.request {
                twoFactorPart(req)
            } else if runner.accountSummary == nil {
                loginPart
            } else {
                accountPart
            }
            logPart
        }
    }

    private var statusPart: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(runner.libsReady ? "✅" : "⬜")
                Text("運行庫（4.9.6 原配，首次自動下載）").font(.subheadline)
            }
            HStack {
                Text(runner.adiReady ? "✅" : "⬜")
                Text(runner.adiReady ? "adi.pb 已 provisioning（Apparition 目錄）" : "adi.pb 尚未 provisioning").font(.subheadline)
            }
            if runner.busy {
                Text("⏳ 執行中… 已 \(runner.elapsed) 秒").font(.subheadline).foregroundColor(.orange)
            }
            Button {
                if let url = URL(string: "apple-magnifier://enable-jit?bundle-id=com.pax.odatest") {
                    UIApplication.shared.open(url)
                }
            } label: {
                Text("① 用 TrollStore 開 JIT（會以 JIT 重開本 App）").frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            Text("需先在 TrollStore 設定裡打開「URL Scheme Enabled」。重開後再按下方登入。墊片餵的裝置屬性全空（與 Unicorn 版的 Pixel 5 模板成對照）。")
                .font(.caption).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    private var loginPart: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("登入自稱").font(.headline)
            Picker("自稱", selection: $runner.claimAndroid) {
                Text("Android").tag(true)
                Text("Mac").tag(false)
            }
            .pickerStyle(.segmented)
            Text(runner.claimAndroid ? ApparitionRunner.androidClientInfo : ApparitionRunner.macClientInfo)
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
            TextField("Apple ID（電郵）", text: $runner.appleID)
                .textContentType(.username)
                .autocapitalization(.none)
                .disableAutocorrection(true)
                .textFieldStyle(.roundedBorder)
            SecureField("密碼", text: $runner.password)
                .textContentType(.password)
                .textFieldStyle(.roundedBorder)
            Button {
                runner.login()
            } label: {
                Text("以 Apparition 引擎登入").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(runner.busy || runner.appleID.isEmpty || runner.password.isEmpty)
            Button {
                runner.loginWithRust()
            } label: {
                Text("以 Rust（isideload）登入").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(runner.busy || runner.appleID.isEmpty || runner.password.isEmpty)
            Text("Rust 版：登入全程走他們的 isideload（GrandSlam＋2FA＋token），anisette 由本區的原生引擎在進程內提供，自稱固定 Android、token 段改 Mac。")
                .font(.caption).foregroundColor(.secondary)
            Button("重置 ADI（刪 Apparition 的 adi.pb）") { runner.resetADI() }
                .font(.subheadline)
                .disabled(runner.busy)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    private var accountPart: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("✅ 登入成功（Apparition 引擎）").font(.headline)
            if let summary = runner.accountSummary {
                Text(summary).font(.subheadline)
            }
            if !runner.teams.isEmpty {
                Text("Teams（\(runner.teams.count)）：").font(.subheadline).bold()
                ForEach(runner.teams, id: \.id) { t in
                    Text("• \(t.name)（\(t.id)）").font(.caption)
                }
            }
            Button("登出") { runner.logout() }.buttonStyle(.bordered)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    @ViewBuilder
    private func twoFactorPart(_ req: TwoFactorRequest) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("雙重認證（2FA）").font(.headline)
            if let err = req.error {
                Text("⚠️ \(err)").font(.subheadline).foregroundColor(.red)
            }
            switch req {
            case .selectDeliveryMethod(_, let phones):
                Button("信任裝置推送") { runner.twoFactor.respond(.requestTrustedDevice) }
                    .buttonStyle(.bordered)
                ForEach(phones) { phone in
                    Button("SMS 簡訊 → \(phone.number)") { runner.twoFactor.respond(.requestSMS(phoneID: phone.id)) }
                        .buttonStyle(.bordered)
                    Button("語音電話 → \(phone.number)") { runner.twoFactor.respond(.requestVoice(phoneID: phone.id)) }
                        .buttonStyle(.bordered)
                }
            case .trustedDevice, .sms, .voice:
                HStack(spacing: 10) {
                    TextField("6 位驗證碼", text: $code)
                        .keyboardType(.numberPad)
                        .textFieldStyle(.roundedBorder)
                    Button("送出") {
                        let c = code.trimmingCharacters(in: .whitespaces)
                        code = ""
                        runner.twoFactor.respond(.verificationCode(c))
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(code.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            Button("取消登入") {
                code = ""
                runner.twoFactor.respond(.cancel)
            }
            .font(.subheadline)
            .foregroundColor(.red)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    private var logPart: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Apparition 日誌").font(.headline)
                Spacer()
                Button("複製日誌") { UIPasteboard.general.string = runner.logText }.font(.subheadline)
                Button("清空") { runner.clearLog() }.font(.subheadline)
            }
            Text(runner.logText.isEmpty ? "（尚無日誌）" : runner.logText)
                .font(.system(.caption, design: .monospaced))
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }
}
