import SwiftUI
import SideSign

struct ContentView: View {
    @StateObject private var runner = LoginRunner()
    @State private var code: String = ""

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    statusSection
                    if let req = runner.rustTwoFactor.request {
                        RustTwoFactorPanel(bridge: runner.rustTwoFactor, request: req)
                    } else if let req = runner.twoFactor.request {
                        twoFactorSection(req)
                    } else if runner.accountSummary == nil {
                        loginSection
                    } else {
                        accountSection
                    }
                    logSection
                    ApparitionSection()
                }
                .padding()
            }
            .navigationTitle("ODA 登入測試")
        }
        .navigationViewStyle(.stack)
    }

    // MARK: - 狀態

    private var statusSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("狀態").font(.headline)
            HStack {
                Text(runner.libsReady ? "✅" : "⬜")
                Text("運行庫（首次登入時自動下載）").font(.subheadline)
            }
            HStack {
                Text(runner.adiReady ? "✅" : "⬜")
                Text(runner.adiReady ? "adi.pb 已 provisioning" : "adi.pb 尚未 provisioning").font(.subheadline)
            }
            if runner.busy {
                Text("⏳ 執行中… 已 \(runner.elapsed) 秒")
                    .font(.subheadline)
                    .foregroundColor(.orange)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    // MARK: - 登入表單

    private var loginSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Apple ID 登入").font(.headline)
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
                Text("登入").frame(maxWidth: .infinity)
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
            Text("Rust 版：登入全程走他們的 isideload（GrandSlam＋2FA＋token），anisette 仍由本機 AnisetteDataManager 生成，自稱 Android、token 段改 Mac。")
                .font(.caption)
                .foregroundColor(.secondary)
            Text("密碼只會傳給 Apple（gsa.apple.com），不保存、不寫入日誌。登入全程用本機生成的 anisette（ODA），不經任何遠端 anisette 伺服器。")
                .font(.caption)
                .foregroundColor(.secondary)
            Button("重置 ADI（刪 adi.pb）") { runner.resetADI() }
                .font(.subheadline)
                .disabled(runner.busy)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    // MARK: - 已登入

    private var accountSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("✅ 登入成功").font(.headline)
            if let summary = runner.accountSummary {
                Text(summary).font(.subheadline)
            }
            if !runner.teams.isEmpty {
                Text("Teams（\(runner.teams.count)）：").font(.subheadline).bold()
                ForEach(runner.teams, id: \.id) { t in
                    Text("• \(t.name)（\(t.id)）")
                        .font(.caption)
                }
            }
            Button("登出") { runner.logout() }
                .buttonStyle(.bordered)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    // MARK: - 2FA 面板

    @ViewBuilder
    private func twoFactorSection(_ req: TwoFactorRequest) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("雙重認證（2FA）").font(.headline)
            if let err = req.error {
                Text("⚠️ \(err)").font(.subheadline).foregroundColor(.red)
            }
            switch req {
            case .selectDeliveryMethod(let preferred, let phones):
                Text("選擇接收驗證碼的方式：").font(.subheadline)
                Button {
                    runner.twoFactor.respond(.requestTrustedDevice)
                } label: {
                    Text("信任裝置推送\(preferred == .trustedDevice ? "（預設）" : "")")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                ForEach(phones) { phone in
                    Button {
                        runner.twoFactor.respond(.requestSMS(phoneID: phone.id))
                    } label: {
                        Text("SMS 簡訊 → \(phone.number)\(preferred == .sms ? "（預設）" : "")")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    Button {
                        runner.twoFactor.respond(.requestVoice(phoneID: phone.id))
                    } label: {
                        Text("語音電話 → \(phone.number)")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
                cancelButton
            case .trustedDevice:
                Text("驗證碼已推送到你的信任裝置，請輸入：").font(.subheadline)
                codeEntry
                Button("改用 SMS 簡訊") {
                    runner.twoFactor.respond(.requestSMS(phoneID: "1"))
                }
                .font(.subheadline)
                cancelButton
            case .sms(let phones, let activeID, _):
                let num = phones.first(where: { $0.id == activeID })?.number ?? "你的電話"
                Text("驗證碼已用 SMS 傳到 \(num)，請輸入：").font(.subheadline)
                codeEntry
                HStack(spacing: 14) {
                    Button("重發") { runner.twoFactor.respond(.requestSMS(phoneID: activeID)) }
                    Button("改語音") { runner.twoFactor.respond(.requestVoice(phoneID: activeID)) }
                }
                .font(.subheadline)
                cancelButton
            case .voice(let phones, let activeID, _):
                let num = phones.first(where: { $0.id == activeID })?.number ?? "你的電話"
                Text("驗證碼正以語音電話打到 \(num)，請輸入：").font(.subheadline)
                codeEntry
                Button("重發") { runner.twoFactor.respond(.requestVoice(phoneID: activeID)) }
                    .font(.subheadline)
                cancelButton
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    private var codeEntry: some View {
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

    private var cancelButton: some View {
        Button("取消登入") {
            code = ""
            runner.twoFactor.respond(.cancel)
        }
        .font(.subheadline)
        .foregroundColor(.red)
    }

    // MARK: - 日誌

    private var logSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("日誌").font(.headline)
                Spacer()
                Button("複製日誌") {
                    UIPasteboard.general.string = runner.logText
                }
                .font(.subheadline)
                Button("清空") { runner.clearLog() }
                    .font(.subheadline)
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
