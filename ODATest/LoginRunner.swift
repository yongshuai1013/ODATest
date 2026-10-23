import Foundation
import SideSign

/// 2FA 橋：SideSign 的 verificationHandler 是 async 閉包，被呼叫時把請求
/// 掛到 UI 上等使用者操作（選傳送方式／輸入驗證碼），再用 continuation 回覆。
@MainActor
final class TwoFactorBridge: ObservableObject {
    @Published var request: TwoFactorRequest? = nil
    private var continuation: CheckedContinuation<TwoFactorResponse, Error>?

    nonisolated func enqueue(_ req: TwoFactorRequest) async throws -> TwoFactorResponse {
        try await withCheckedThrowingContinuation { cont in
            Task { @MainActor in
                self.request = req
                self.continuation = cont
            }
        }
    }

    func respond(_ resp: TwoFactorResponse) {
        let cont = continuation
        continuation = nil
        request = nil
        cont?.resume(returning: resp)
    }
}

/// 登入測試流程（與 SideStore 相同的接線）：
/// AnisetteDataManager(remoteODA) 本地生成 anisette → DeveloperPortal.authenticate
/// （SRP 登入 + 2FA）→ fetchTeams 驗證 session 真的可用。
@MainActor
final class LoginRunner: ObservableObject {
    @Published var logText: String = ""
    @Published var busy: Bool = false
    @Published var elapsed: Int = 0
    @Published var appleID: String = UserDefaults.standard.string(forKey: "oda.appleID") ?? ""
    @Published var password: String = ""
    @Published var accountSummary: String? = nil
    @Published var teams: [(name: String, id: String)] = []
    @Published var libsReady: Bool = false
    @Published var adiReady: Bool = false

    let twoFactor = TwoFactorBridge()
    private var authSession: AuthSession?
    private var timer: Timer?

    // MARK: - 路徑與持久化

    var baseDir: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("ODA", isDirectory: true)
    }
    var adiFile: URL { baseDir.appendingPathComponent("adi.pb") }

    var identifier: UUID {
        if let s = UserDefaults.standard.string(forKey: "oda.identifier"),
           let u = UUID(uuidString: s) {
            return u
        }
        let u = UUID()
        UserDefaults.standard.set(u.uuidString, forKey: "oda.identifier")
        return u
    }

    init() {
        refreshStatus()
        log("App 啟動。identifier = \(identifier.uuidString)")
        log("entitlements 對照：本 App 帶 increased-memory-limit + extended-virtual-addressing（請用 TrollStore 安裝以保留）")
    }

    func refreshStatus() {
        let manager = AnisetteDataManager(mode: nil, baseDirectory: baseDir)
        libsReady = AnisetteDataManager.validateLibrariesExist(at: manager.libsDir)
        adiReady = FileManager.default.fileExists(atPath: adiFile.path)
    }

    // MARK: - 日誌與忙碌狀態

    func log(_ message: String) {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        logText += "[\(f.string(from: Date()))] \(message)\n"
    }

    func clearLog() { logText = "" }

    private func beginBusy() {
        busy = true
        elapsed = 0
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.elapsed += 1 }
        }
    }

    private func endBusy() {
        busy = false
        timer?.invalidate()
        timer = nil
        refreshStatus()
    }

    // MARK: - 登入

    func login() {
        guard !busy else { return }
        let id = appleID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !id.isEmpty, !password.isEmpty else {
            log("⚠️ 請先輸入 Apple ID 和密碼")
            return
        }
        UserDefaults.standard.set(id, forKey: "oda.appleID")
        let pwd = password
        let base = baseDir
        let adiURL = adiFile
        let ident = identifier
        let bridge = twoFactor
        beginBusy()
        log("開始登入：\(id)")
        let started = Date()
        Task.detached {
            do {
                // 1. 本地 anisette（remoteODA：缺運行庫會自己下載 oda.json 的庫）
                await self.note("步驟 1/3：生成本地 anisette（ODA）…")
                let manager = AnisetteDataManager(mode: nil, baseDirectory: base)
                let odaURL = URL(string: "https://zzz.haus/oda.json")!
                let existingBlob = try? Data(contentsOf: adiURL)
                if existingBlob == nil {
                    await self.note("沒有舊 adi.pb，本次會做完整 provisioning（Unicorn 模擬，在舊機上可能要幾分鐘）")
                }
                let (data, newBlob) = try await manager.fetchAnisetteData(
                    mode: .remoteODA(sourceURL: odaURL, fallbackURL: odaURL),
                    identifier: ident,
                    existingAdiBlob: existingBlob
                )
                if let blob = newBlob {
                    try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
                    try? blob.write(to: adiURL)
                    await self.note("新的 adi.pb 已保存（\(blob.count) bytes）")
                }
                await self.note("anisette 就緒：MD=\(data.oneTimePassword.prefix(10))… MD-M=\(data.machineID.prefix(10))… RINFO=\(data.routingInfo)")

                // 2. SRP 登入（+ 2FA 走 UI 橋）
                await self.note("步驟 2/3：向 Apple 登入（SRP）…")
                let portal = DeveloperPortal()
                let handler: DeveloperPortal.VerificationHandler = { req in
                    try await bridge.enqueue(req)
                }
                let session = try await portal.authenticate(
                    appleID: id,
                    password: pwd,
                    anisetteData: data,
                    xcodeVersion: "26.0",
                    verificationHandler: handler
                )
                await self.note("登入成功：\(session.account.name) <\(session.account.appleID)>")

                // 3. 用 session 拉 teams，證明 session 真的能用
                await self.note("步驟 3/3：拉取 teams 驗證 session…")
                let fetchedTeams = try await portal.fetchTeams(for: session.account, session: session.session)
                let secs = Int(Date().timeIntervalSince(started))
                await MainActor.run {
                    self.authSession = session
                    self.accountSummary = "\(session.account.name) <\(session.account.appleID)>"
                    self.teams = fetchedTeams.map { (name: $0.name, id: $0.identifier) }
                    self.password = ""
                    self.log("✅ 全部完成，耗時 \(secs) 秒：登入成功，共 \(fetchedTeams.count) 個 team")
                    for t in fetchedTeams {
                        self.log("  • \(t.name)（\(t.identifier)）")
                    }
                    self.endBusy()
                }
            } catch {
                await self.finishFail(error, started: started)
            }
        }
    }

    func logout() {
        authSession = nil
        accountSummary = nil
        teams = []
        log("已登出（session 僅存記憶體，已清除）")
    }

    func resetADI() {
        guard !busy else { return }
        try? FileManager.default.removeItem(at: adiFile)
        log("已刪除 adi.pb，下次登入會重新 provisioning")
        refreshStatus()
    }

    // MARK: - detached 回報橋

    fileprivate func note(_ message: String) async {
        await MainActor.run { self.log(message) }
    }

    fileprivate func finishFail(_ error: Error, started: Date) async {
        await MainActor.run {
            self.log("❌ 登入失敗（耗時 \(Int(Date().timeIntervalSince(started))) 秒）：\(error.localizedDescription)")
            self.log("錯誤詳情：\(String(describing: error))")
            self.endBusy()
        }
    }
}
