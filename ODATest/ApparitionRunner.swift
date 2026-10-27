import Foundation
import CryptoKit
import ZIPFoundation
import SideSign

/// Apparition 引擎測試流程（移植自 Apparition 的原生 anisette 實現，MIT）：
/// 同一份 Apple Music 4.9.6 運行庫，但不用 Unicorn 模擬——用原生 ELF 載入器
/// 把 .so 直接映射進本進程執行（需 TrollStore 開 JIT）。墊片餵的裝置屬性全空。
/// 佈建的網路往返照 isideload remote_v3 客戶端流程：lookup 拿 URL bag →
/// midStartProvisioning 拿 spim → 引擎 start → cpim → midFinishProvisioning
/// 拿 ptm/tk → 引擎 end → adi.pb 落盤。之後 OTP → AnisetteData → 走與
/// LoginRunner 相同的 DeveloperPortal 登入，自稱（clientInfo）可在
/// Android（Apparition 常數）／Mac 間切換做對照。
@MainActor
final class ApparitionRunner: ObservableObject {
    @Published var logText: String = ""
    @Published var busy: Bool = false
    @Published var elapsed: Int = 0
    @Published var appleID: String = UserDefaults.standard.string(forKey: "oda.appleID") ?? ""
    @Published var password: String = ""
    @Published var accountSummary: String? = nil
    @Published var teams: [(name: String, id: String)] = []
    @Published var libsReady: Bool = false
    @Published var adiReady: Bool = false
    /// 自稱：true = Android（Apparition 常數），false = Mac（Mac15,7）
    @Published var claimAndroid: Bool = UserDefaults.standard.object(forKey: "apparition.claimAndroid") as? Bool ?? true

    let twoFactor = TwoFactorBridge()
    private var authSession: AuthSession?
    private var timer: Timer?
    private var engineStarted = false

    static let androidClientInfo = "<Pixel 8><Android; 14; UQ1A.240205.004><com.apple.AuthKit/1 (com.apple.android.music/4.9.6)>"
    static let macClientInfo = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    static let userAgent = "akd/1.0 CFNetwork/808.1.4"
    static let libsSourceURL = URL(string: "https://raw.githubusercontent.com/yongshuai1013/EiliStore/main/oda/applemusic-4.9.6-oda.json")!

    var claim: String { claimAndroid ? Self.androidClientInfo : Self.macClientInfo }

    // MARK: - 路徑（與 ODA/Unicorn 引擎完全分開，避免 adi.pb 互相污染）

    var baseDir: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("Apparition", isDirectory: true)
    }
    var libsDir: URL { baseDir.appendingPathComponent("libs", isDirectory: true) }
    var provDir: URL { baseDir.appendingPathComponent("provisioning", isDirectory: true) }
    var servicesPath: URL { libsDir.appendingPathComponent("libstoreservicescore.so") }
    var corePath: URL { libsDir.appendingPathComponent("libCoreADI.so") }
    var adiPbURL: URL { provDir.appendingPathComponent("adi.pb") }

    /// 與 Unicorn 引擎共用同一個 identifier（同 App 同裝置身份）
    var identifier: UUID {
        if let s = UserDefaults.standard.string(forKey: "oda.identifier"),
           let u = UUID(uuidString: s) {
            return u
        }
        let u = UUID()
        UserDefaults.standard.set(u.uuidString, forKey: "oda.identifier")
        return u
    }

    var identifierBytes: [UInt8] {
        let u = identifier
        return [u.uuid.0, u.uuid.1, u.uuid.2, u.uuid.3, u.uuid.4, u.uuid.5, u.uuid.6, u.uuid.7,
                u.uuid.8, u.uuid.9, u.uuid.10, u.uuid.11, u.uuid.12, u.uuid.13, u.uuid.14, u.uuid.15]
    }

    /// X-Apple-I-MD-LU：identifier 16 位元組的 SHA-256（hex），與 isideload 語意一致
    var mdLU: String {
        SHA256.hash(data: Data(identifierBytes)).map { String(format: "%02x", $0) }.joined()
    }

    init() {
        refreshStatus()
        log("Apparition 引擎就緒。identifier = \(identifier.uuidString)")
        log("⚠️ 原生執行需 JIT：先按上方「用 TrollStore 開 JIT」以 JIT 重開本 App，再登入；否則載庫會失敗或閃退")
    }

    func refreshStatus() {
        libsReady = FileManager.default.fileExists(atPath: servicesPath.path)
            && FileManager.default.fileExists(atPath: corePath.path)
        adiReady = FileManager.default.fileExists(atPath: adiPbURL.path)
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

    fileprivate func note(_ message: String) async {
        await MainActor.run { self.log(message) }
    }

    // MARK: - 步驟 1：下載 4.9.6 原配運行庫

    private func ensureLibraries() async throws {
        if libsReady { return }
        await note("下載運行庫包（4.9.6 原配）：\(Self.libsSourceURL.absoluteString)")
        let (data, _) = try await URLSession.shared.data(from: Self.libsSourceURL)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let b64 = obj["l"] as? String,
              let payload = Data(base64Encoded: b64) else {
            throw NSError(domain: "Apparition", code: 1, userInfo: [NSLocalizedDescriptionKey: "oda.json 格式不符"])
        }
        let hex = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        if let expected = obj["s"] as? String {
            await note(hex == expected.lowercased() ? "✅ 庫包 SHA-256 一致" : "⚠️ 庫包 SHA-256 不一致（期望 \(expected)，實際 \(hex)）")
        }
        let fm = FileManager.default
        try fm.createDirectory(at: libsDir, withIntermediateDirectories: true)
        let zipURL = baseDir.appendingPathComponent("oda-libs.zip")
        try payload.write(to: zipURL)
        let tmp = baseDir.appendingPathComponent("unzipped-\(UUID().uuidString)", isDirectory: true)
        try fm.unzipItem(at: zipURL, to: tmp)
        // 在解壓結果裡找兩支 .so（不假設內部目錄形狀）
        var foundServices: URL?
        var foundCore: URL?
        if let en = fm.enumerator(at: tmp, includingPropertiesForKeys: nil) {
            for case let url as URL in en {
                if url.lastPathComponent == "libstoreservicescore.so" { foundServices = url }
                if url.lastPathComponent == "libCoreADI.so" { foundCore = url }
            }
        }
        guard let s = foundServices, let c = foundCore else {
            throw NSError(domain: "Apparition", code: 2, userInfo: [NSLocalizedDescriptionKey: "庫包裡找不到兩支 .so"])
        }
        try? fm.removeItem(at: servicesPath)
        try? fm.removeItem(at: corePath)
        try fm.copyItem(at: s, to: servicesPath)
        try fm.copyItem(at: c, to: corePath)
        try? fm.removeItem(at: tmp)
        await note("運行庫就位：libstoreservicescore.so + libCoreADI.so")
        await MainActor.run { self.refreshStatus() }
    }

    // MARK: - 步驟 2：啟動引擎（原生載入）

    private func ensureEngine() async throws {
        if engineStarted { return }
        try FileManager.default.createDirectory(at: provDir, withIntermediateDirectories: true)
        await note("啟動 Apparition 引擎（原生載入 .so，需 JIT）…")
        // CoreADI 的 set_identifier 只收 16 字元識別碼（UUID 連字號形式的前 16 字元，
        // 即 Apparition adi_identifier 的格式）；傳完整 36 字元 UUID 會被回 ADI -45001。
        let adiIdentifier = String(identifier.uuidString.prefix(16))
        await note("ADI 識別碼（16 字元）= \(adiIdentifier)")
        var errBuf = [CChar](repeating: 0, count: 512)
        let rc = apparition_adi_init(servicesPath.path, corePath.path, provDir.path, adiIdentifier, &errBuf, errBuf.count)
        guard rc == 0 else {
            throw NSError(domain: "Apparition", code: Int(rc), userInfo: [NSLocalizedDescriptionKey: "引擎 init 失敗 rc=\(rc)：\(String(cString: errBuf))"])
        }
        engineStarted = true
        let code = apparition_adi_login_code()
        await note("引擎已啟動。login_code = \(code)（0 = 已佈建）")
    }

    // MARK: - 步驟 3：佈建（網路往返照 isideload remote_v3 客戶端流程）

    private func plistRequest(url: URL, body: [String: Any], extraHeaders: [String: String]) async throws -> [String: Any] {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        req.setValue("text/x-xml-plist", forHTTPHeaderField: "Accept")
        req.setValue(claim, forHTTPHeaderField: "X-Mme-Client-Info")
        req.setValue(Self.userAgent, forHTTPHeaderField: "User-Agent")
        for (k, v) in extraHeaders { req.setValue(v, forHTTPHeaderField: k) }
        req.httpBody = try PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw NSError(domain: "Apparition", code: 3, userInfo: [NSLocalizedDescriptionKey: "plist 請求失敗：\(url.lastPathComponent) HTTP \((resp as? HTTPURLResponse)?.statusCode ?? -1)"])
        }
        guard let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            throw NSError(domain: "Apparition", code: 4, userInfo: [NSLocalizedDescriptionKey: "回應不是 plist dict：\(url.lastPathComponent)"])
        }
        return (plist["Response"] as? [String: Any]) ?? plist
    }

    private func provisionIfNeeded() async throws {
        if apparition_adi_login_code() == 0 {
            await note("ADI 已佈建（adi.pb 存在），跳過佈建")
            return
        }
        await note("開始佈建：先向 GrandSlam 拿 URL bag…")
        let bag = try await plistRequest(
            url: URL(string: "https://gsa.apple.com/grandslam/GsService2/lookup")!,
            body: ["Header": [String: Any](), "Request": [String: Any]()],
            extraHeaders: [:]
        )
        guard let urls = bag["urls"] as? [String: Any],
              let startURLStr = urls["midStartProvisioning"] as? String,
              let endURLStr = urls["midFinishProvisioning"] as? String,
              let startURL = URL(string: startURLStr),
              let endURL = URL(string: endURLStr) else {
            throw NSError(domain: "Apparition", code: 5, userInfo: [NSLocalizedDescriptionKey: "URL bag 缺 midStartProvisioning/midFinishProvisioning"])
        }
        let provHeaders = ["X-Apple-I-MD-LU": mdLU, "X-Mme-Device-Id": identifier.uuidString]
        await note("midStartProvisioning…")
        let startResp = try await plistRequest(url: startURL, body: ["Header": [String: Any](), "Request": [String: Any]()], extraHeaders: provHeaders)
        guard let spimB64 = startResp["spim"] as? String, let spim = Data(base64Encoded: spimB64) else {
            throw NSError(domain: "Apparition", code: 6, userInfo: [NSLocalizedDescriptionKey: "start 回應缺 spim"])
        }
        // start_provisioning 每次呼叫都開新 session，不能用兩段式先探長度：
        // 一次呼叫給足緩衝（cpim 只有數百位元組，64KB 綽綽有餘）。
        var session: UInt32 = 0
        var cpimLen = 0
        var cpimBuf = [UInt8](repeating: 0, count: 65536)
        let cpimCapacity = cpimBuf.count
        let spimBytes = [UInt8](spim)
        let rc = spimBytes.withUnsafeBufferPointer { ptr in
            cpimBuf.withUnsafeMutableBufferPointer { out in
                apparition_adi_start_provisioning(ptr.baseAddress, spimBytes.count, &session, out.baseAddress, cpimCapacity, &cpimLen)
            }
        }
        guard rc == 0 else {
            throw NSError(domain: "Apparition", code: Int(rc), userInfo: [NSLocalizedDescriptionKey: "start_provisioning 失敗 rc=\(rc)：\(lastError())"])
        }
        let cpim = Data(cpimBuf.prefix(cpimLen)).base64EncodedString()
        await note("引擎 start 完成（session=\(session)，cpim \(cpimLen) bytes），midFinishProvisioning…")
        let endResp = try await plistRequest(url: endURL, body: ["Header": [String: Any](), "Request": ["cpim": cpim]], extraHeaders: provHeaders)
        guard let ptmB64 = endResp["ptm"] as? String, let ptm = Data(base64Encoded: ptmB64),
              let tkB64 = endResp["tk"] as? String, let tk = Data(base64Encoded: tkB64) else {
            throw NSError(domain: "Apparition", code: 8, userInfo: [NSLocalizedDescriptionKey: "finish 回應缺 ptm/tk"])
        }
        let ptmBytes = [UInt8](ptm)
        let tkBytes = [UInt8](tk)
        let rcEnd = ptmBytes.withUnsafeBufferPointer { p in
            tkBytes.withUnsafeBufferPointer { t in
                apparition_adi_end_provisioning(session, p.baseAddress, ptmBytes.count, t.baseAddress, tkBytes.count)
            }
        }
        guard rcEnd == 0 else {
            throw NSError(domain: "Apparition", code: Int(rcEnd), userInfo: [NSLocalizedDescriptionKey: "end_provisioning 失敗 rc=\(rcEnd)：\(lastError())"])
        }
        await note("✅ 佈建完成，adi.pb 已落盤")
        await MainActor.run { self.refreshStatus() }
    }

    private func lastError() -> String {
        var buf = [CChar](repeating: 0, count: 512)
        _ = apparition_adi_last_error(&buf, buf.count)
        return String(cString: buf)
    }

    // MARK: - 登入（OTP → AnisetteData → DeveloperPortal）

    func login() {
        guard !busy else { return }
        let id = appleID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !id.isEmpty, !password.isEmpty else {
            log("⚠️ 請先輸入 Apple ID 和密碼")
            return
        }
        UserDefaults.standard.set(id, forKey: "oda.appleID")
        UserDefaults.standard.set(claimAndroid, forKey: "apparition.claimAndroid")
        let pwd = password
        let bridge = twoFactor
        let currentClaim = claim
        beginBusy()
        log("開始登入（Apparition 引擎）：\(id)，自稱 = \(claimAndroid ? "Android" : "Mac")")
        let started = Date()
        Task.detached {
            do {
                try await self.ensureLibraries()
                try await self.ensureEngine()
                try await self.provisionIfNeeded()
                await self.note("取 OTP…")
                var midLen = 0, otpLen = 0
                _ = apparition_adi_request_otp(nil, 0, &midLen, nil, 0, &otpLen)
                // 容量先快照成 let、出參用另一組變量：同一呼叫裡又讀又 & 傳同一個 var
                // 會觸發 Swift 獨佔存取衝突（#6 cpimBuf 同型 bug），容量會讀到錯值。
                let midCap = midLen, otpCap = otpLen
                var mid = [UInt8](repeating: 0, count: midCap)
                var otp = [UInt8](repeating: 0, count: otpCap)
                var midOut = 0, otpOut = 0
                let rc = mid.withUnsafeMutableBufferPointer { m in
                    otp.withUnsafeMutableBufferPointer { o in
                        apparition_adi_request_otp(m.baseAddress, midCap, &midOut, o.baseAddress, otpCap, &otpOut)
                    }
                }
                guard rc == 0 else {
                    throw NSError(domain: "Apparition", code: Int(rc), userInfo: [NSLocalizedDescriptionKey: "request_otp 失敗 rc=\(rc)：\(await self.lastError())"])
                }
                let fmt = ISO8601DateFormatter()
                let data = AnisetteData(
                    machineID: Data(mid.prefix(midOut)).base64EncodedString(),
                    oneTimePassword: Data(otp.prefix(otpOut)).base64EncodedString(),
                    localUserID: await self.mdLU,
                    routingInfo: "17106176",
                    deviceID: await self.identifier.uuidString,
                    serialNumber: "0",
                    clientInfo: currentClaim,
                    userAgent: Self.userAgent,
                    clientTime: fmt.string(from: Date()),
                    locale: "en_US",
                    timeZone: TimeZone.current.identifier
                )
                await self.note("anisette 就緒：MD=\(data.oneTimePassword.prefix(10))… RINFO=\(data.routingInfo)")

                await self.note("向 Apple 登入（SRP）…")
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
        log("已登出")
    }

    func resetADI() {
        guard !busy else { return }
        try? FileManager.default.removeItem(at: adiPbURL)
        log("已刪除 Apparition 的 adi.pb，下次登入會重新佈建")
        refreshStatus()
    }

    private func finishFail(_ error: Error, started: Date) async {
        await MainActor.run {
            self.log("❌ 失敗（耗時 \(Int(Date().timeIntervalSince(started))) 秒）：\(error.localizedDescription)")
            self.log("錯誤詳情：\(String(describing: error))")
            self.endBusy()
        }
    }
}
