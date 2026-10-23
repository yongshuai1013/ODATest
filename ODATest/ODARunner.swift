import Foundation
import CryptoKit
import ZIPFoundation
import AnisetteKit

/// On-Device Anisette 測試流程：
/// 1. 從 https://zzz.haus/oda.json 下載運行庫包（libCoreADI.so + libstoreservicescore.so）
/// 2. 用 AnisetteKit（Unicorn TCI 模擬執行 libCoreADI）在本機 provisioning + 生成 anisette headers
/// 所有狀態都放在 Documents/ODA/ 底下，方便用系統「文件」App 檢查。
@MainActor
final class ODARunner: ObservableObject {
    @Published var logText: String = ""
    @Published var busy: Bool = false
    @Published var elapsed: Int = 0
    @Published var headers: [(String, String)] = []
    @Published var libsReady: Bool = false
    @Published var adiReady: Bool = false
    @Published var adiSize: Int = 0

    private var timer: Timer?

    // MARK: - 路徑

    var baseDir: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("ODA", isDirectory: true)
    }
    var libsDir: URL { baseDir.appendingPathComponent("libs", isDirectory: true) }
    var provDir: URL { baseDir.appendingPathComponent("provisioning", isDirectory: true) }
    var adiPbURL: URL { provDir.appendingPathComponent("adi.pb") }

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
        log("運行庫目錄：\(libsDir.path)")
        log("Provisioning 目錄：\(provDir.path)")
    }

    func refreshStatus() {
        libsReady = AnisetteClient.validateLibrariesExist(at: libsDir)
        if let attrs = try? FileManager.default.attributesOfItem(atPath: adiPbURL.path),
           let size = attrs[.size] as? Int {
            adiReady = true
            adiSize = size
        } else {
            adiReady = false
            adiSize = 0
        }
    }

    // MARK: - 日誌

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

    // MARK: - 步驟 1：下載運行庫

    func downloadLibraries() {
        guard !busy else { return }
        beginBusy()
        log("開始下載 ODA 元數據：https://zzz.haus/oda.json")
        Task.detached { [libsDir, baseDir] in
            do {
                let (data, _) = try await URLSession.shared.data(from: URL(string: "https://zzz.haus/oda.json")!)
                await self.note("元數據下載完成（\(data.count) bytes），解析中…")
                guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    throw NSError(domain: "ODA", code: 1, userInfo: [NSLocalizedDescriptionKey: "oda.json 不是 JSON 物件"])
                }
                let sha = (obj["s"] as? String) ?? (obj["sha256"] as? String) ?? (obj["sha"] as? String)
                guard let b64 = (obj["l"] as? String) ?? (obj["libraries"] as? String) ?? (obj["payload"] as? String),
                      let payload = Data(base64Encoded: b64) else {
                    throw NSError(domain: "ODA", code: 2, userInfo: [NSLocalizedDescriptionKey: "oda.json 缺 l 欄位或 base64 解碼失敗"])
                }
                let digest = SHA256.hash(data: payload)
                let hex = digest.map { String(format: "%02x", $0) }.joined()
                await self.note("payload 解碼完成（\(payload.count) bytes）")
                await self.note("SHA-256 計算值：\(hex)")
                if let sha {
                    await self.note("SHA-256 期望值（s）：\(sha)")
                    await self.note(hex.lowercased() == sha.lowercased() ? "✅ 雜湊一致" : "⚠️ 雜湊不一致（照樣繼續，僅記錄）")
                }
                let fm = FileManager.default
                try fm.createDirectory(at: libsDir, withIntermediateDirectories: true)
                try fm.createDirectory(at: baseDir, withIntermediateDirectories: true)
                let zipURL = baseDir.appendingPathComponent("oda-libs.zip")
                try payload.write(to: zipURL)
                // 解壓到臨時目錄再搬，避免舊檔殘留
                let tmp = baseDir.appendingPathComponent("unzipped-\(UUID().uuidString)", isDirectory: true)
                try fm.unzipItem(at: zipURL, to: tmp)
                for name in AnisetteConstants.Libraries.requiredNames {
                    let src = tmp.appendingPathComponent(name)
                    let dst = libsDir.appendingPathComponent(name)
                    if fm.fileExists(atPath: dst.path) { try fm.removeItem(at: dst) }
                    try fm.moveItem(at: src, to: dst)
                    let size = (try? fm.attributesOfItem(atPath: dst.path)[.size] as? Int) ?? -1
                    await self.note("已就位：\(name)（\(size) bytes）")
                }
                try? fm.removeItem(at: tmp)
                try? fm.removeItem(at: zipURL)
                await self.finishOK("運行庫下載完成")
            } catch {
                await self.finishFail(error)
            }
        }
    }

    // MARK: - 步驟 2：生成 anisette

    func generate() {
        guard !busy else { return }
        guard libsReady else {
            log("⚠️ 運行庫還沒下載，先做步驟 1")
            return
        }
        beginBusy()
        headers = []
        log("建立 AnisetteClient…（client-info 用 AnisetteKit 預設：\(AnisetteConstants.defaultClientInfo)）")
        let started = Date()
        Task.detached { [provDir, libsDir, identifier] in
            do {
                let client = try AnisetteClient(
                    provisioningDir: provDir,
                    libraryDirectoryResolver: { libsDir }
                )
                await self.note("Client 建立成功，開始生成（首次會先做 provisioning；Unicorn 模擬執行在 A10 上可能要幾分鐘，請勿關 App）…")
                let (hdrs, newBlob) = try await client.getAnisetteData(identifier: identifier, storage: .disk)
                let secs = Int(Date().timeIntervalSince(started))
                if let blob = newBlob {
                    await self.note("本次新 provisioning 出 adi.pb（\(blob.count) bytes）")
                }
                let sorted = hdrs.sorted { $0.key < $1.key }.map { ($0.key, $0.value) }
                await MainActor.run {
                    self.headers = sorted
                    self.log("✅ 生成成功，耗時 \(secs) 秒，共 \(sorted.count) 個 headers")
                    self.endBusy()
                }
            } catch {
                await self.finishFail(error, started: started)
            }
        }
    }

    // MARK: - 重置

    func resetADI() {
        guard !busy else { return }
        do {
            if FileManager.default.fileExists(atPath: adiPbURL.path) {
                try FileManager.default.removeItem(at: adiPbURL)
                log("已刪除 adi.pb，下次生成會重新 provisioning")
            } else {
                log("adi.pb 不存在，無需重置")
            }
        } catch {
            log("刪除 adi.pb 失敗：\(error.localizedDescription)")
        }
        refreshStatus()
    }

    func deleteLibraries() {
        guard !busy else { return }
        try? FileManager.default.removeItem(at: libsDir)
        log("已刪除運行庫目錄")
        refreshStatus()
    }

    // MARK: - detached 回報橋

    fileprivate func note(_ message: String) async {
        await MainActor.run { self.log(message) }
    }

    fileprivate func finishOK(_ message: String) async {
        await MainActor.run {
            self.log("✅ \(message)")
            self.endBusy()
        }
    }

    fileprivate func finishFail(_ error: Error, started: Date? = nil) async {
        await MainActor.run {
            if let started {
                self.log("❌ 失敗（耗時 \(Int(Date().timeIntervalSince(started))) 秒）：\(error.localizedDescription)")
            } else {
                self.log("❌ 失敗：\(error.localizedDescription)")
            }
            self.log("錯誤詳情：\(String(describing: error))")
            self.endBusy()
        }
    }
}
