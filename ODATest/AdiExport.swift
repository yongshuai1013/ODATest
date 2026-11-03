import Foundation
import CryptoKit
import UIKit

/// adi.pb＋身份導出（唯讀）：把既有 adi.pb 原封不動複製出來，連同一份
/// identity.json 以系統分享面板送出，供跨裝置判讀實驗使用。
/// 本工具只讀檔案與 UserDefaults 的 identifier——不觸發 provisioning、
/// 不刪檔、不改動任何既有登入／鑄造行為。檔案不存在時明確回報「尚未鑄造」。
enum AdiExporter {

    static func export(engine: String, engineLabel: String, adiURL: URL, identifier: UUID,
                       log: (String) -> Void) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: adiURL.path) else {
            log("⚠️ 導出失敗：\(engineLabel) 的 adi.pb 尚未鑄造（\(adiURL.lastPathComponent) 不存在）——請先在本區完成一次 provisioning／登入讓它鑄造後，再回來導出")
            return
        }
        do {
            let data = try Data(contentsOf: adiURL)
            guard data.count >= 8 else {
                log("⚠️ 導出失敗：\(engineLabel) 的 adi.pb 只有 \(data.count) bytes，小於 8-byte 檔頭，形狀異常")
                return
            }
            // 檔頭：[u32be = 1][u32be = N]，其後為不透明本體（8 + N + 580 形狀）
            let word1 = (UInt32(data[0]) << 24) | (UInt32(data[1]) << 16) | (UInt32(data[2]) << 8) | UInt32(data[3])
            let n = (UInt32(data[4]) << 24) | (UInt32(data[5]) << 16) | (UInt32(data[6]) << 8) | UInt32(data[7])
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            let u = identifier.uuid
            let idBytes = Data([u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
                                u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15])
            let mdLU = SHA256.hash(data: idBytes).map { String(format: "%02x", $0) }.joined()
            let info = Bundle.main.infoDictionary
            let fmt = ISO8601DateFormatter()
            let identity: [String: Any] = [
                "engine": engine,
                "identifier": identifier.uuidString,
                "adi_identifier_16": String(identifier.uuidString.prefix(16)),
                "local_user_id": mdLU,
                "adi_pb_size": data.count,
                "adi_pb_header_word1": Int(word1),
                "adi_pb_header_n": Int(n),
                "adi_pb_total_minus_n": data.count - Int(n),
                "adi_pb_sha256": sha,
                "app_version": (info?["CFBundleShortVersionString"] as? String) ?? "?",
                "app_build": (info?["CFBundleVersion"] as? String) ?? "?",
                "exported_at": fmt.string(from: Date()),
            ]
            let jsonData = try JSONSerialization.data(withJSONObject: identity, options: [.prettyPrinted, .sortedKeys])
            let outDir = fm.temporaryDirectory.appendingPathComponent("adi-export-\(engine)", isDirectory: true)
            try? fm.removeItem(at: outDir)
            try fm.createDirectory(at: outDir, withIntermediateDirectories: true)
            let pbOut = outDir.appendingPathComponent("adi.pb")
            let idOut = outDir.appendingPathComponent("identity.json")
            try data.write(to: pbOut)
            try jsonData.write(to: idOut)
            log("📤 導出 \(engineLabel) 身份：identifier=\(identifier.uuidString)")
            log("📤 adi.pb：\(data.count) bytes，檔頭字1=\(word1)，N=\(n)，總長-N=\(data.count - Int(n))，SHA-256=\(sha)")
            presentShare(items: [pbOut, idOut])
        } catch {
            log("⚠️ 導出失敗：\(error.localizedDescription)")
        }
    }

    private static func presentShare(items: [URL]) {
        DispatchQueue.main.async {
            let scene = UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }.first
            guard let root = scene?.windows.first(where: { $0.isKeyWindow })?.rootViewController else { return }
            var top = root
            while let presented = top.presentedViewController { top = presented }
            let vc = UIActivityViewController(activityItems: items, applicationActivities: nil)
            if let pop = vc.popoverPresentationController {
                pop.sourceView = top.view
                pop.sourceRect = CGRect(x: top.view.bounds.midX, y: top.view.bounds.midY, width: 1, height: 1)
            }
            top.present(vc, animated: true)
        }
    }
}
