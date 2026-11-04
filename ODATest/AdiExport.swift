import Foundation
import CryptoKit
import UIKit

/// adi.pb＋身份導出（唯讀）：把既有 adi.pb 原封不動複製出來，連同 identity.json
/// 打包成單一 zip 以系統分享面板送出，供跨裝置判讀實驗使用（兩份散檔在部分
/// 分享目標會被吞掉一份，故改單一 zip）；identity.json 全文另原樣印進 App
/// 日誌，複製日誌即可整份帶走當備援。
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
            let zipData = makeStoredZip(entries: [
                (name: "adi.pb", data: data),
                (name: "identity.json", data: jsonData),
            ])
            let zipName = "adi-\(engine).zip"
            let outDir = fm.temporaryDirectory.appendingPathComponent("adi-export-\(engine)", isDirectory: true)
            try? fm.removeItem(at: outDir)
            try fm.createDirectory(at: outDir, withIntermediateDirectories: true)
            let zipOut = outDir.appendingPathComponent(zipName)
            try zipData.write(to: zipOut)
            log("📤 導出 \(engineLabel) 身份：identifier=\(identifier.uuidString)")
            log("📤 adi.pb：\(data.count) bytes，檔頭字1=\(word1)，N=\(n)，總長-N=\(data.count - Int(n))，SHA-256=\(sha)")
            log("📤 已打包單一 zip：\(zipName)，共 \(zipData.count) bytes，內含 adi.pb（\(data.count) B）與 identity.json（\(jsonData.count) B）")
            log("----- identity.json 全文（起）-----")
            log(String(data: jsonData, encoding: .utf8) ?? "")
            log("----- identity.json 全文（訖）-----")
            presentShare(items: [zipOut])
        } catch {
            log("⚠️ 導出失敗：\(error.localizedDescription)")
        }
    }

    // MARK: - 最小 zip 寫法（STORE 無壓縮，不引第三方依賴）

    private static func appendU16(_ d: inout Data, _ v: UInt16) {
        d.append(UInt8(v & 0xff))
        d.append(UInt8((v >> 8) & 0xff))
    }

    private static func appendU32(_ d: inout Data, _ v: UInt32) {
        d.append(UInt8(v & 0xff))
        d.append(UInt8((v >> 8) & 0xff))
        d.append(UInt8((v >> 16) & 0xff))
        d.append(UInt8((v >> 24) & 0xff))
    }

    private static func dosDateTime(from date: Date) -> (UInt16, UInt16) {
        let c = Calendar(identifier: .gregorian)
            .dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        let time = UInt16(((c.hour ?? 0) << 11) | ((c.minute ?? 0) << 5) | ((c.second ?? 0) / 2))
        let day = UInt16(((max(1980, c.year ?? 1980) - 1980) << 9) | ((c.month ?? 1) << 5) | (c.day ?? 1))
        return (time, day)
    }

    private static let crcTable: [UInt32] = (0...255).map { i -> UInt32 in
        var crc = UInt32(i)
        for _ in 0..<8 {
            crc = (crc & 1) != 0 ? (0xEDB88320 ^ (crc >> 1)) : (crc >> 1)
        }
        return crc
    }

    private static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for b in data {
            crc = crcTable[Int((crc ^ UInt32(b)) & 0xff)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }

    private static func makeStoredZip(entries: [(name: String, data: Data)]) -> Data {
        var out = Data()
        var central = Data()
        let (dosTime, dosDate) = dosDateTime(from: Date())
        for entry in entries {
            let nameData = Data(entry.name.utf8)
            let crc = crc32(entry.data)
            let size = UInt32(entry.data.count)
            let offset = UInt32(out.count)
            appendU32(&out, 0x04034b50) // local file header
            appendU16(&out, 20)
            appendU16(&out, 0)
            appendU16(&out, 0) // method = STORE
            appendU16(&out, dosTime)
            appendU16(&out, dosDate)
            appendU32(&out, crc)
            appendU32(&out, size)
            appendU32(&out, size)
            appendU16(&out, UInt16(nameData.count))
            appendU16(&out, 0)
            out.append(nameData)
            out.append(entry.data)
            appendU32(&central, 0x02014b50) // central directory entry
            appendU16(&central, 20)
            appendU16(&central, 20)
            appendU16(&central, 0)
            appendU16(&central, 0)
            appendU16(&central, dosTime)
            appendU16(&central, dosDate)
            appendU32(&central, crc)
            appendU32(&central, size)
            appendU32(&central, size)
            appendU16(&central, UInt16(nameData.count))
            appendU16(&central, 0)
            appendU16(&central, 0)
            appendU16(&central, 0)
            appendU16(&central, 0)
            appendU32(&central, 0)
            appendU32(&central, offset)
            central.append(nameData)
        }
        let cdOffset = UInt32(out.count)
        out.append(central)
        appendU32(&out, 0x06054b50) // end of central directory
        appendU16(&out, 0)
        appendU16(&out, 0)
        appendU16(&out, UInt16(entries.count))
        appendU16(&out, UInt16(entries.count))
        appendU32(&out, UInt32(central.count))
        appendU32(&out, cdOffset)
        appendU16(&out, 0)
        return out
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
