import SwiftUI

struct ContentView: View {
    @StateObject private var runner = ODARunner()

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    statusSection
                    actionSection
                    if !runner.headers.isEmpty {
                        headersSection
                    }
                    logSection
                }
                .padding()
            }
            .navigationTitle("ODA 測試")
        }
        .navigationViewStyle(.stack)
    }

    // MARK: - 狀態

    private var statusSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("狀態").font(.headline)
            HStack {
                Text(runner.libsReady ? "✅" : "❌")
                Text("運行庫（libCoreADI.so / libstoreservicescore.so）")
                    .font(.subheadline)
            }
            HStack {
                Text(runner.adiReady ? "✅" : "⬜")
                Text(runner.adiReady ? "adi.pb 已 provisioning（\(runner.adiSize) bytes）" : "adi.pb 尚未 provisioning")
                    .font(.subheadline)
            }
            Text("identifier：\(runner.identifier.uuidString)")
                .font(.caption)
                .foregroundColor(.secondary)
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

    // MARK: - 操作

    private var actionSection: some View {
        VStack(spacing: 10) {
            Button {
                runner.downloadLibraries()
            } label: {
                Text("① 下載運行庫（oda.json）")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(runner.busy)

            Button {
                runner.generate()
            } label: {
                Text("② 生成 Anisette（本地）")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.green)
            .disabled(runner.busy || !runner.libsReady)

            HStack(spacing: 10) {
                Button("重置 ADI") { runner.resetADI() }
                    .buttonStyle(.bordered)
                    .disabled(runner.busy)
                Button("刪除運行庫") { runner.deleteLibraries() }
                    .buttonStyle(.bordered)
                    .tint(.red)
                    .disabled(runner.busy)
            }
        }
    }

    // MARK: - 結果 headers

    private var headersSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("生成結果（\(runner.headers.count) 個）").font(.headline)
                Spacer()
                Button("複製全部") {
                    let all = runner.headers.map { "\($0.0): \($0.1)" }.joined(separator: "\n")
                    UIPasteboard.general.string = all
                    runner.log("已複製全部 headers")
                }
                .font(.subheadline)
            }
            ForEach(runner.headers, id: \.0) { pair in
                VStack(alignment: .leading, spacing: 2) {
                    Text(pair.0)
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(pair.1)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
                .onTapGesture {
                    UIPasteboard.general.string = "\(pair.0): \(pair.1)"
                    runner.log("已複製 \(pair.0)")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
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
