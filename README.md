# ODATest — On-Device Anisette 登入測試

專門測試 SideStore 的 **On-Device Anisette（ODA）** 能不能在真機上完成一次真正的 Apple ID 登入的最小 App。接線與 SideStore 相同：SideSign 的 `AnisetteDataManager`（remoteODA 模式）+ `DeveloperPortal.authenticate`。

## 流程

1. **本地 anisette**：`AnisetteDataManager` 在需要時自己下載 `https://zzz.haus/oda.json` 的運行庫（`libCoreADI.so` + `libstoreservicescore.so`），用 AnisetteKit 在 **Unicorn 引擎（TCI 純解釋、不需 JIT）** 裡執行 CoreADI，於裝置本機完成 ADI provisioning 並生成 anisette headers。`adi.pb` 存在 App 的 `Documents/ODA/`。
2. **登入**：`DeveloperPortal.authenticate(appleID:password:anisetteData:xcodeVersion: "26.0", verificationHandler:)` 走 GrandSlam SRP；需要 2FA 時 App 會跳出面板讓你選信任裝置／SMS／語音並輸入驗證碼。
3. **驗證**：登入成功後自動 `fetchTeams`，畫面列出帳號的 teams，證明 session 真的可用（不只是拿到 token）。

## 對照實驗（閃退歸因）

SideStore 開 ODA 按登入閃退（官方 issue #1582）的主因指向：免費安裝版缺 `increased-memory-limit` / `extended-virtual-addressing` entitlements，Unicorn 在舊機上分配 translator buffer 失敗後直接終止進程。

本 App 的 IPA **帶這兩個 entitlements**（CI 以 ad-hoc 簽名嵌入），**請用 TrollStore 安裝**（會保留 entitlements）。若在 iPhone 7 上能跑通登入，即坐實該歸因。

## 注意

- 密碼只傳給 Apple，不保存、不寫日誌；session 只存記憶體，登出即清。
- 首次登入要做完整 provisioning，Unicorn 模擬在舊機上可能要幾分鐘，畫面有秒數，不要關 App。
- 「重置 ADI」刪掉 adi.pb 後，下次登入會重新 provisioning。
