# ODATest — On-Device Anisette 測試

專門測試 SideStore 的 **On-Device Anisette**（mahee96/AnisetteKit）在真機上能不能跑通的最小 App。

## 它怎麼運作

1. **下載運行庫**：抓 `https://zzz.haus/oda.json`（SideStore 官方同一個來源），解出 `libCoreADI.so` + `libstoreservicescore.so`（Android 版 Apple 私有庫），驗 SHA-256，存到 App 的 `Documents/ODA/libs/`。
2. **本地生成**：AnisetteKit 用自訂 ELF loader 把 .so 載入 **Unicorn 引擎（TCI 純解釋模式，不需要 JIT）** 裡執行，在裝置本機完成 ADI provisioning（對 Apple `gsa.apple.com/grandslam/GsService2/lookup` 起三步流程），把 `adi.pb` 存到 `Documents/ODA/provisioning/`，之後直接生成 anisette headers（X-Apple-I-MD 等）。

## 使用

1. 裝好打開 App，依序按「① 下載運行庫」→「② 生成 Anisette」。
2. 首次生成會先 provisioning，Unicorn 模擬跑加密運算，在舊機上可能要幾分鐘，畫面有秒數計時，不要關 App。
3. 成功後把 headers 和完整日誌複製回報；失敗也請把日誌整份回報（裡面有錯誤碼）。

## 注意

- client-info 用 AnisetteKit 預設（MacBookPro18,3 / macOS 26.6 的 AuthKit 身份）。
- 「重置 ADI」會刪掉 adi.pb，下一次生成會重新 provisioning。
- 所有檔案都在 `Documents/ODA/`，可用系統「文件」App 瀏覽。
