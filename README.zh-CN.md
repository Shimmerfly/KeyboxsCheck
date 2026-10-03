# KeyboxsCheck

一个用于审计 Android 密钥证明 **keybox** 的 Android 应用：扫描所有可访问的
keybox，对照 Google 的证明吊销列表检查每个密钥，并按**密钥身份**分组 —— 因此
只在可篡改字段上有差异的克隆 keybox 会归到同一组。

基于 [KernelSU Style UI Kit](https://github.com/chenaizhang/KernelSU-Style-UI-Kit)
模板，参考 [KeyAttestation](https://github.com/VisionR1/KeyAttestation)。

## 功能

1. **扫描**：递归扫描绝对路径目录，或通过 SAF 授权的目录，找出所有 `*.xml`。
2. **解析**：把看起来像 keybox 的 XML 判定为「确认」（可解析的 XML + 至少一个
   `<Key>` + 可解析为 X.509 的证书链）或「非 keybox」。
3. **吊销检查**：把链中每张证书对照
   `https://android.googleapis.com/attestation/status`，取最严重的结果：
   `REVOKED`、`SUSPENDED`、`VALID` 或 `UNKNOWN`。
4. **从 Telegram 导入**：用你配置的 Bot 轮询频道，拉取其中所有 `.xml`，与本地
   结果合并成同一份报告比对。
5. **按密钥身份分组**：密钥身份取自私钥推导出的 SubjectPublicKeyInfo 的
   SHA-256（失败时退化到 leaf 证书，再退化到原始 PEM 字节）。`DeviceID` 等克隆
   者可以随意修改的字段**不参与**匹配，只作为「差异字段」列出。
6. **保存**：把每个确认的 keybox 保存到
   `<输出目录>/<设备ID或unknown>/<原文件名>.xml`，同时生成
   `classification.json` 与 `report.md`。

## 环境要求

- Android 8.0（API 26）及以上。
- 不需要 root。读取任意绝对路径是可选项，用 `MANAGE_EXTERNAL_STORAGE`；默认走 SAF。
- 联网获取吊销列表。无网络时使用 24 小时缓存；完全没有缓存时全部报告为
  `UNKNOWN`，**不会**误报为未吊销。

## Telegram 配置

1. 用 [@BotFather](https://t.me/BotFather) 创建 Bot，复制 token。
2. **把 Bot 加入该频道**。Telegram 只对 Bot 已加入的频道下发 `channel_post`
   更新，建议直接设为管理员。
3. 私有频道请填数字 id（`-100…`），公开频道也可以填 `@用户名`。
4. 在 App 的 keybox 页面填入 token 与频道。token 只存于应用私有
   `SharedPreferences`，不会写进报告、日志或版本控制。

## 构建

```bash
./gradlew :app:assembleDebug          # debug APK
./gradlew :app:testDebugUnitTest      # JVM 单元测试（仅引擎）
./gradlew :app:assembleRelease        # release APK，需要签名密钥
```

引擎包 `dev.hcy917.keyboxchecker.keybox` 只依赖 JDK（外加 OkHttp 与
`org.json`），所以单元测试无需 Android 运行时即可在纯 JVM 上跑通。
`KeyboxRepository` 是该包中唯一接触 Android SDK 的文件，Compose 界面位于
`ui/screen/keybox`。

## 发布签名

`app/build.gradle.kts` 使用 apksign Gradle 插件，读取四个**项目属性**：
`KEYSTORE_FILE`、`KEYSTORE_PASSWORD`、`KEY_ALIAS`、`KEY_PASSWORD`。
建议用环境变量注入而不入库：

```bash
export ORG_GRADLE_PROJECT_KEYSTORE_FILE=/secure/release.jks
export ORG_GRADLE_PROJECT_KEYSTORE_PASSWORD=…
export ORG_GRADLE_PROJECT_KEY_ALIAS=…
export ORG_GRADLE_PROJECT_KEY_PASSWORD=…
./gradlew :app:assembleRelease
```

未提供时插件回退到 debug 签名，构建仍然成功。

## 持续集成

| 工作流 | 触发 | 作用 |
| --- | --- | --- |
| `.github/workflows/build.yml` | push / PR 到 `main` | 跑 `:app:testDebugUnitTest`，再跑 `:app:assembleDebug` 与 `:app:lintDebug`，上传 APK、测试报告与 lint 报告 |
| `.github/workflows/release.yml` | 推送 `v*` tag | 构建已签名的 release APK 并发布 GitHub Release |
| `.github/workflows/sync-upstream.yml` | 每日 03:00 UTC | 合并上游 UI 模板的新提交并创建 PR |

release 工作流需要四个仓库 Secret：`KEYSTORE_FILE`（base64 编码的签名文件）、
`KEYSTORE_PASSWORD`、`KEY_ALIAS`、`KEY_PASSWORD`。签名是尽力而为：没有 Secret
时仍会产出 debug 签名的 APK 并打印警告。

## 隐私与范围

- Telegram 凭据只保存在设备上的应用私有存储中。
- 无遥测。仅有的网络请求是你自己提供的 Telegram API 与 Google 公开吊销列表。
- 本项目与 Google 无关，也未被其认可。请只对你自己拥有或获授权检查的 keybox
  使用；keybox 是标识设备证明身份的秘密材料。

## 许可证

GPL-3.0，继承自上游 UI 模板。见 `LICENSE`。
