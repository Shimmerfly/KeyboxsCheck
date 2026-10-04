# KeyboxsCheck

一个用于审计 Android 密钥证明 **keybox** 的 Android 应用：扫描所有可访问的
keybox，按两个参考项目的方式逐项检查，并**以文件为单位**逐条列出 —— 同一个密钥
出现在多个文件里时会被标注为雷同，而不是被悄悄合并成一条。

基于 [KernelSU Style UI Kit](https://github.com/chenaizhang/KernelSU-Style-UI-Kit)
模板。检查项沿用 [KimmyXYC/KeyboxChecker](https://github.com/KimmyXYC/KeyboxChecker)
的做法；链根识别使用 [VisionR1/KeyAttestation](https://github.com/VisionR1/KeyAttestation)
钉住的根公钥，其中包括 RKP（远程配置）检测。

## 功能

1. **扫描**：递归扫描绝对路径目录，或通过 SAF 授权的目录，找出所有 `*.xml`；
   也可以直接用「选择文件」挑一个或多个 keybox，无需授权它们所在的目录。
2. **解析**：把看起来像 keybox 的 XML 判定为「确认」（可解析的 XML + 至少一个
   `<Key>` + 可解析为 X.509 的证书链）或「非 keybox」。
3. **检查**：对每个确认的 keybox 跑 KeyboxChecker 的六项规则：

   | 检查项 | 规则 |
   | --- | --- |
   | 有效期 | 每张证书都必须落在自身 `notBefore`/`notAfter` 区间内 —— **链中任一证书过期，该 keybox 直接记为 `REVOKED`（已吊销）** |
   | 私钥 ↔ 叶证书 | 私钥推导出的公钥必须等于叶证书的公钥 |
   | 链链接 | 每张证书的签发者必须等于下一张的主体，且签名必须验证通过 |
   | 链根 | 最后一张证书必须匹配某个钉住的根 |
   | 证书条数 | 超过 3 张会被标记 |
   | 吊销 | 每张证书的序列号都会在 Google 公开列表中查询 |

4. **识别链根**：与 KeyAttestation 一样钉住已知根证书的 SubjectPublicKeyInfo ——
   Google 硬件证明根（RSA 4096）、**Google RKP 根**（`CN=Key Attestation CA1`，
   P-384）、AOSP 软件根（EC 与 RSA）、以及三星 Knox SAK v1 / v2 / SAK-M v1。
   其它一律报告为未知根，因此本地自建的根不可能冒充 Google 根。
5. **RKP 检测**：满足任一信号即判定为 RKP —— 链终止于钉住的 RKP 根，或叶证书
   携带 `ProvisioningInfo` 扩展（`1.3.6.1.4.1.11129.2.1.30`）。
6. **吊销检查**：把链中每张证书对照
   `https://android.googleapis.com/attestation/status`，取最严重的结果：
   `REVOKED`、`SUSPENDED`、`VALID` 或 `UNKNOWN`。公开列表混用十进制与十六进制
   序列号，两种读法都会被索引。列表不可用时全部报告为 `UNKNOWN`，**不会**误报
   为未吊销。证书过期本身就等于已吊销：该判定在本地完成，因此即使拿不到列表
   也会生效。
7. **按密钥比对、按文件列出**：密钥身份取自私钥推导出的 SubjectPublicKeyInfo
   的 SHA-256（失败时退化到 leaf 证书，再退化到原始 PEM 字节）。`DeviceID` 等
   克隆者可以随意修改的字段**不参与**匹配。列表**不**对同一个密钥做合并 ——
   一个文件一条，凡是共享同一个密钥的文件都会在结果里互相标注为**雷同**，因此
   只改过 `DeviceID` 的第二份拷贝不会被藏起来。
8. **保存**仍然有效、且**已由吊销检测放行**的已确认 keybox：

   - **拿不到吊销列表就不写任何东西**。keybox 是密钥：列表不可用时所有密钥只能报
     `UNKNOWN`，此时直接拒绝保存（界面会写明原因），而不是把一个可能已被吊销的密钥
     写进库里。`REVOKED`、`SUSPENDED`、`UNKNOWN` 以及已过期的 keybox 一律不保存，
     每一个被跳过的文件都会写明原因；
   - 每个候选都会与**本次扫描的其它文件**以及**本地已有的库**各比对一遍：同一个
     密钥只写出第一份，库里已经存在的密钥不会再存一遍，被跳过的会在结果里写明
     与哪个文件雷同、或库里已经有什么；
   - 一个 keybox 带**两个密钥**（ECDSA 与 RSA 各一把），因此**每一把密钥**都参与
     上面的比对 —— 只要有一把密钥相同，两个文件就是同一个证书；
   - 已过期的 keybox（链中任一证书不在有效期内）记为 `REVOKED`，不保存，改为列入
     「跳过」；
   - `DeviceID` 会被改写成**你自己的设备 ID**（在 keybox 页面填写），因此保存下来
     的 keybox 带的是你的身份而不是卖家的；
   - 文件名统一为 `yyyyMMdd` + `R`/`N` + 5 位随机数字，例如
     `20261003R12345.xml` —— `R` 表示 RKP keybox，`N` 表示其它密钥；随机部分会在
     当天已保存的文件中查重，重复则重新抽取；
   - 同时生成 `classification.json` 与 `report.md`。
9. **「已保存」分区**（底部导航 `Home → 已保存 → Settings`）：列出所有已保存的
   keybox，显示名按「日期 + 类型 + 序号」拼出来，例如 `2026年10月3日本地58052`
   —— `R`/`N` 前缀决定显示「RKP」还是「本地」，磁盘上的文件名仍保持原名不变。
   分区里提供三个整库操作：

   - **一键检测吊销**：把整个保存目录当成一次扫描，用当前吊销列表逐条判定，并把
     结果写回列表（已经确认吊销/暂停的文件会被标红）；
   - **一键删除所有吊销**：只删除检测确认 **已吊销或已暂停** 的文件，点击后会先弹
     确认框；没有检测过就不会删除任何东西；
   - **导出**：把全部 keybox 与 `classification.json`/`report.md` 打包成一个 zip，
     可以保存到你选的位置，也可以直接走系统分享。

## 环境要求

- Android 8.0（API 26）及以上。
- 不需要 root。读取任意绝对路径是可选项，用 `MANAGE_EXTERNAL_STORAGE`；默认走 SAF。
- 联网获取吊销列表。无网络时使用 24 小时缓存；完全没有缓存时全部报告为
  `UNKNOWN`，**不会**误报为未吊销，此时也不会保存任何 keybox。
- 你自己的设备 ID，在 keybox 页面填写，仅在保存时使用。

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
| `.github/workflows/lint-baseline.yml` | 手动 | 上游模板变动后重新生成 `app/lint-baseline.xml` |

release 工作流需要四个仓库 Secret：`KEYSTORE_FILE`（base64 编码的签名文件）、
`KEYSTORE_PASSWORD`、`KEY_ALIAS`、`KEY_PASSWORD`。签名是尽力而为：没有 Secret
时仍会产出 debug 签名的 APK 并打印警告。

## 隐私与范围

- 无遥测、无账号。仅有的网络请求是 Google 公开吊销列表；上游模板同步只在 CI 中运行。
- 与你的 keybox 有关的一切都不会离开设备：保存的文件、分类 JSON 与报告都写在
  你选择的输出目录里。
- 本项目与 Google 无关，也未被其认可。请只对你自己拥有或获授权检查的 keybox
  使用；keybox 是标识设备证明身份的秘密材料。

## 许可证

GPL-3.0，继承自上游 UI 模板。见 `LICENSE`。
