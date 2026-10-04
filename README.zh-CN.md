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

   - **拿不到吊销列表就什么都不写。** keybox 本身是密钥，列表不可达时每个密钥都是
     `UNKNOWN`，此时直接拒绝保存（界面会写明原因），而不是把一个可能已被吊销的密钥
     写进库里。`REVOKED`、`SUSPENDED`、`UNKNOWN` 以及已过期的 keybox 一律不保存，
     每个被跳过的文件都会写明原因；
   - 每个候选都会与本次扫描的其它文件**以及本地已有的库**比对：同一个密钥只写一份，
     库里已经有的不再写，跳过时会写明与谁雷同、或与库里哪个文件是同一个密钥；
   - 一个 keybox 可能带两个密钥（一个 ECDSA、一个 RSA），因此**每一个**密钥都参与
     比对 —— 只要有一个密钥相同，两个文件就算同一份证书；
   - 已过期的 keybox（链中任一证书不在有效期内）记为 `REVOKED`，不保存，改为列入
     跳过清单；
   - `DeviceID` 会被改写成**你自己的设备 ID**（在 keybox 页面填写），因此保存下来
     的 keybox 带的是你的身份，而不是卖家的；
   - 文件名格式为 `yyyyMMdd` + `R`/`N` + 5 位随机数字，例如 `20261003R12345.xml`
     —— `R` 表示 RKP keybox，`N` 表示其它，随机部分会在当天已保存的文件中查重，
     重复则重新抽取；
   - 文件**直接放进 `/data/adb/teesim`**，也就是 TEESimulator 模块读取 keybox 的
     目录：不建子目录，也不在旁边写任何别的文件，因为模块只读这个目录、里面也不该
     有其它东西。写入该目录需要 root，应用会在第一次需要时申请；没有 root 就完全
     不保存，界面会写明原因。
9. **「已保存」分区**（底部导航 `Home → 已保存 → Settings`）：列出上面那个模块目录。
   每条按日期、类型、序号显示 —— `2026年10月3日本地58052` —— 磁盘上的文件名保持
   不变，由文件名里的 `R`/`N` 决定显示「RKP」还是「本地」。模块 `config.json` 指向
   的那个 keybox 会在列表里**高亮**并标注为当前使用，**「设为当前 keybox」**会把该
   文件里每个 profile 的 `keybox` 字段都指向你选中的文件（有确认框；keybox 本身
   不会被修改）。该分区有四个整库操作：

   - **一键检测吊销**：把整个保存目录当成一次扫描，用当前吊销列表逐条判定，并把
     结果写回列表，被吊销的会变红；
   - **一键删除所有吊销**：只删除已由检测确认为 `REVOKED` 或 `SUSPENDED` 的文件，
     删除前有确认框 —— 没有检测过就不会删任何东西；
   - **设为当前 keybox**：把模块切换到你选中的那个 keybox；
   - **导出**：把全部 keybox 打包成一个 zip，可以保存到你选的位置，也可以直接走
     系统分享。

## 环境要求

- Android 8.0（API 26）及以上。
- **需要 root**（保存与「已保存」分区）：keybox 放在 `/data/adb/teesim`，
  那是 TEESimulator 模块的目录，只有 root 能读写。扫描和检测都不需要 root，
  读取任意绝对路径也不需要，它是可选项，用 `MANAGE_EXTERNAL_STORAGE`；
  默认走 SAF。
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
- 与你的 keybox 有关的一切都不会离开设备：文件写在你自己设备上的模块目录里，
  不会写到别处，也不再在旁边生成任何报告文件。
- 本项目与 Google 无关，也未被其认可。请只对你自己拥有或获授权检查的 keybox
  使用；keybox 是标识设备证明身份的秘密材料。

## 许可证

GPL-3.0，继承自上游 UI 模板。见 `LICENSE`。
