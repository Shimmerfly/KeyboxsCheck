package dev.hcy917.keyboxchecker.keybox

import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Builds the aggregated [ScanReport] and renders it as JSON and Markdown.
 *
 * Uses `org.json` rather than a serialization library: the template already
 * depends on it (`ui/util/Downloader.kt`) and the report schema is small
 * enough that hand-written mapping stays readable.
 */
object ReportWriter {

    private const val ISO_PATTERN = "yyyy-MM-dd'T'HH:mm:ss'Z'"

    fun iso(millis: Long): String {
        val format = SimpleDateFormat(ISO_PATTERN, Locale.US)
        format.timeZone = TimeZone.getTimeZone("UTC")
        return format.format(Date(millis))
    }

    /** Groups, de-duplicates and packages a batch of analysed keyboxes. */
    fun assemble(
        inputDescription: String,
        analyzed: List<AnalyzedKeybox>,
        revocation: RevocationSnapshot,
        filesScanned: Int,
        xmlFiles: Int,
        notKeybox: Int,
        unreadable: Int,
        nowMillis: Long = System.currentTimeMillis(),
    ): ScanReport {
        val marking = KeyboxClassifier.markDuplicates(analyzed)
        val confirmed = marking.keyboxes.filter { it.isConfirmed }
            .sortedWith(compareByDescending<AnalyzedKeybox> { it.status.severity }.thenBy { it.fileName })
        return ScanReport(
            inputDescription = inputDescription,
            generatedAtMillis = nowMillis,
            renderedAtIso = iso(nowMillis),
            keys = confirmed,
            repeatedKeys = KeyboxClassifier.repeatedKeys(confirmed),
            stats = KeyboxClassifier.stats(
                filesScanned = filesScanned,
                xmlFiles = xmlFiles,
                keyboxes = confirmed,
                notKeybox = notKeybox,
                unreadable = unreadable,
                duplicateCount = marking.duplicateCount,
            ),
            revocation = revocation,
        )
    }

    // ------------------------------------------------------------------ JSON

    fun toJson(report: ScanReport): String {
        val root = JSONObject()
        root.put("generatedAt", report.renderedAtIso)
        root.put("generatedAtMillis", report.generatedAtMillis)
        root.put("input", report.inputDescription)
        root.put("tool", "KeyboxsCheck")
        root.put("ignoredIdentityFields", JSONArray(IGNORED_IDENTITY_FIELDS))

        root.put(
            "revocation",
            JSONObject().apply {
                put("source", report.revocation.source.name)
                put("usable", report.revocation.isUsable)
                put("entryCount", report.revocation.entryCount)
                put("fetchedAtMillis", report.revocation.fetchedAtMillis)
                put("expires", report.revocation.expires ?: JSONObject.NULL)
                put("error", report.revocation.error ?: JSONObject.NULL)
            },
        )

        root.put(
            "stats",
            JSONObject().apply {
                put("filesScanned", report.stats.filesScanned)
                put("xmlFiles", report.stats.xmlFiles)
                put("confirmedKeyboxes", report.stats.confirmedKeyboxes)
                put("notKeybox", report.stats.notKeybox)
                put("unreadable", report.stats.unreadable)
                put("duplicates", report.stats.duplicates)
            },
        )

        val certificates = JSONArray()
        for (keybox in report.keys) {
            certificates.put(memberJson(keybox))
        }
        root.put("certificates", certificates)

        val repeated = JSONArray()
        for (key in report.repeatedKeys) {
            repeated.put(
                JSONObject().apply {
                    put("keyId", key.keyId)
                    put("count", key.count)
                    put("files", JSONArray(key.fileNames))
                },
            )
        }
        root.put("repeatedKeys", repeated)
        return root.toString(2)
    }

    private fun memberJson(keybox: AnalyzedKeybox): JSONObject = JSONObject().apply {
        put("fileName", keybox.fileName)
        put("keyId", keybox.primaryKeyId ?: JSONObject.NULL)
        put("deviceId", keybox.deviceId ?: JSONObject.NULL)
        put("contentSha256", keybox.contentSha256)
        put("chainFingerprint", keybox.chainFingerprint)
        put("source", keybox.source.name)
        put("status", keybox.status.name)
        put("duplicateOf", keybox.duplicateOf ?: JSONObject.NULL)
        put("parseError", keybox.parseError ?: JSONObject.NULL)
        put("remoteProvisioned", keybox.remoteProvisioned)
        put("expired", keybox.expired)

        val keys = JSONArray()
        for (key in keybox.keys) {
            val certificates = JSONArray()
            for (certificate in key.certificates) {
                certificates.put(
                    JSONObject().apply {
                        put("index", certificate.index)
                        put("subject", certificate.subject)
                        put("issuer", certificate.issuer)
                        put("serialHex", certificate.serialHex)
                        put("notBefore", iso(certificate.notBefore))
                        put("notAfter", iso(certificate.notAfter))
                        put("isCa", certificate.isCa)
                    },
                )
            }
            keys.put(
                JSONObject().apply {
                    put("index", key.index)
                    put("algorithm", key.algorithm)
                    put("keyId", key.keyId)
                    put("identitySource", key.identitySource.name)
                    put("identityError", key.identityError ?: JSONObject.NULL)
                    put("status", key.status.name)
                    put("matchedSerial", key.matchedSerial ?: JSONObject.NULL)
                    put("revocationReason", key.revocationReason ?: JSONObject.NULL)
                    put("chainValid", key.chainValid ?: JSONObject.NULL)
                    put("chainError", key.chainError ?: JSONObject.NULL)
                    put("chainRoot", key.chainRoot ?: JSONObject.NULL)
                    put("rootStatus", key.rootStatus.name)
                    put("remoteProvisioned", key.remoteProvisioned)
                    put("privateKeyMatchesLeaf", key.privateKeyMatchesLeaf ?: JSONObject.NULL)
                    put("expired", key.expired)
                    put("expiredCertificates", JSONArray(key.expiredCertificates))
                    put("tooManyCertificates", key.tooManyCertificates)
                    put("certificates", certificates)
                },
            )
        }
        put("keys", keys)
    }

    // -------------------------------------------------------------- Markdown

    fun toMarkdown(report: ScanReport): String {
        val builder = StringBuilder(4096)
        builder.append("# KeyboxsCheck 检测报告\n\n")
        builder.append("- 生成时间（UTC）：`").append(report.renderedAtIso).append("`\n")
        builder.append("- 输入来源：`").append(report.inputDescription).append("`\n")
        builder.append("- 应用：KeyboxsCheck\n\n")

        builder.append("## 汇总\n\n")
        builder.append("| 指标 | 数值 |\n| --- | --- |\n")
        builder.append("| 扫描文件数 | ").append(report.stats.filesScanned).append(" |\n")
        builder.append("| 其中 XML | ").append(report.stats.xmlFiles).append(" |\n")
        builder.append("| 确认为 keybox | ").append(report.stats.confirmedKeyboxes).append(" |\n")
        builder.append("| 非 keybox | ").append(report.stats.notKeybox).append(" |\n")
        builder.append("| 无法读取 | ").append(report.stats.unreadable).append(" |\n")
        builder.append("| 内容重复 | ").append(report.stats.duplicates).append(" |\n")
        builder.append("| keybox 文件 | ").append(report.keys.size).append(" |\n\n")

        val revoked = report.keys.count { it.status == RevocationStatus.REVOKED }
        val suspended = report.keys.count { it.status == RevocationStatus.SUSPENDED }
        val valid = report.keys.count { it.status == RevocationStatus.VALID }
        val unknown = report.keys.count { it.status == RevocationStatus.UNKNOWN }
        builder.append("### 吊销状态分布\n\n")
        builder.append("| 状态 | 文件数 |\n| --- | --- |\n")
        builder.append("| 已吊销 / REVOKED | ").append(revoked).append(" |\n")
        builder.append("| 已暂停 / SUSPENDED | ").append(suspended).append(" |\n")
        builder.append("| 未吊销 / VALID | ").append(valid).append(" |\n")
        builder.append("| 未知 / UNKNOWN | ").append(unknown).append(" |\n\n")

        builder.append("### 吊销列表来源\n\n")
        builder.append("- 来源：`").append(report.revocation.source.name).append("`\n")
        builder.append("- 条目数：").append(report.revocation.entryCount).append("\n")
        if (report.revocation.fetchedAtMillis > 0) {
            builder.append("- 抓取时间：`").append(iso(report.revocation.fetchedAtMillis)).append("`\n")
        }
        report.revocation.expires?.let { builder.append("- 有效期至：`").append(it).append("`\n") }
        report.revocation.error?.let { builder.append("- 错误：").append(it).append("\n") }
        if (!report.revocation.isUsable) {
            builder.append("\n> ⚠️ 未获得吊销列表，所有密钥状态均为 UNKNOWN，**不代表密钥可用**。\n")
        }
        builder.append('\n')

        builder.append("## 密钥列表\n\n")
        if (report.keys.isEmpty()) {
            builder.append("_没有解析出任何 keybox。_\n")
            return builder.toString()
        }

        val repeats = report.repeatedKeys.associateBy { it.keyId }
        if (repeats.isNotEmpty()) {
            builder.append("### ⚠️ 雷同证书\n\n")
            builder.append("下列文件互为同一个密钥，保存时只会保留其中一份：\n\n")
            for (key in report.repeatedKeys) {
                builder.append("- `").append(key.keyId).append("` — ")
                builder.append(key.fileNames.joinToString("`, `", "`", "`"))
                builder.append('\n')
            }
            builder.append('\n')
        }

        builder.append("每个文件单独成节，不按密钥合并。")
        builder.append("匹配时忽略的字段：")
        builder.append(IGNORED_IDENTITY_FIELDS.joinToString("`, `", "`", "`"))
        builder.append("——这些字段可以被任意编辑，不参与密钥比对。\n\n")
        for ((position, keybox) in report.keys.withIndex()) {
            builder.append("### ").append(position + 1).append(". ").append(statusLabel(keybox.status))
            builder.append(" — `").append(keybox.fileName).append("`\n\n")
            builder.append("- 密钥指纹（SHA-256）：`")
            builder.append(keybox.primaryKeyId ?: "（未能识别密钥身份）")
            builder.append("`\n")
            builder.append("- DeviceID：")
            builder.append(keybox.deviceId?.let { "`$it`" } ?: "_（未标注）_")
            builder.append('\n')
            builder.append("- 证书链：").append(chainLabel(keybox))
            builder.append("（链指纹 `").append(keybox.chainFingerprint.take(16).ifEmpty { "-" }).append("`）\n")
            builder.append("- 远程配置（RKP）：")
            builder.append(if (keybox.remoteProvisioned) "是" else "否")
            builder.append('\n')
            builder.append("- 备注：").append(notes(keybox)).append('\n')
            repeats[keybox.primaryKeyId]?.let { repeated ->
                val twins = repeated.fileNames.filter { it != keybox.fileName }
                if (twins.isNotEmpty()) {
                    builder.append("- ⚠️ 与 ")
                    builder.append(twins.joinToString("`, `", "`", "`"))
                    builder.append(" 是同一个密钥，保存时只留一份\n")
                }
            }
            builder.append('\n')

            if (keybox.keys.size > 1) {
                builder.append("| 密钥 | 算法 | 来源 | 状态 | 链校验 |\n")
                builder.append("| --- | --- | --- | --- | --- |\n")
                for (key in keybox.keys) {
                    builder.append("| #").append(key.index + 1).append(" | ")
                    builder.append(key.algorithm).append(" | ")
                    builder.append(key.identitySource.name).append(" | ")
                    builder.append(key.status.name).append(" | ")
                    builder.append(
                        when (key.chainValid) {
                            true -> "通过"
                            false -> "失效"
                            null -> "未知"
                        },
                    ).append(" |\n")
                }
                builder.append('\n')
            }
        }

        builder.append("---\n\n")
        builder.append("> 说明：DeviceID 与 attestation 属性可被任意编辑，因此**不参与**密钥匹配；")
        builder.append("密钥身份由密钥材料（私钥推导出的公钥指纹）决定，但列表按**文件**逐条给出，")
        builder.append("同一个密钥出现在多个文件里时只在末尾互相标注为雷同。状态为 UNKNOWN 表示未能完成吊销查询；")
        builder.append("链中任一证书不在有效期内时，该 keybox 直接记为 REVOKED（已吊销）且不会被保存。\n")
        builder.append("> 保存时会同时与本次扫描结果和本地已有的库比对：同一个密钥只写出第一份，")
        builder.append("库里已经存在的密钥不会重复保存。\n")
        builder.append("> 检测项：证书有效期、私钥与叶证书匹配、链内逐级签名、链根公钥比对、证书张数、")
        builder.append("逐张证书吊销查询（KimmyXYC/KeyboxChecker 的方法，链根公钥来自 VisionR1/KeyAttestation）。\n")
        return builder.toString()
    }

    private fun statusLabel(status: RevocationStatus): String = when (status) {
        RevocationStatus.REVOKED -> "🔴 已吊销 REVOKED"
        RevocationStatus.SUSPENDED -> "🟠 已暂停 SUSPENDED"
        RevocationStatus.VALID -> "🟢 未吊销 VALID"
        RevocationStatus.UNKNOWN -> "⚪ 未知 UNKNOWN"
    }

    /** How the chain terminates, in the vocabulary of the pinned key list. */
    private fun rootLabel(key: AnalyzedKey): String = when (key.rootStatus) {
        RootStatus.NULL -> "链根：未知（无证书）"
        RootStatus.FAILED -> "链根：读取失败"
        RootStatus.AOSP -> "链根：AOSP 软件证明根"
        RootStatus.GOOGLE -> "链根：Google 硬件证明根"
        RootStatus.GOOGLE_RKP -> "链根：Google RKP 根（CN=Key Attestation CA1）"
        RootStatus.KNOX -> "链根：Samsung Knox 根"
        RootStatus.UNKNOWN -> "链根：⛔ 未被识别为已知证明根"
    }

    private fun chainLabel(member: AnalyzedKeybox): String = when {
        member.keys.isEmpty() -> "-"
        member.keys.any { it.chainValid == false } -> "失效"
        member.keys.all { it.chainValid == true } -> "通过"
        else -> "未知"
    }

    private fun notes(member: AnalyzedKeybox): String {
        val parts = ArrayList<String>(5)
        member.duplicateOf?.let { parts += "内容重复于 `$it`" }
        member.parseError?.let { parts += it }
        // Expired certificates need no note of their own: every expired key
        // carries its expiry inside the revocation reason below.
        member.keys.mapNotNull { it.identityError }.distinct().forEach { parts += it }
        member.keys.mapNotNull { it.chainError }.distinct().forEach { parts += it }
        member.keys.mapNotNull { it.revocationReason }.distinct()
            .forEach { parts += "吊销原因：$it" }
        member.keys.map { rootLabel(it) }.distinct().forEach { parts += it }
        member.keys.mapNotNull { key ->
            key.privateKeyMatchesLeaf?.takeIf { !it }?.let { "私钥与叶子证书不匹配" }
        }.distinct().forEach { parts += it }
        if (member.keys.any { it.tooManyCertificates }) parts += "证书链超过 3 张"
        return parts.joinToString("；").ifBlank { "-" }
    }

    // ------------------------------------------------------------- filenames

    fun suggestedFileName(prefix: String, extension: String, nowMillis: Long): String {
        val format = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
        format.timeZone = TimeZone.getTimeZone("UTC")
        return "$prefix-${format.format(Date(nowMillis))}.$extension"
    }
}
