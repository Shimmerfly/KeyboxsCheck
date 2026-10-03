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
            groups = KeyboxClassifier.classify(confirmed),
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
                put("entryCount", report.revocation.entries.size)
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

        val groups = JSONArray()
        for (group in report.groups) {
            val members = JSONArray()
            for (member in group.members) {
                members.put(memberJson(member))
            }
            groups.put(
                JSONObject().apply {
                    put("keyId", group.keyId)
                    put("status", group.status.name)
                    put("memberCount", group.memberCount)
                    put("chainVariants", group.chainVariants)
                    put("identicalChains", group.identicalChains)
                    put("deviceIds", JSONArray(group.deviceIds))
                    put("hasTamperedDeviceId", group.hasTamperedDeviceId)
                    put("chainFingerprints", JSONArray(group.chainFingerprints))
                    put("ignoredFields", JSONArray(IGNORED_IDENTITY_FIELDS))
                    put("members", members)
                },
            )
        }
        root.put("groups", groups)
        return root.toString(2)
    }

    private fun memberJson(keybox: AnalyzedKeybox): JSONObject = JSONObject().apply {
        put("fileName", keybox.fileName)
        put("deviceId", keybox.deviceId ?: JSONObject.NULL)
        put("contentSha256", keybox.contentSha256)
        put("chainFingerprint", keybox.chainFingerprint)
        put("source", keybox.source.name)
        put("status", keybox.status.name)
        put("duplicateOf", keybox.duplicateOf ?: JSONObject.NULL)
        put("parseError", keybox.parseError ?: JSONObject.NULL)
        put("deviceIdMatchesLeafSerial", keybox.deviceIdMatchesLeafSerial ?: JSONObject.NULL)

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
                    put("rootRecognized", key.rootRecognized)
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
        builder.append("| 密钥身份组 | ").append(report.groups.size).append(" |\n\n")

        val revoked = report.groups.count { it.status == RevocationStatus.REVOKED }
        val suspended = report.groups.count { it.status == RevocationStatus.SUSPENDED }
        val valid = report.groups.count { it.status == RevocationStatus.VALID }
        val unknown = report.groups.count { it.status == RevocationStatus.UNKNOWN }
        builder.append("### 吊销状态分布\n\n")
        builder.append("| 状态 | 组数 |\n| --- | --- |\n")
        builder.append("| 已吊销 / REVOKED | ").append(revoked).append(" |\n")
        builder.append("| 已暂停 / SUSPENDED | ").append(suspended).append(" |\n")
        builder.append("| 未吊销 / VALID | ").append(valid).append(" |\n")
        builder.append("| 未知 / UNKNOWN | ").append(unknown).append(" |\n\n")

        builder.append("### 吊销列表来源\n\n")
        builder.append("- 来源：`").append(report.revocation.source.name).append("`\n")
        builder.append("- 条目数：").append(report.revocation.entries.size).append("\n")
        if (report.revocation.fetchedAtMillis > 0) {
            builder.append("- 抓取时间：`").append(iso(report.revocation.fetchedAtMillis)).append("`\n")
        }
        report.revocation.expires?.let { builder.append("- 有效期至：`").append(it).append("`\n") }
        report.revocation.error?.let { builder.append("- 错误：").append(it).append("\n") }
        if (!report.revocation.isUsable) {
            builder.append("\n> ⚠️ 未获得吊销列表，所有密钥状态均为 UNKNOWN，**不代表密钥可用**。\n")
        }
        builder.append('\n')

        builder.append("## 密钥分组\n\n")
        if (report.groups.isEmpty()) {
            builder.append("_没有解析出任何 keybox。_\n")
            return builder.toString()
        }

        for ((position, group) in report.groups.withIndex()) {
            builder.append("### ").append(position + 1).append(". ").append(statusLabel(group.status))
            builder.append(" — `").append(group.keyId.take(32)).append("`\n\n")
            builder.append("- 密钥指纹（SHA-256）：`").append(group.keyId).append("`\n")
            builder.append("- 成员文件数：").append(group.memberCount).append("\n")
            builder.append("- 证书链变体：").append(group.chainVariants)
            if (group.chainVariants > 1) builder.append("（同一密钥存在多份不同证书链，可能已重新签发）")
            builder.append("\n")
            builder.append("- 设备 ID：")
            if (group.deviceIds.isEmpty()) {
                builder.append("_（未标注）_")
            } else {
                builder.append(group.deviceIds.joinToString("`, `", "`", "`"))
            }
            builder.append("\n")
            if (group.hasTamperedDeviceId) {
                builder.append("- ⚠️ 同一密钥下出现 ").append(group.deviceIds.size)
                builder.append(" 个不同 DeviceID，DeviceID 不参与匹配\n")
            }
            builder.append("- 匹配时忽略的字段：")
            builder.append(IGNORED_IDENTITY_FIELDS.joinToString("`, `", "`", "`"))
            builder.append("\n\n")

            builder.append("| 文件 | DeviceID | 吊销状态 | 链校验 | 链指纹 | 备注 |\n")
            builder.append("| --- | --- | --- | --- | --- | --- |\n")
            for (member in group.members) {
                builder.append("| `").append(member.fileName).append("` | ")
                builder.append(member.deviceId?.let { "`$it`" } ?: "-").append(" | ")
                builder.append(member.status.name).append(" | ")
                builder.append(chainLabel(member)).append(" | ")
                builder.append(member.chainFingerprint.take(16).ifEmpty { "-" }).append(" | ")
                builder.append(notes(member)).append(" |\n")
            }
            builder.append('\n')
        }

        builder.append("---\n\n")
        builder.append("> 说明：DeviceID 与 attestation 属性可被任意编辑，因此**不参与**密钥匹配；")
        builder.append("仅密钥材料（私钥推导出的公钥指纹）决定分组。状态为 UNKNOWN 表示未能完成吊销查询。\n")
        return builder.toString()
    }

    private fun statusLabel(status: RevocationStatus): String = when (status) {
        RevocationStatus.REVOKED -> "🔴 已吊销 REVOKED"
        RevocationStatus.SUSPENDED -> "🟠 已暂停 SUSPENDED"
        RevocationStatus.VALID -> "🟢 未吊销 VALID"
        RevocationStatus.UNKNOWN -> "⚪ 未知 UNKNOWN"
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
        member.deviceIdMatchesLeafSerial?.let { matches ->
            parts += if (matches) {
                "DeviceID 与叶子证书序列号一致"
            } else {
                "DeviceID 与叶子证书序列号不一致（该字段在签发后被修改过）"
            }
        }
        member.keys.mapNotNull { it.identityError }.distinct().forEach { parts += it }
        member.keys.mapNotNull { it.chainError }.distinct().forEach { parts += it }
        member.keys.mapNotNull { it.revocationReason }.distinct()
            .forEach { parts += "吊销原因：$it" }
        return parts.joinToString("；").ifBlank { "-" }
    }

    // ------------------------------------------------------------- filenames

    fun suggestedFileName(prefix: String, extension: String, nowMillis: Long): String {
        val format = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
        format.timeZone = TimeZone.getTimeZone("UTC")
        return "$prefix-${format.format(Date(nowMillis))}.$extension"
    }
}
