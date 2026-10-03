package dev.hcy917.keyboxchecker.keybox

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The report is the user-visible deliverable of a scan, so its two renderings
 * (the machine readable `classification.json` and the human readable
 * `report.md`) are asserted here rather than only being exercised through CI.
 *
 * The last test is a privacy guard: the report is written to disk and often
 * shared, so it must never contain a credential.
 */
class ReportWriterTest {

    private val fixedNow = 1_700_000_000_000L

    private val usable = RevocationSnapshot(
        entries = mapOf(
            "4D2" to RevocationEntry("4D2", RevocationStatus.REVOKED, "KEY_COMPROMISE"),
        ),
        source = RevocationSource.NETWORK,
        fetchedAtMillis = fixedNow,
        expires = "2026-01-01T00:00:00Z",
    )

    // -------------------------------------------------------------- formatting

    @Test
    fun `iso renders UTC timestamps`() {
        assertEquals("1970-01-01T00:00:00Z", ReportWriter.iso(0L))
        assertEquals("2023-11-14T22:13:20Z", ReportWriter.iso(fixedNow))
    }

    @Test
    fun `suggested file names embed prefix stamp and extension`() {
        assertEquals(
            "classification-19700101-000000.json",
            ReportWriter.suggestedFileName("classification", "json", 0L),
        )
        assertEquals(
            "report-20231114-221320.md",
            ReportWriter.suggestedFileName("report", "md", fixedNow),
        )
    }

    // ---------------------------------------------------------------- assemble

    @Test
    fun `assemble keeps only confirmed keyboxes and counts the stats`() {
        val report = ReportWriter.assemble(
            inputDescription = "SAF:content://tree/keyboxes",
            analyzed = listOf(
                analyzed("good.xml", keyId = "AAAA"),
                // A parse failure never reaches the result list.
                analyzed("broken.xml", keyId = "BBBB", parseError = "XML 解析失败"),
            ),
            revocation = usable,
            filesScanned = 7,
            xmlFiles = 3,
            notKeybox = 1,
            unreadable = 2,
            nowMillis = fixedNow,
        )

        assertEquals(1, report.keys.size)
        assertEquals("good.xml", report.keys[0].fileName)
        assertEquals(7L, report.stats.filesScanned.toLong())
        assertEquals(3L, report.stats.xmlFiles.toLong())
        assertEquals(2L, report.stats.unreadable.toLong())
        assertEquals(1L, report.stats.notKeybox.toLong())
        assertEquals("2023-11-14T22:13:20Z", report.renderedAtIso)
    }

    @Test
    fun `assemble sorts the most severe keybox first`() {
        val report = ReportWriter.assemble(
            inputDescription = "dir",
            analyzed = listOf(
                analyzed("valid.xml", keyId = "A", status = RevocationStatus.VALID),
                analyzed("unknown.xml", keyId = "B", status = RevocationStatus.UNKNOWN),
                analyzed("suspended.xml", keyId = "C", status = RevocationStatus.SUSPENDED),
                analyzed("revoked.xml", keyId = "D", status = RevocationStatus.REVOKED),
            ),
            revocation = usable,
            filesScanned = 4,
            xmlFiles = 4,
            notKeybox = 0,
            unreadable = 0,
            nowMillis = fixedNow,
        )

        assertEquals(
            // Severity ranks REVOKED > SUSPENDED > UNKNOWN > VALID, so an
            // undetermined keybox is surfaced above a verified-clean one.
            listOf("revoked.xml", "suspended.xml", "unknown.xml", "valid.xml"),
            report.keys.map { it.fileName },
        )
    }

    @Test
    fun `assemble lists every file and reports the keys they share`() {
        val report = ReportWriter.assemble(
            inputDescription = "dir",
            analyzed = listOf(
                analyzed("a.xml", keyId = "SAME", deviceId = "ORIGINAL", status = RevocationStatus.REVOKED),
                analyzed("b.xml", keyId = "SAME", deviceId = "CLONED", status = RevocationStatus.REVOKED),
                analyzed("c.xml", keyId = "OTHER", deviceId = "OTHER-DEV"),
            ),
            revocation = usable,
            filesScanned = 3,
            xmlFiles = 3,
            notKeybox = 0,
            unreadable = 0,
            nowMillis = fixedNow,
        )

        // Three files, three entries: an edited DeviceID does not merge them.
        assertEquals(3, report.keys.size)
        assertEquals(
            listOf("a.xml", "b.xml", "c.xml"),
            report.keys.map { it.fileName }.sorted(),
        )
        assertEquals("CLONED", report.keys.first { it.fileName == "b.xml" }.deviceId)
        assertEquals(1, report.repeatedKeys.size)
        assertEquals("SAME", report.repeatedKeys[0].keyId)
        assertEquals(listOf("a.xml", "b.xml"), report.repeatedKeys[0].fileNames)
    }

    // -------------------------------------------------------------------- JSON

    @Test
    fun `json is parseable and carries the schema the app promises`() {
        val report = report()
        // Parsing back proves the writer emitted well-formed JSON.
        val root = JSONObject(ReportWriter.toJson(report))

        assertEquals("KeyboxsCheck", root.getString("tool"))
        assertEquals("dir + Telegram:my_channel", root.getString("input"))
        assertEquals("2023-11-14T22:13:20Z", root.getString("generatedAt"))
        assertEquals(fixedNow, root.getLong("generatedAtMillis"))

        val ignored = root.getJSONArray("ignoredIdentityFields")
        assertTrue((0 until ignored.length()).any { ignored.getString(it) == "DeviceID" })

        val revocation = root.getJSONObject("revocation")
        assertEquals("NETWORK", revocation.getString("source"))
        assertTrue(revocation.getBoolean("usable"))
        assertEquals(1, revocation.getInt("entryCount"))

        val stats = root.getJSONObject("stats")
        assertEquals(4, stats.getInt("filesScanned"))

        val certificates = root.getJSONArray("certificates")
        assertEquals(2, certificates.length())
        val certificate = certificates.getJSONObject(0)
        assertEquals("a.xml", certificate.getString("fileName"))
        assertEquals("SAME", certificate.getString("keyId"))
        assertEquals("REVOKED", certificate.getString("status"))
        assertEquals("ORIGINAL", certificate.getString("deviceId"))
        assertEquals("LOCAL_PATH", certificate.getString("source"))

        val repeated = root.getJSONArray("repeatedKeys").getJSONObject(0)
        assertEquals("SAME", repeated.getString("keyId"))
        assertEquals(2, repeated.getInt("count"))

        val key = certificate.getJSONArray("keys").getJSONObject(0)
        assertEquals("SAME", key.getString("keyId"))
        assertEquals("PRIVATE_KEY", key.getString("identitySource"))
        assertEquals("REVOKED", key.getString("status"))
        assertEquals(true, key.getBoolean("chainValid"))
    }

    @Test
    fun `json uses null for values a scan could not determine`() {
        val report = ReportWriter.assemble(
            inputDescription = "dir",
            analyzed = listOf(
                analyzed(
                    "unknown.xml",
                    keyId = "U",
                    deviceId = null,
                    status = RevocationStatus.UNKNOWN,
                    chainValid = null,
                    identityError = "私钥无法推导公钥",
                ),
            ),
            revocation = RevocationSnapshot.EMPTY,
            filesScanned = 1,
            xmlFiles = 1,
            notKeybox = 0,
            unreadable = 0,
            nowMillis = fixedNow,
        )
        val root = JSONObject(ReportWriter.toJson(report))

        assertFalse(root.getJSONObject("revocation").getBoolean("usable"))
        assertEquals("NONE", root.getJSONObject("revocation").getString("source"))
        assertTrue(root.getJSONObject("revocation").isNull("expires"))

        val certificate = root.getJSONArray("certificates").getJSONObject(0)
        assertTrue(certificate.isNull("deviceId"))
        assertTrue(certificate.isNull("duplicateOf"))
        assertTrue(certificate.isNull("parseError"))

        val key = certificate.getJSONArray("keys").getJSONObject(0)
        assertTrue(key.isNull("chainValid"))
        assertEquals("私钥无法推导公钥", key.getString("identityError"))
    }

    @Test
    fun `the report never carries a bot token`() {
        val report = report()
        // `describeInput` intentionally names the channel only; a token must not leak.
        assertFalse(ReportWriter.toJson(report).lowercase().contains("token"))
        assertFalse(ReportWriter.toMarkdown(report).lowercase().contains("token"))
    }

    @Test
    fun `json serializes certificate metadata`() {
        val report = ReportWriter.assemble(
            inputDescription = "dir",
            analyzed = listOf(
                analyzed(
                    "cert.xml",
                    keyId = "C",
                    certificates = listOf(
                        CertificateInfo(
                            index = 0,
                            subject = "CN=Keybox Leaf",
                            issuer = "CN=${"Google Hardware Attestation Root"}",
                            serialHex = "4D2",
                            notBefore = TestPki.NOT_BEFORE,
                            notAfter = TestPki.NOT_AFTER,
                            isCa = false,
                        ),
                    ),
                ),
            ),
            revocation = usable,
            filesScanned = 1,
            xmlFiles = 1,
            notKeybox = 0,
            unreadable = 0,
            nowMillis = fixedNow,
        )

        val certificate = JSONObject(ReportWriter.toJson(report))
            .getJSONArray("certificates").getJSONObject(0)
            .getJSONArray("keys").getJSONObject(0)
            .getJSONArray("certificates").getJSONObject(0)

        assertEquals(0, certificate.getInt("index"))
        assertEquals("4D2", certificate.getString("serialHex"))
        assertEquals(false, certificate.getBoolean("isCa"))
        assertEquals("2020-09-13T12:26:40Z", certificate.getString("notBefore"))
        assertEquals("2033-05-18T03:33:20Z", certificate.getString("notAfter"))
    }

    // ---------------------------------------------------------------- Markdown

    @Test
    fun `markdown renders the summary and every group`() {
        val markdown = ReportWriter.toMarkdown(report())

        assertTrue(markdown.startsWith("# KeyboxsCheck 检测报告"))
        assertTrue(markdown.contains("| 确认为 keybox | 2 |"))
        assertTrue(markdown.contains("| keybox 文件 | 2 |"))
        // The full group fingerprint is printed, not the truncated heading.
        assertTrue(markdown.contains("`SAME`"))
        assertTrue(markdown.contains("🔴 已吊销 REVOKED"))
        assertTrue(markdown.contains("`a.xml`"))
        assertTrue(markdown.contains("`b.xml`"))
        assertTrue(markdown.contains("因此**不参与**密钥匹配"))
        assertTrue(markdown.contains("匹配时忽略的字段"))
    }

    @Test
    fun `markdown warns when the revocation table could not be fetched`() {
        val report = ReportWriter.assemble(
            inputDescription = "dir",
            analyzed = listOf(analyzed("a.xml", keyId = "A", status = RevocationStatus.UNKNOWN)),
            revocation = RevocationSnapshot.EMPTY,
            filesScanned = 1,
            xmlFiles = 1,
            notKeybox = 0,
            unreadable = 0,
            nowMillis = fixedNow,
        )
        val markdown = ReportWriter.toMarkdown(report)

        assertTrue(markdown.contains("不代表密钥可用"))
        assertTrue(markdown.contains("⚪ 未知 UNKNOWN"))
    }

    @Test
    fun `markdown reports an empty scan explicitly`() {
        val report = ReportWriter.assemble(
            inputDescription = "empty-dir",
            analyzed = emptyList(),
            revocation = usable,
            filesScanned = 0,
            xmlFiles = 0,
            notKeybox = 0,
            unreadable = 0,
            nowMillis = fixedNow,
        )
        val markdown = ReportWriter.toMarkdown(report)

        assertTrue(markdown.contains("_没有解析出任何 keybox。_"))
        assertTrue(report.keys.isEmpty())
    }

    @Test
    fun `markdown notes duplicates and broken chains`() {
        val report = ReportWriter.assemble(
            inputDescription = "dir",
            analyzed = listOf(
                analyzed("first.xml", keyId = "D", contentSha256 = "SHA-SAME"),
                analyzed("second.xml", keyId = "D", contentSha256 = "SHA-SAME", chainValid = false),
            ),
            revocation = usable,
            filesScanned = 2,
            xmlFiles = 2,
            notKeybox = 0,
            unreadable = 0,
            nowMillis = fixedNow,
        )
        val markdown = ReportWriter.toMarkdown(report)

        assertTrue(report.stats.duplicates == 1)
        assertTrue(markdown.contains("内容重复于 `first.xml`"))
        assertTrue(markdown.contains("证书链：失效"))
    }

    // ------------------------------------------------------------------- utils

    private fun report(): ScanReport = ReportWriter.assemble(
        inputDescription = "dir + Telegram:my_channel",
        analyzed = listOf(
            analyzed("a.xml", keyId = "SAME", deviceId = "ORIGINAL", status = RevocationStatus.REVOKED),
            analyzed("b.xml", keyId = "SAME", deviceId = "CLONED", status = RevocationStatus.REVOKED),
        ),
        revocation = usable,
        filesScanned = 4,
        xmlFiles = 3,
        notKeybox = 1,
        unreadable = 0,
        nowMillis = fixedNow,
    )

    private fun analyzed(
        fileName: String,
        keyId: String,
        deviceId: String? = null,
        status: RevocationStatus = RevocationStatus.VALID,
        chainValid: Boolean? = true,
        chainFingerprint: String = "CHAIN-$keyId",
        contentSha256: String = "SHA-$fileName",
        certificates: List<CertificateInfo> = emptyList(),
        identityError: String? = null,
        parseError: String? = null,
    ): AnalyzedKeybox = AnalyzedKeybox(
        fileName = fileName,
        contentSha256 = contentSha256,
        deviceId = deviceId,
        keys = if (parseError != null) {
            emptyList()
        } else {
            listOf(
                AnalyzedKey(
                    index = 0,
                    algorithm = "ecdsa",
                    keyId = keyId,
                    identitySource = IdentitySource.PRIVATE_KEY,
                    identityError = identityError,
                    status = status,
                    matchedSerial = null,
                    revocationReason = if (status == RevocationStatus.REVOKED) "KEY_COMPROMISE" else null,
                    chainValid = chainValid,
                    chainError = null,
                    certificates = certificates,
                ),
            )
        },
        chainFingerprint = chainFingerprint,
        source = KeyboxSource.LOCAL_PATH,
        parseError = parseError,
        duplicateOf = null,
    )
}
