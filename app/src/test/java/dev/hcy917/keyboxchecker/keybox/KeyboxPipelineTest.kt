package dev.hcy917.keyboxchecker.keybox

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

/**
 * Walks the whole analysis path exactly the way [KeyboxRepository] does — raw
 * keybox XML in, a finished [ScanReport] out — with real DER parsing, real
 * signature verification and the real renderers in between.
 *
 * Every fixture is generated on the fly by [TestPki]; no real keybox, key or
 * certificate is part of this repository.
 */
class KeyboxPipelineTest {

    private val fixedNow = 1_700_000_000_000L

    private val rootPair = TestPki.ecKeyPair()
    private val leafPair = TestPki.ecKeyPair()
    private val leafSerial = BigInteger.valueOf(0x4D2L)

    private val leafDer = TestPki.certificate(
        subjectCommonName = "Keybox Leaf",
        subjectKey = leafPair.public,
        issuerCommonName = TestPki.GOOGLE_ROOT_CN,
        issuerKey = rootPair.private,
        serial = leafSerial,
    )
    private val rootDer = TestPki.selfSigned(rootPair, TestPki.GOOGLE_ROOT_CN, 1L)

    private val leafPem = Pem.encode("CERTIFICATE", leafDer)
    private val rootPem = Pem.encode("CERTIFICATE", rootDer)
    private val privateKeyPem = Pem.encode("PRIVATE KEY", leafPair.private.encoded)

    private val usableTable = RevocationSnapshot(
        entries = emptyMap(),
        source = RevocationSource.NETWORK,
        fetchedAtMillis = fixedNow,
    )

    private val revokedTable = RevocationSnapshot(
        entries = RevocationList.parseEntries(
            """{"entries":{"4D2":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}""",
        ),
        source = RevocationSource.NETWORK,
        fetchedAtMillis = fixedNow,
    )

    @Test
    fun `a synthetic keybox travels from xml to a revoked report entry`() {
        val xml = keyboxXml(deviceId = "DEV-1")
        val analyzed = scan(xml, "keybox.xml", revokedTable)

        // Identity is the public key recovered from the private key.
        assertTrue(analyzed.isConfirmed)
        assertEquals(Der.sha256(leafPair.public.encoded), analyzed.primaryKeyId)
        assertEquals(RevocationStatus.REVOKED, analyzed.status)

        val report = assemble(listOf(analyzed), revokedTable)
        assertEquals(1, report.groups.size)
        assertEquals(RevocationStatus.REVOKED, report.groups[0].status)
        assertEquals(Der.sha256(leafPair.public.encoded), report.groups[0].keyId)

        val json = JSONObject(ReportWriter.toJson(report))
        assertEquals("REVOKED", json.getJSONArray("groups").getJSONObject(0).getString("status"))

        val markdown = ReportWriter.toMarkdown(report)
        assertTrue(markdown.contains("🔴 已吊销 REVOKED"))
        assertTrue(markdown.contains("吊销原因：KEY_COMPROMISE"))
        assertTrue(markdown.contains("| 通过 |"))
    }

    @Test
    fun `the same key under two device ids lands in one group`() {
        val first = scan(keyboxXml(deviceId = "ORIGINAL-SERIAL"), "first.xml", RevocationSnapshot.EMPTY)
        val second = scan(keyboxXml(deviceId = "CLONED-SERIAL"), "second.xml", RevocationSnapshot.EMPTY)

        val report = assemble(listOf(first, second), RevocationSnapshot.EMPTY)

        assertEquals(1, report.groups.size)
        val group = report.groups[0]
        assertEquals(2, group.memberCount)
        assertTrue(group.hasTamperedDeviceId)
        assertEquals(listOf("CLONED-SERIAL", "ORIGINAL-SERIAL"), group.deviceIds.sorted())
        // Identical chains, so this is a clone rather than a re-issue.
        assertEquals(1, group.chainVariants)
        assertTrue(group.identicalChains)
        assertFalse(report.keys.any { it.duplicateOf != null })
    }

    @Test
    fun `a namespaced document and a multi keybox document behave identically`() {
        val namespaced = scan(
            keyboxXml(deviceId = "DEV-N", namespaced = true),
            "namespaced.xml",
            RevocationSnapshot.EMPTY,
        )
        assertEquals(Der.sha256(leafPair.public.encoded), namespaced.primaryKeyId)

        val multi = scan(
            TestPki.multiKeyboxXml(
                deviceIds = listOf("A", "B"),
                algorithm = "ecdsa",
                privateKeyPem = privateKeyPem,
                chainPems = listOf(leafPem, rootPem),
            ),
            "multi.xml",
            RevocationSnapshot.EMPTY,
        )
        assertEquals("A | B", multi.deviceId)
        assertEquals(2, multi.keys.size)
        assertTrue(multi.isConfirmed)
    }

    @Test
    fun `a file that is not a keybox only affects the statistics`() {
        val strings = "<?xml version=\"1.0\" encoding=\"utf-8\"?><resources><string name=\"app_name\">x</string></resources>"
        val outcome = KeyboxParser.parse(strings, "strings.xml")

        assertTrue(outcome is ParseOutcome.NotKeybox)
        assertFalse(ReportWriter.toJson(assemble(emptyList(), usableTable, notKeybox = 1)).isEmpty())

        val report = assemble(listOf(scan(keyboxXml(deviceId = "DEV-1"), "keybox.xml", usableTable)), usableTable, notKeybox = 1)
        assertEquals(1L, report.stats.confirmedKeyboxes.toLong())
        assertEquals(1L, report.stats.notKeybox.toLong())
        assertEquals(1, report.groups.size)
    }

    @Test
    fun `an unreadable private key still yields a comparable identity`() {
        val xml = TestPki.keyboxXml(
            deviceId = "DEV-BROKEN",
            algorithm = "ecdsa",
            privateKeyPem = Pem.encode("PRIVATE KEY", byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)),
            chainPems = listOf(leafPem, rootPem),
        )
        val analyzed = scan(xml, "broken-key.xml", usableTable)
        val key = analyzed.keys[0]

        assertEquals(IdentitySource.LEAF_CERTIFICATE, key.identitySource)
        // Degrading the identity source must not change which key it identifies.
        assertEquals(Der.sha256(leafPair.public.encoded), key.keyId)
        assertTrue(analyzed.isConfirmed)

        // The reason for the fallback is surfaced, never silently swallowed.
        val reason = key.identityError
        assertNotNull(reason)
        assertTrue(ReportWriter.toMarkdown(assemble(listOf(analyzed), usableTable)).contains(reason!!))
    }

    @Test
    fun `a truncated document is rejected before analysis`() {
        val truncated = keyboxXml(deviceId = "DEV-1").substringBefore("<Key ")

        assertTrue(KeyboxParser.parse(truncated, "truncated.xml") is ParseOutcome.NotKeybox)
    }

    // ------------------------------------------------------------------ utils

    private fun keyboxXml(deviceId: String?, namespaced: Boolean = false): String = TestPki.keyboxXml(
        deviceId = deviceId,
        algorithm = "ecdsa",
        privateKeyPem = privateKeyPem,
        chainPems = listOf(leafPem, rootPem),
        namespaced = namespaced,
    )

    private fun scan(xml: String, name: String, table: RevocationSnapshot): AnalyzedKeybox {
        val outcome = KeyboxParser.parse(xml, name)
        assertTrue("expected a keybox but got $outcome", outcome is ParseOutcome.Ok)
        val ok = outcome as ParseOutcome.Ok
        return KeyboxAnalyzer(table) { fixedNow }
            .analyze(name, Der.sha256(xml.toByteArray()), ok.keybox, KeyboxSource.LOCAL_PATH)
    }

    private fun assemble(
        analyzed: List<AnalyzedKeybox>,
        table: RevocationSnapshot,
        notKeybox: Int = 0,
    ): ScanReport = ReportWriter.assemble(
        inputDescription = "test",
        analyzed = analyzed,
        revocation = table,
        filesScanned = analyzed.size + notKeybox,
        xmlFiles = analyzed.size + notKeybox,
        notKeybox = notKeybox,
        unreadable = 0,
        nowMillis = fixedNow,
    )
}
