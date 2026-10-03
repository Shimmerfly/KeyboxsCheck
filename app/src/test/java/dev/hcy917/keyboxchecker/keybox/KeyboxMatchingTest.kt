package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

/**
 * The matching rules that make the checker work against real data.
 *
 * Every case here was derived from a real keybox and from the published status
 * list, both of which are less tidy than the format documentation suggests:
 * the list mixes decimal and hex serials, Google's roots carry no common name,
 * and `DeviceID` is an editable attribute.
 */
class KeyboxMatchingTest {

    private val fixedNow = 1_700_000_000_000L

    private val rootPair = TestPki.ecKeyPair()
    private val leafPair = TestPki.ecKeyPair()
    private val leafSerial = BigInteger.valueOf(0x4D2L)
    private val rootSerial = BigInteger.valueOf(1L)

    // ------------------------------------------------------- name decoding

    @Test
    fun `der encoded attributes are decoded into readable form`() {
        // Exactly what X500Principal.getName() prints for Google's keymaster root.
        val subject = "2.5.4.5=#131066393230303965383533623662303435,2.5.4.12=#0c03544545"

        assertEquals("serialNumber=f92009e853b6b045, title=TEE", CertificateNames.readable(subject))
    }

    @Test
    fun `plain common names survive unchanged`() {
        assertEquals("CN=Keybox Leaf", CertificateNames.readable("CN=Keybox Leaf"))
    }

    @Test
    fun `quoted values keep their commas`() {
        assertEquals("CN=Keybox, Inc.", CertificateNames.readable("2.5.4.3=\"Keybox, Inc.\""))
    }

    @Test
    fun `attributes expose oid short name and value`() {
        val attributes = CertificateNames.attributes("2.5.4.5=#131066393230303965383533623662303435,2.5.4.3=Leaf")

        assertEquals(2, attributes.size)
        assertEquals("2.5.4.5", attributes[0].oid)
        assertEquals("serialNumber", attributes[0].name)
        assertEquals("f92009e853b6b045", attributes[0].value)
        assertEquals("CN", attributes[1].name)
        assertEquals("Leaf", attributes[1].value)
    }

    // ------------------------------------------------------ serial spellings

    @Test
    fun `decimal serials from the published list are matched`() {
        // 979 of the 1759 published entries are plain decimal, not hex.
        val serial = BigInteger("224403031710863989")
        val snapshot = table(
            """{"entries":{"224403031710863989":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}""",
        )

        assertEquals(RevocationStatus.REVOKED, snapshot.lookup(serial)?.status)
    }

    @Test
    fun `hex serials still match after the decimal support was added`() {
        val snapshot = table(
            """{"entries":{"c35747a084470c3135aeefe2b8d40cd6":{"status":"REVOKED"}}}""",
        )
        val serial = BigInteger("c35747a084470c3135aeefe2b8d40cd6", 16)

        assertEquals(RevocationStatus.REVOKED, snapshot.lookup(serial)?.status)
    }

    @Test
    fun `entries are indexed under the trimmed spelling too`() {
        val snapshot = table("""{"entries":{"0000ABCD":{"status":"SUSPENDED"}}}""")

        assertEquals(RevocationStatus.SUSPENDED, snapshot.lookup(BigInteger("ABCD", 16))?.status)
    }

    @Test
    fun `decimal only applies to values made of digits`() {
        assertEquals("224403031710863989", RevocationKeys.decimal("000224403031710863989"))
        assertNull(RevocationKeys.decimal("c35747a084470c3135aeefe2b8d40cd6"))
    }

    @Test
    fun `serials survive decoration and leading zeros`() {
        assertEquals("ABCD", RevocationKeys.normalize("0x00:00:ab:cd"))
        assertEquals("0", RevocationKeys.normalize("0000"))
    }

    @Test
    fun `the reported entry count is the published count not the index size`() {
        // One published serial, indexed under several spellings.
        val snapshot = table("""{"entries":{"0000ABCD":{"status":"REVOKED"}}}""")

        assertTrue(snapshot.entries.size > 1)
        assertEquals(1, snapshot.entryCount)
    }

    // ---------------------------------------------------- end-to-end matching

    @Test
    fun `a decimal-published revoked serial is reported through the whole analyzer`() {
        // The leaf really is issued with this serial, and the list really does
        // publish it in decimal.
        val decimalSerial = BigInteger("224403031710863989")
        val leafDer = TestPki.certificate(
            subjectCommonName = "Keybox Leaf",
            subjectKey = leafPair.public,
            issuerCommonName = TestPki.GOOGLE_ROOT_CN,
            issuerKey = rootPair.private,
            serial = decimalSerial,
        )
        val table = table(
            """{"entries":{"224403031710863989":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}""",
        )
        val analyzed = analyze(
            keybox(
                chain = listOf(Pem.encode("CERTIFICATE", leafDer), Pem.encode("CERTIFICATE", rootDer())),
            ),
            table,
        )

        assertEquals(RevocationStatus.REVOKED, analyzed.keys[0].status)
        assertEquals("KEY_COMPROMISE", analyzed.keys[0].revocationReason)
        assertEquals(RevocationStatus.REVOKED, analyzed.status)
    }

    // -------------------------------------------------------- root recognition

    @Test
    fun `a root identified by serial number is recognised`() {
        // Google's roots have no CN; only serialNumber=f92009e853b6b045.
        val rootName = TestPki.derName("2.5.4.5" to "f92009e853b6b045")
        val root = TestPki.certificate(
            subjectCommonName = "",
            subjectKey = rootPair.public,
            issuerCommonName = "",
            issuerKey = rootPair.private,
            serial = rootSerial,
            subjectDer = rootName,
            issuerDer = rootName,
        )
        val leaf = TestPki.certificate(
            subjectCommonName = "Keybox Leaf",
            subjectKey = leafPair.public,
            issuerCommonName = "",
            issuerKey = rootPair.private,
            serial = leafSerial,
            issuerDer = rootName,
        )
        val key = analyze(
            keybox(
                chain = listOf(
                    Pem.encode("CERTIFICATE", leaf),
                    Pem.encode("CERTIFICATE", root),
                ),
            ),
        ).keys[0]

        assertEquals(java.lang.Boolean.TRUE, key.chainValid)
        assertTrue(key.rootRecognized)
        assertNotNull(key.chainRoot)
        assertTrue(key.chainRoot!!.contains("f92009e853b6b045"))
        assertTrue(key.certificates[0].subject.contains("Keybox Leaf"))
    }

    @Test
    fun `a self signed root nobody vouches for is unknown not valid`() {
        // A locally generated chain verifies perfectly; that proves nothing.
        val localPair = TestPki.ecKeyPair()
        val localRoot = TestPki.selfSigned(localPair, "Locally Generated Root", 0x77L)
        val leaf = TestPki.certificate(
            subjectCommonName = "Keybox Leaf",
            subjectKey = leafPair.public,
            issuerCommonName = "Locally Generated Root",
            issuerKey = localPair.private,
            serial = leafSerial,
        )
        val key = analyze(
            keybox(
                chain = listOf(
                    Pem.encode("CERTIFICATE", leaf),
                    Pem.encode("CERTIFICATE", localRoot),
                ),
            ),
        ).keys[0]

        assertNull(key.chainValid)
        assertFalse(key.rootRecognized)
        assertNotNull(key.chainError)
        assertTrue(key.chainError!!.contains("自签名"))
    }

    // -------------------------------------------------------- device id check

    @Test
    fun `a device id that equals the leaf serial is flagged as consistent`() {
        val analyzed = analyze(keybox(deviceId = "4D2"))

        assertEquals(java.lang.Boolean.TRUE, analyzed.deviceIdMatchesLeafSerial)
    }

    @Test
    fun `an edited device id is detected`() {
        val analyzed = analyze(keybox(deviceId = "DEADBEEF"))

        assertEquals(java.lang.Boolean.FALSE, analyzed.deviceIdMatchesLeafSerial)
    }

    @Test
    fun `device id comparison is skipped when nothing can be compared`() {
        assertNull(analyze(keybox(deviceId = null)).deviceIdMatchesLeafSerial)
        assertNull(
            analyze(keybox(deviceId = "4D2", chain = emptyList())).deviceIdMatchesLeafSerial,
        )
    }

    // ------------------------------------------------------------------ utils

    private fun rootDer(): ByteArray = TestPki.selfSigned(rootPair, TestPki.GOOGLE_ROOT_CN, 1L)

    private fun analyze(
        keybox: Keybox,
        revocation: RevocationSnapshot = table("""{"entries":{}}"""),
    ): AnalyzedKeybox = KeyboxAnalyzer(revocation) { fixedNow }
        .analyze(keybox.sourceName ?: "kb.xml", "SHA-${keybox.sourceName}", keybox, KeyboxSource.LOCAL_PATH)

    private fun table(json: String): RevocationSnapshot = RevocationSnapshot(
        entries = RevocationList.parseEntries(json),
        source = RevocationSource.NETWORK,
        fetchedAtMillis = fixedNow,
    )

    private fun keybox(
        chain: List<String> = listOf(leafPem(), rootPem()),
        deviceId: String? = "4D2",
    ): Keybox = Keybox(
        deviceId = deviceId,
        keys = listOf(
            KeyboxKey(
                index = 0,
                algorithm = "ecdsa",
                privateKeyPem = Pem.encode("PRIVATE KEY", leafPair.private.encoded),
                chainPem = chain,
            ),
        ),
        sourceName = "kb.xml",
    )

    private fun leafPem(): String = Pem.encode(
        "CERTIFICATE",
        TestPki.certificate(
            subjectCommonName = "Keybox Leaf",
            subjectKey = leafPair.public,
            issuerCommonName = TestPki.GOOGLE_ROOT_CN,
            issuerKey = rootPair.private,
            serial = leafSerial,
        ),
    )

    private fun rootPem(): String = Pem.encode("CERTIFICATE", rootDer())
}
