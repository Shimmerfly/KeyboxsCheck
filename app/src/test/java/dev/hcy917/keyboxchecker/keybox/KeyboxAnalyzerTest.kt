package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

/**
 * End-to-end behaviour of the analysis layer on synthetic attestation chains:
 * identity comes from the key, revocation from the table, and a check that could
 * not be performed is never reported as clean.
 */
class KeyboxAnalyzerTest {

    private val fixedNow = 1_700_000_000_000L

    private val rootPair = TestPki.ecKeyPair()
    private val leafPair = TestPki.ecKeyPair()
    private val leafSerial = BigInteger.valueOf(0x4D2L)
    private val rootSerial = BigInteger.valueOf(1L)

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

    @Test
    fun `the private key and the leaf certificate agree on one identity`() {
        val analyzed = analyze(keybox())

        assertTrue(analyzed.isConfirmed)
        assertEquals("DEV-1", analyzed.deviceId)
        assertEquals(1, analyzed.keys.size)
        assertEquals(IdentitySource.PRIVATE_KEY, analyzed.keys[0].identitySource)
        assertEquals(Der.sha256(leafPair.public.encoded), analyzed.keys[0].keyId)
        assertEquals(RevocationStatus.VALID, analyzed.keys[0].status)
        assertEquals(Boolean.TRUE, analyzed.keys[0].chainValid)
        assertNull(analyzed.keys[0].chainError)
        assertEquals(2, analyzed.keys[0].certificates.size)
        assertTrue(analyzed.chainFingerprint.isNotEmpty())
    }

    @Test
    fun `a revoked leaf serial is reported as revoked`() {
        val table = table("""{"entries":{"4D2":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}""")
        val key = analyze(keybox(), table).keys[0]

        assertEquals(RevocationStatus.REVOKED, key.status)
        assertTrue(key.isRevoked)
        assertEquals("KEY_COMPROMISE", key.revocationReason)
        assertNotNull(key.matchedSerial)
    }

    @Test
    fun `the most severe status across the chain wins`() {
        val table = table(
            """{"entries":{"1":{"status":"REVOKED"},"4D2":{"status":"SUSPENDED"}}}""",
        )
        val key = analyze(keybox(), table).keys[0]
        assertEquals(RevocationStatus.REVOKED, key.status)
        assertEquals(RevocationStatus.REVOKED, analyze(keybox(), table).status)
    }

    @Test
    fun `an unavailable table yields unknown never valid`() {
        val key = analyze(keybox(), RevocationSnapshot.EMPTY).keys[0]
        assertEquals(RevocationStatus.UNKNOWN, key.status)
        assertFalse(key.isRevoked)
        assertEquals(Boolean.TRUE, key.chainValid)
    }

    @Test
    fun `a chain without certificates is unknown`() {
        val key = analyze(keybox(chain = emptyList()), RevocationSnapshot.EMPTY).keys[0]
        assertEquals(RevocationStatus.UNKNOWN, key.status)
        assertNull(key.chainValid)
        assertNotNull(key.chainError)
    }

    @Test
    fun `an unusable private key falls back to the leaf certificate`() {
        val broken = Pem.encode("PRIVATE KEY", byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8))
        val key = analyze(keybox(keyPem = broken)).keys[0]

        assertEquals(IdentitySource.LEAF_CERTIFICATE, key.identitySource)
        assertEquals(Der.sha256(leafPair.public.encoded), key.keyId)
        assertNotNull(key.identityError)
    }

    @Test
    fun `no key material at all degrades to the raw byte hash`() {
        val key = analyze(keybox(keyPem = null, chain = emptyList())).keys[0]
        assertEquals(IdentitySource.RAW_PEM, key.identitySource)
        assertEquals(Der.sha256(ByteArray(0)), key.keyId)
        assertNotNull(key.identityError)
    }

    @Test
    fun `a broken chain is reported as invalid`() {
        val strangerPair = TestPki.ecKeyPair()
        val strangerPem = Pem.encode(
            "CERTIFICATE",
            TestPki.selfSigned(strangerPair, "Totally Unrelated Root", 0x99L),
        )
        val key = analyze(keybox(chain = listOf(leafPem, strangerPem))).keys[0]

        assertEquals(Boolean.FALSE, key.chainValid)
        assertNotNull(key.chainError)
    }

    @Test
    fun `a root-first chain is reordered before verification`() {
        val key = analyze(keybox(chain = listOf(rootPem, leafPem))).keys[0]

        assertEquals(Boolean.TRUE, key.chainValid)
        assertTrue(key.certificates[0].subject.contains("Keybox Leaf"))
        assertTrue(key.certificates[1].subject.contains(TestPki.GOOGLE_ROOT_CN))
    }

    @Test
    fun `certificate metadata is carried into the report`() {
        val info = analyze(keybox()).keys[0].certificates[0]
        assertEquals(0, info.index)
        assertEquals("4D2", info.serialHex)
        assertEquals(TestPki.NOT_BEFORE, info.notBefore)
        assertEquals(TestPki.NOT_AFTER, info.notAfter)
        assertTrue(info.issuer.contains(TestPki.GOOGLE_ROOT_CN))
        assertFalse(info.isExpired(fixedNow))
    }

    @Test
    fun `a failed parse is not confirmed`() {
        val analyzer = KeyboxAnalyzer(usableTable) { fixedNow }
        val failure = analyzer.failure("broken.xml", "SHA", "XML 解析失败", KeyboxSource.LOCAL_PATH)

        assertFalse(failure.isConfirmed)
        assertNull(failure.primaryKeyId)
        assertEquals(RevocationStatus.UNKNOWN, failure.status)
        assertEquals("XML 解析失败", failure.parseError)
    }

    // ------------------------------------------------------------------ utils

    private fun analyze(
        keybox: Keybox,
        revocation: RevocationSnapshot = usableTable,
    ): AnalyzedKeybox = KeyboxAnalyzer(revocation) { fixedNow }
        .analyze(keybox.sourceName ?: "kb.xml", "SHA-${keybox.sourceName}", keybox, KeyboxSource.LOCAL_PATH)

    private fun table(json: String): RevocationSnapshot = RevocationSnapshot(
        entries = RevocationList.parseEntries(json),
        source = RevocationSource.NETWORK,
        fetchedAtMillis = fixedNow,
    )

    private fun keybox(
        keyPem: String? = privateKeyPem,
        chain: List<String> = listOf(leafPem, rootPem),
        deviceId: String? = "DEV-1",
    ): Keybox = Keybox(
        deviceId = deviceId,
        keys = listOf(KeyboxKey(index = 0, algorithm = "ecdsa", privateKeyPem = keyPem, chainPem = chain)),
        sourceName = "kb.xml",
    )
}
