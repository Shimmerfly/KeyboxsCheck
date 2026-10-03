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
    fun `every pinned root decodes and maps back to its status`() {
        // The constants are generated by script from the two reference projects,
        // so each one is re-decoded here and checked against the pinned status.
        val pinned = RootKeys.pinnedKeys()

        assertEquals(7, pinned.size)
        pinned.forEach { (status, encoded) ->
            assertEquals(status, RootKeys.identify(publicKeyOf(encoded)))
        }
        assertNull(RootKeys.encoded(null))
        assertEquals(RootStatus.NULL, RootKeys.identify(null as java.security.PublicKey?))
    }

    @Test
    fun `the pinned roots have the shapes the reference projects describe`() {
        val byStatus = RootKeys.pinnedKeys().groupBy({ it.first }, { publicKeyOf(it.second) })

        val google = byStatus.getValue(RootStatus.GOOGLE).single() as java.security.interfaces.RSAPublicKey
        assertEquals(4096, google.modulus.bitLength())

        val rkp = byStatus.getValue(RootStatus.GOOGLE_RKP).single() as java.security.interfaces.ECPublicKey
        assertEquals(384, rkp.params.curve.field.fieldSize)

        assertEquals(2, byStatus.getValue(RootStatus.AOSP).size)
        assertEquals(3, byStatus.getValue(RootStatus.KNOX).size)
    }

    @Test
    fun `an unrelated key is not a known root`() {
        assertEquals(RootStatus.UNKNOWN, RootKeys.identify(TestPki.ecKeyPair().public))
        assertEquals(RootStatus.UNKNOWN, RootKeys.identify(TestPki.rsaKeyPair().public))
    }

    @Test
    fun `the chain root is rendered readably even when it carries no CN`() {
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
        assertNotNull(key.chainRoot)
        assertTrue(key.chainRoot!!.contains("f92009e853b6b045"))
        assertTrue(key.certificates[0].subject.contains("Keybox Leaf"))
    }

    @Test
    fun `a self signed root nobody vouches for yields an unknown root`() {
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

        // The links check out, so the chain is internally consistent, but no
        // pinned root vouches for it — which is what rootStatus reports.
        assertEquals(java.lang.Boolean.TRUE, key.chainValid)
        assertEquals(RootStatus.UNKNOWN, key.rootStatus)
        assertNotNull(key.chainRoot)
        assertTrue(key.chainRoot!!.contains("Locally Generated Root"))
        assertFalse(key.remoteProvisioned)
    }

    @Test
    fun `rkp is reported for the pinned rkp root or the provisioning extension`() {
        assertTrue(RootKeys.isRemoteProvisioned(RootStatus.GOOGLE_RKP, null))
        assertFalse(RootKeys.isRemoteProvisioned(RootStatus.GOOGLE, null))
        assertFalse(RootKeys.hasProvisioningInfo(null))
    }

    private fun publicKeyOf(encoded: String): java.security.PublicKey {
        val spec = java.security.spec.X509EncodedKeySpec(java.util.Base64.getDecoder().decode(encoded))
        return runCatching { java.security.KeyFactory.getInstance("EC").generatePublic(spec) }
            .recoverCatching { java.security.KeyFactory.getInstance("RSA").generatePublic(spec) }
            .getOrThrow()
    }

    // ------------------------------------------------- private key vs leaf

    @Test
    fun `the private key is checked against the leaf certificate`() {
        val analyzed = analyze(keybox(deviceId = "4D2"))

        assertEquals(java.lang.Boolean.TRUE, analyzed.keys[0].privateKeyMatchesLeaf)
        assertEquals("PRIVATE_KEY", analyzed.keys[0].identitySource.name)
    }

    @Test
    fun `a private key that belongs to another leaf is reported as a mismatch`() {
        // Same key material by identity, but the certificate was issued for a
        // different key, so the two halves of the keybox disagree.
        val stranger = TestPki.ecKeyPair()
        val leaf = TestPki.certificate(
            subjectCommonName = "Keybox Leaf",
            subjectKey = stranger.public,
            issuerCommonName = TestPki.GOOGLE_ROOT_CN,
            issuerKey = rootPair.private,
            serial = leafSerial,
        )
        val analyzed = analyze(
            keybox(chain = listOf(Pem.encode("CERTIFICATE", leaf))),
        )

        assertEquals(java.lang.Boolean.FALSE, analyzed.keys[0].privateKeyMatchesLeaf)
    }

    @Test
    fun `the device id never decides group membership`() {
        // Two files with the same key and different DeviceIDs stay one group;
        // DeviceID is decoration, not identity.
        val analyzed = analyze(keybox(deviceId = "anything-at-all"))

        assertEquals("PRIVATE_KEY", analyzed.keys[0].identitySource.name)
        assertEquals(1, analyzed.keys.size)
    }

    // ---------------------------------------------------------------- expiry

    @Test
    fun `an expired certificate makes the keybox count as revoked`() {
        val key = analyze(keybox(chain = listOf(expiredLeafPem(), rootPem()))).keys.single()

        assertEquals(RevocationStatus.REVOKED, key.status)
        assertTrue(key.expired)
        assertEquals(listOf(0), key.expiredCertificates)
        assertNotNull(key.revocationReason)
        assertTrue(key.revocationReason!!.contains("证书已过期"))
    }

    @Test
    fun `expiry alone is enough to revoke without the published list`() {
        val key = analyze(
            keybox = keybox(chain = listOf(expiredLeafPem(), rootPem())),
            revocation = RevocationSnapshot(emptyMap(), RevocationSource.NONE, fixedNow),
        ).keys.single()

        assertEquals(RevocationStatus.REVOKED, key.status)
    }

    @Test
    fun `a keybox inside its validity window stays valid`() {
        val key = analyze(keybox()).keys.single()

        assertEquals(RevocationStatus.VALID, key.status)
        assertFalse(key.expired)
        assertTrue(key.expiredCertificates.isEmpty())
        assertNull(key.revocationReason)
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

    private fun expiredLeafPem(): String = Pem.encode(
        "CERTIFICATE",
        TestPki.certificate(
            subjectCommonName = "Keybox Leaf",
            subjectKey = leafPair.public,
            issuerCommonName = TestPki.GOOGLE_ROOT_CN,
            issuerKey = rootPair.private,
            serial = leafSerial,
            notAfterMillis = fixedNow - 1_000L,
        ),
    )

    private fun rootPem(): String = Pem.encode("CERTIFICATE", rootDer())
}
