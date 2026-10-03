package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * The keybox format varies wildly in the wild: namespace prefix present or not,
 * `DeviceID` as attribute or child, PEM armour or a bare base64 blob. All of
 * those spellings have to land on the same model.
 */
class KeyboxParserTest {

    private val leafPair = TestPki.ecKeyPair()
    private val rootPair = TestPki.ecKeyPair()

    private val leafDer = TestPki.certificate(
        subjectCommonName = "Keybox Leaf",
        subjectKey = leafPair.public,
        issuerCommonName = TestPki.GOOGLE_ROOT_CN,
        issuerKey = rootPair.private,
        serial = java.math.BigInteger.valueOf(0x1234),
    )
    private val rootDer = TestPki.selfSigned(rootPair, TestPki.GOOGLE_ROOT_CN, 1L)

    private val privateKeyPem = Pem.encode("PRIVATE KEY", leafPair.private.encoded)
    private val chainPems = listOf(
        Pem.encode("CERTIFICATE", leafDer),
        Pem.encode("CERTIFICATE", rootDer),
    )

    private fun ok(xml: String, fileName: String? = "keybox.xml"): Keybox {
        val outcome = KeyboxParser.parse(xml, fileName)
        assertTrue("expected a keybox, got $outcome", outcome is ParseOutcome.Ok)
        return (outcome as ParseOutcome.Ok).keybox
    }

    private fun rejected(xml: String): ParseOutcome.NotKeybox {
        val outcome = KeyboxParser.parse(xml)
        assertTrue("expected a rejection, got $outcome", outcome is ParseOutcome.NotKeybox)
        return outcome as ParseOutcome.NotKeybox
    }

    @Test
    fun `a plain keybox yields its device id and one key`() {
        val keybox = ok(TestPki.keyboxXml("SERIAL-ABC", "ecdsa", privateKeyPem, chainPems))
        assertEquals("SERIAL-ABC", keybox.deviceId)
        assertEquals(1, keybox.keys.size)
        assertEquals(0, keybox.keys[0].index)
        assertEquals("ecdsa", keybox.keys[0].declaredAlgorithm)
        assertEquals(2, keybox.keys[0].chainPem.size)
        assertEquals("keybox.xml", keybox.sourceName)
    }

    @Test
    fun `a namespaced document parses identically`() {
        val keybox = ok(
            TestPki.keyboxXml("SERIAL-ABC", "ecdsa", privateKeyPem, chainPems, namespaced = true),
        )
        assertEquals("SERIAL-ABC", keybox.deviceId)
        assertEquals(1, keybox.keys.size)
    }

    @Test
    fun `device id as a child element is accepted`() {
        val keybox = ok(
            TestPki.keyboxXml("ELEMENT-ID", "ecdsa", privateKeyPem, chainPems, deviceIdAsElement = true),
        )
        assertEquals("ELEMENT-ID", keybox.deviceId)
    }

    @Test
    fun `a document whose root is the keybox element is accepted`() {
        val keybox = ok(TestPki.keyboxBlock("ROOT-LEVEL", "ecdsa", privateKeyPem, chainPems))
        assertEquals("ROOT-LEVEL", keybox.deviceId)
        assertEquals(1, keybox.keys.size)
    }

    @Test
    fun `two keyboxes in one document are flattened and both device ids kept`() {
        val keybox = ok(
            TestPki.multiKeyboxXml(listOf("DEVICE-A", "DEVICE-B"), "ecdsa", privateKeyPem, chainPems),
        )
        assertEquals("DEVICE-A | DEVICE-B", keybox.deviceId)
        assertEquals(2, keybox.keys.size)
        assertEquals(1, keybox.keys[1].index)
    }

    @Test
    fun `bare base64 bodies are dressed up into pem`() {
        val bareKey = Base64.getEncoder().encodeToString(leafPair.private.encoded)
        val bareChain = chainPems.map { Base64.getEncoder().encodeToString(leafDer) }
        val keybox = ok(TestPki.keyboxXml("BARE", "ecdsa", bareKey, bareChain))
        assertNotNull(keybox.keys[0].privateKeyPem)
        assertTrue(keybox.keys[0].privateKeyPem!!.startsWith("-----BEGIN EC PRIVATE KEY-----"))
        assertTrue(keybox.keys[0].chainPem[0].startsWith("-----BEGIN CERTIFICATE-----"))
    }

    @Test
    fun `an unrelated xml document is reported as not a keybox`() {
        val outcome = rejected("<?xml version=\"1.0\"?><resources><string name=\"a\">b</string></resources>")
        assertTrue(outcome.reason, outcome.reason.contains("resources"))
        assertTrue(KeyboxParser.isWellFormed("<?xml version=\"1.0\"?><resources/>"))
        assertFalse(KeyboxParser.isWellFormed("<resources>"))
    }

    @Test
    fun `truncated xml and a keybox without keys are rejected`() {
        assertTrue(rejected("<AndroidAttestation><Keybox>").reason.contains("XML"))
        val withoutKeys = TestPki.keyboxXml("NO-KEYS", "ecdsa", privateKeyPem, chainPems)
            .replace("<Key algorithm", "<NotAKey algorithm")
            .replace("</Key>", "</NotAKey>")
        assertTrue(KeyboxParser.isWellFormed(withoutKeys))
        assertFalse(KeyboxParser.parse(withoutKeys) is ParseOutcome.Ok)
    }

    @Test
    fun `an oversized document is skipped without parsing`() {
        val huge = "<AndroidAttestation>" + " ".repeat(4 * 1024 * 1024 + 1)
        val outcome = rejected(huge)
        assertTrue(outcome.reason, outcome.reason.contains("4MB"))
    }

    @Test
    fun `a doctype declaration is refused rather than expanded`() {
        val hostile = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>" +
            "<AndroidAttestation><Keybox/></AndroidAttestation>"
        assertFalse(KeyboxParser.isWellFormed(hostile))
        assertFalse(KeyboxParser.parse(hostile) is ParseOutcome.Ok)
    }
}
