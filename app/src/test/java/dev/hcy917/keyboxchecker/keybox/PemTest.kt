package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Keybox files are hand-edited, so the PEM reader has to be forgiving. */
class PemTest {

    private val payload = ByteArray(180) { (it * 7).toByte() }

    @Test
    fun `encode then decode round trips`() {
        val text = Pem.encode("EC PRIVATE KEY", payload)
        val block = Pem.decodeFirst(text)
        assertNotNull(block)
        assertEquals("EC PRIVATE KEY", block!!.label)
        assertEquals(payload.toList(), block.der.toList())
    }

    @Test
    fun `encode wraps at 64 characters`() {
        val text = Pem.encode("CERTIFICATE", payload)
        val bodyLines = text.lines().filter { it.isNotBlank() && !it.startsWith("-----") }
        assertTrue("expected several body lines", bodyLines.size > 1)
        for (line in bodyLines) assertTrue(line, line.length <= 64)
    }

    @Test
    fun `crlf and missing trailing newline are tolerated`() {
        val text = Pem.encode("CERTIFICATE", payload).replace("\n", "\r\n").trimEnd()
        val block = Pem.decodeFirst(text)
        assertNotNull(block)
        assertEquals(payload.toList(), block!!.der.toList())
    }

    @Test
    fun `several blocks are split apart`() {
        val text = Pem.encode("CERTIFICATE", payload) + Pem.encode("EC PRIVATE KEY", payload.reversedArray())
        val blocks = Pem.decodeBlocks(text)
        assertEquals(2, blocks.size)
        assertEquals("CERTIFICATE", blocks[0].label)
        assertEquals("EC PRIVATE KEY", blocks[1].label)
    }

    @Test
    fun `label filter picks the requested block`() {
        val text = Pem.encode("CERTIFICATE", payload) + Pem.encode("EC PRIVATE KEY", payload)
        assertEquals("EC PRIVATE KEY", Pem.decodeFirst(text, "EC PRIVATE KEY")!!.label)
        assertEquals("CERTIFICATE", Pem.decodeFirst(text, "CERTIFICATE")!!.label)
        // An unknown label falls back to the first block instead of failing.
        assertEquals("CERTIFICATE", Pem.decodeFirst(text, "RSA PRIVATE KEY")!!.label)
    }

    @Test
    fun `text without a block decodes to nothing`() {
        assertNull(Pem.decodeFirst(""))
        assertNull(Pem.decodeFirst("<resources/>"))
        assertFalse(Pem.looksLikePem("<resources/>"))
        assertTrue(Pem.looksLikePem(Pem.encode("CERTIFICATE", payload)))
    }

    @Test
    fun `key label is discovered for diagnostics`() {
        val text = Pem.encode("CERTIFICATE", payload) + Pem.encode("PRIVATE KEY", payload)
        assertEquals("PRIVATE KEY", Pem.labelOfKeyBlock(text))
        assertNull(Pem.labelOfKeyBlock(Pem.encode("CERTIFICATE", payload)))
    }
}
