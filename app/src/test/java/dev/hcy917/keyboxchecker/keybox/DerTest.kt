package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec

/**
 * The DER helpers carry the whole identity story: a private key must turn into
 * exactly the same SubjectPublicKeyInfo the JDK would produce, otherwise two
 * copies of one leaked key would land in different groups.
 */
class DerTest {

    @Test
    fun `sha256 matches the known vector`() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Der.sha256("abc".toByteArray(Charsets.UTF_8)),
        )
    }

    @Test
    fun `sha256Short keeps the requested prefix`() {
        val short = Der.sha256Short("abc".toByteArray(Charsets.UTF_8), 16)
        assertEquals(16, short.length)
        assertEquals("ba7816bf8f01cfea", short)
    }

    @Test
    fun `oid round trips for long and short arcs`() {
        for (dotted in listOf("1.2.840.10045.2.1", "1.3.132.0.34", "2.5.4.3", "1.2.840.113549.1.1.1")) {
            val encoded = Der.oid(dotted)
            val tlv = Der.parseTlv(encoded)
            assertEquals(Der.TAG_OID, tlv.tag)
            assertEquals(dotted, Der.decodeOid(encoded, tlv))
        }
    }

    @Test
    fun `long form length is read back`() {
        val encoded = Der.octetString(ByteArray(200))
        val tlv = Der.parseTlv(encoded)
        assertEquals(Der.TAG_OCTET_STRING, tlv.tag)
        assertTrue("length=${tlv.length}", tlv.length == 200)
        assertTrue("headerLength=${tlv.headerLength}", tlv.headerLength == 3)
        // totalLength is header + content: the tag byte is already inside headerLength.
        assertEquals(3 + 200, tlv.totalLength)
    }

    @Test
    fun `pkcs8 ec private key derives the jdk public key`() {
        val pair = TestPki.ecKeyPair()
        val pkcs8 = pair.private.encoded
        val spki = Der.publicKeyInfoOfPrivateKey(pkcs8, "ec", "PRIVATE KEY")
        assertNotNull("SPKI must be derivable from a PKCS#8 EC key", spki)
        assertArrayEquals(pair.public.encoded, spki)
    }

    @Test
    fun `sec1 without a public point is recovered by scalar multiplication`() {
        val pair = TestPki.ecKeyPair()
        val sec1 = sec1WithCurveOnly(pair.private.encoded)
        val spki = Der.publicKeyInfoOfPrivateKey(sec1, "ec", "EC PRIVATE KEY")
        assertNotNull("the [1] public point is optional and must be recomputed", spki)
        assertArrayEquals(pair.public.encoded, spki)
    }

    @Test
    fun `pkcs1 rsa private key derives the jdk public key`() {
        val pair = TestPki.rsaKeyPair()
        val crt = KeyFactory.getInstance("RSA")
            .generatePrivate(PKCS8EncodedKeySpec(pair.private.encoded)) as RSAPrivateCrtKey
        val pkcs1 = Der.seq(
            Der.int(0),
            Der.integer(crt.modulus),
            Der.integer(crt.publicExponent),
            Der.integer(crt.privateExponent),
            Der.integer(crt.primeP),
            Der.integer(crt.primeQ),
            Der.integer(crt.primeExponentP),
            Der.integer(crt.primeExponentQ),
            Der.integer(crt.crtCoefficient),
        )
        val spki = Der.publicKeyInfoOfPrivateKey(pkcs1, "rsa", "RSA PRIVATE KEY")
        assertNotNull("PKCS#1 must be wrapped into PKCS#8 on demand", spki)
        assertArrayEquals(pair.public.encoded, spki)
    }

    @Test
    fun `pkcs8 rsa private key derives the jdk public key`() {
        val pair = TestPki.rsaKeyPair()
        val spki = Der.publicKeyInfoOfPrivateKey(pair.private.encoded, "rsa", "PRIVATE KEY")
        assertNotNull(spki)
        assertArrayEquals(pair.public.encoded, spki)
    }

    @Test
    fun `a bare sec1 key is not mistaken for pkcs8`() {
        val pair = TestPki.ecKeyPair()
        val sec1 = sec1WithCurveOnly(pair.private.encoded)
        assertNull(Der.pkcs8AlgorithmOid(sec1))
        assertEquals(Der.PrivateKeyEncoding.SEC1_EC, Der.detectEncoding(sec1, "ec"))
        assertNotNull(Der.pkcs8AlgorithmOid(pair.private.encoded))
        assertEquals(Der.PrivateKeyEncoding.PKCS8, Der.detectEncoding(pair.private.encoded, null))
    }

    @Test
    fun `pem labels map onto encodings`() {
        assertEquals(Der.PrivateKeyEncoding.PKCS8, Der.classifyPrivateKey("PRIVATE KEY"))
        assertEquals(Der.PrivateKeyEncoding.PKCS8, Der.classifyPrivateKey(" private key "))
        assertEquals(Der.PrivateKeyEncoding.SEC1_EC, Der.classifyPrivateKey("EC PRIVATE KEY"))
        assertEquals(Der.PrivateKeyEncoding.PKCS1_RSA, Der.classifyPrivateKey("RSA PRIVATE KEY"))
        assertEquals(Der.PrivateKeyEncoding.UNKNOWN, Der.classifyPrivateKey(null))
    }

    @Test
    fun `truncated input fails closed instead of throwing`() {
        assertNull(Der.publicKeyInfoOfPrivateKey(ByteArray(0), "ec", "PRIVATE KEY"))
        assertNull(Der.publicKeyInfoOfPrivateKey(byteArrayOf(0x30, 0x05, 0x02), "ec", "EC PRIVATE KEY"))
        assertNull(Der.pkcs8Inner(ByteArray(3)))
    }

    /**
     * ECB-shaped `ECPrivateKey` carrying the curve OID but deliberately omitting
     * the optional `[1]` public point.
     */
    private fun sec1WithCurveOnly(pkcs8: ByteArray): ByteArray {
        val key = KeyFactory.getInstance("EC")
            .generatePrivate(PKCS8EncodedKeySpec(pkcs8)) as ECPrivateKey
        val scalar = Der.fixedUnsigned(key.s, 32)
        val parameters = Der.encodeTlv(Der.TAG_CONTEXT_0, Der.oid("1.2.840.10045.3.1.7"))
        return Der.seq(Der.int(1), Der.octetString(scalar), parameters)
    }
}
