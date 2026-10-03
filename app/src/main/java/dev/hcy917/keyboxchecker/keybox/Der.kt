package dev.hcy917.keyboxchecker.keybox

import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Minimal DER (Distinguished Encoding Rules) reader/writer plus the few
 * key-encoding conversions the keybox analyser needs.
 *
 * Everything here is pure JDK so the whole [dev.hcy917.keyboxchecker.keybox]
 * package stays unit-testable on a plain JVM.
 */
object Der {

    const val OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
    const val OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"

    const val TAG_INTEGER = 0x02
    const val TAG_BIT_STRING = 0x03
    const val TAG_OCTET_STRING = 0x04
    const val TAG_NULL = 0x05
    const val TAG_OID = 0x06
    const val TAG_SEQUENCE = 0x30
    const val TAG_CONTEXT_0 = 0xA0
    const val TAG_CONTEXT_1 = 0xA1
    /** Implicitly tagged `[1] BIT STRING` as emitted by a few SEC1 writers. */
    const val TAG_CONTEXT_1_IMPLICIT = 0x81

    /** A parsed TLV header. Length is the content length, not including the header. */
    class Tlv(
        val tag: Int,
        val offset: Int,
        val headerLength: Int,
        val length: Int,
    ) {
        val contentStart: Int get() = offset + headerLength
        val contentEnd: Int get() = contentStart + length
        /** Total on-wire size: header + content. */
        val totalLength: Int get() = headerLength + length
    }

    // ---------------------------------------------------------------- reading

    fun parseTlv(data: ByteArray, offset: Int = 0): Tlv {
        require(offset + 2 <= data.size) { "DER truncated at offset $offset" }
        val tag = data[offset].toInt() and 0xFF
        var cursor = offset + 1
        var first = data[cursor].toInt() and 0xFF
        cursor++
        var length: Int
        if ((first and 0x80) == 0) {
            length = first
        } else {
            val count = first and 0x7F
            require(count in 1..4) { "Unsupported DER length encoding ($count bytes)" }
            length = 0
            repeat(count) {
                require(cursor < data.size) { "DER length truncated" }
                length = (length shl 8) or (data[cursor].toInt() and 0xFF)
                cursor++
            }
        }
        require(cursor + length <= data.size) {
            "DER content overruns buffer: need ${cursor + length}, have ${data.size}"
        }
        return Tlv(tag, offset, cursor - offset, length)
    }

    /** Direct children of a constructed TLV. Works for any constructed tag. */
    fun children(data: ByteArray, parent: Tlv): List<Tlv> {
        val result = ArrayList<Tlv>(4)
        var cursor = parent.contentStart
        while (cursor < parent.contentEnd) {
            val child = parseTlv(data, cursor)
            result += child
            cursor = child.contentEnd
        }
        return result
    }

    fun children(data: ByteArray): List<Tlv> = children(data, parseTlv(data, 0))

    fun content(data: ByteArray, tlv: Tlv): ByteArray =
        data.copyOfRange(tlv.contentStart, tlv.contentEnd)

    fun find(data: ByteArray, list: List<Tlv>, tag: Int): Tlv? = list.firstOrNull { it.tag == tag }

    /** Decodes an OID content body into dotted-decimal form. */
    fun decodeOid(data: ByteArray, tlv: Tlv): String {
        val bytes = data.copyOfRange(tlv.contentStart, tlv.contentEnd)
        if (bytes.isEmpty()) return ""
        val sb = StringBuilder()
        var value = 0L
        var first = true
        for (byte in bytes) {
            val b = byte.toInt() and 0xFF
            value = (value shl 7) or (b and 0x7F).toLong()
            if ((b and 0x80) == 0) {
                if (first) {
                    val arc = (value / 40).coerceAtMost(2L)
                    sb.append(arc).append('.').append(value - arc * 40)
                    first = false
                } else {
                    sb.append('.').append(value)
                }
                value = 0
            }
        }
        return sb.toString()
    }

    // ---------------------------------------------------------------- writing

    fun encodeLength(length: Int): ByteArray = when {
        length < 0x80 -> byteArrayOf(length.toByte())
        length < 0x100 -> byteArrayOf(0x81.toByte(), length.toByte())
        length < 0x10000 -> byteArrayOf(0x82.toByte(), (length shr 8).toByte(), length.toByte())
        else -> byteArrayOf(
            0x83.toByte(),
            (length shr 16).toByte(),
            (length shr 8).toByte(),
            length.toByte(),
        )
    }

    fun encodeTlv(tag: Int, body: ByteArray): ByteArray {
        val header = encodeLength(body.size)
        val out = ByteArray(1 + header.size + body.size)
        out[0] = tag.toByte()
        header.copyInto(out, 1)
        body.copyInto(out, 1 + header.size)
        return out
    }

    fun concat(parts: List<ByteArray>): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var cursor = 0
        for (part in parts) {
            part.copyInto(out, cursor)
            cursor += part.size
        }
        return out
    }

    fun seq(vararg parts: ByteArray): ByteArray = encodeTlv(TAG_SEQUENCE, concat(parts.toList()))

    fun octetString(body: ByteArray): ByteArray = encodeTlv(TAG_OCTET_STRING, body)

    fun bitString(body: ByteArray, unusedBits: Int = 0): ByteArray =
        encodeTlv(TAG_BIT_STRING, byteArrayOf(unusedBits.toByte()) + body)

    fun nullValue(): ByteArray = byteArrayOf(TAG_NULL.toByte(), 0x00)

    /** Encodes a non-negative BigInteger as a DER INTEGER (adds a leading 0x00 when the sign bit is set). */
    fun integer(value: BigInteger): ByteArray = encodeTlv(TAG_INTEGER, unsignedBytes(value))

    fun int(value: Int): ByteArray = integer(BigInteger.valueOf(value.toLong()))

    fun unsignedBytes(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        return if (raw.size > 1 && raw[0] == 0.toByte() && (raw[1].toInt() and 0x80) == 0) {
            raw.copyOfRange(1, raw.size)
        } else {
            raw
        }
    }

    /**
     * Fixed-width big-endian unsigned encoding, zero padded on the left.
     *
     * `BigInteger.toByteArray()` prepends a sign byte whenever the top bit is
     * set, so that byte has to be dropped here rather than kept: a 256-bit EC
     * coordinate would otherwise need 33 bytes and never fit into a 32-byte
     * field.
     */
    fun fixedUnsigned(value: BigInteger, size: Int): ByteArray {
        val raw = value.toByteArray()
        val magnitude = if (raw.size > 1 && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
        require(magnitude.size <= size) { "Value needs ${magnitude.size} bytes, only $size available" }
        val out = ByteArray(size)
        magnitude.copyInto(out, size - magnitude.size)
        return out
    }

    /** Encodes a dotted-decimal OID, including the 40*x+y first-arc packing. */
    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split('.').map { it.toLong() }
        require(arcs.size >= 2) { "OID needs at least two arcs: $dotted" }
        val body = ArrayList<Byte>(arcs.size + 4)
        var value = arcs[0] * 40 + arcs[1]
        for (index in 1 until arcs.size) {
            if (index == 1) {
                body += base128(value)
            } else {
                body += base128(arcs[index])
            }
        }
        return encodeTlv(TAG_OID, body.toByteArray())
    }

    private fun base128(value: Long): List<Byte> {
        require(value >= 0) { "OID arc must be non-negative" }
        if (value == 0L) return listOf(0.toByte())
        val stack = ArrayList<Byte>(4)
        var remaining = value
        while (remaining > 0) {
            stack += (remaining and 0x7F).toByte()
            remaining = remaining shr 7
        }
        stack.reverse()
        return stack.mapIndexed { index, byte ->
            if (index == stack.size - 1) byte else (byte.toInt() or 0x80).toByte()
        }
    }

    // ------------------------------------------------- key material handling

    enum class PrivateKeyEncoding { PKCS8, SEC1_EC, PKCS1_RSA, UNKNOWN }

    fun classifyPrivateKey(pemLabel: String?): PrivateKeyEncoding = when (pemLabel?.trim()?.uppercase()) {
        "PRIVATE KEY" -> PrivateKeyEncoding.PKCS8
        "EC PRIVATE KEY" -> PrivateKeyEncoding.SEC1_EC
        "RSA PRIVATE KEY" -> PrivateKeyEncoding.PKCS1_RSA
        else -> PrivateKeyEncoding.UNKNOWN
    }

    /**
     * Wraps a bare SEC1 / PKCS#1 private key into an unencrypted PKCS#8 structure.
     * A key that already is PKCS#8 is returned unchanged.
     */
    fun toPkcs8(der: ByteArray, encoding: PrivateKeyEncoding): ByteArray = when (encoding) {
        PrivateKeyEncoding.PKCS8 -> der
        PrivateKeyEncoding.SEC1_EC -> {
            val curveOid = findEcCurveOid(der) ?: return der
            seq(int(0), seq(oid(OID_EC_PUBLIC_KEY), oid(curveOid)), octetString(der))
        }
        PrivateKeyEncoding.PKCS1_RSA ->
            seq(int(0), seq(oid(OID_RSA_ENCRYPTION), nullValue()), octetString(der))
        PrivateKeyEncoding.UNKNOWN -> der
    }

    /** Unwraps a PKCS#8 structure to its inner algorithm-specific OCTET STRING body. */
    fun pkcs8Inner(der: ByteArray): ByteArray? {
        return runCatching {
            val top = parseTlv(der)
            require(top.tag == TAG_SEQUENCE) { "PKCS#8 must be a SEQUENCE" }
            val parts = children(der, top)
            require(parts.size >= 3) { "PKCS#8 needs version, algorithm and key" }
            val inner = parts[2]
            require(inner.tag == TAG_OCTET_STRING) { "PKCS#8 private key must be an OCTET STRING" }
            content(der, inner)
        }.getOrNull()
    }

    /**
     * Algorithm OID of a PKCS#8 structure, or null when [der] is not PKCS#8.
     *
     * The structural check matters: a bare SEC1 key is also
     * `SEQUENCE { INTEGER, ..., SEQUENCE { OID curve } }`, so merely finding an
     * OID would misclassify it. PKCS#8 always has the shape
     * `SEQUENCE { INTEGER version, SEQUENCE algorithm, OCTET STRING key }`
     * and an algorithm OID we recognise.
     */
    fun pkcs8AlgorithmOid(der: ByteArray): String? = runCatching {
        val top = parseTlv(der)
        if (top.tag != TAG_SEQUENCE) return null
        val parts = children(der, top)
        if (parts.size < 3) return null
        if (parts[0].tag != TAG_INTEGER) return null
        if (parts[1].tag != TAG_SEQUENCE) return null
        if (parts[2].tag != TAG_OCTET_STRING) return null
        val oidTlv = find(der, children(der, parts[1]), TAG_OID) ?: return null
        val oid = decodeOid(der, oidTlv)
        if (oid != OID_EC_PUBLIC_KEY && oid != OID_RSA_ENCRYPTION) return null
        oid
    }.getOrNull()

    /** Locates the named-curve OID inside a SEC1 ECPrivateKey structure. */
    fun findEcCurveOid(der: ByteArray, top: Tlv? = null): String? = runCatching {
        val root = top ?: parseTlv(der)
        val parts = children(der, root)
        val parameters = parts.firstOrNull { it.tag == TAG_CONTEXT_0 } ?: return null
        val oidTlv = find(der, children(der, parameters), TAG_OID) ?: return null
        decodeOid(der, oidTlv)
    }.getOrNull()

    /**
     * Uncompressed public point (04 || X || Y) carried in the `[1]` field of a
     * SEC1 structure. OpenSSL and SunEC emit the explicit form
     * (`A1 .. 03 .. 00 04 ..`), but the bare implicit form (`81 .. 00 04 ..`)
     * is accepted too.
     */
    fun sec1PublicPoint(der: ByteArray, top: Tlv? = null): ByteArray? = runCatching {
        val root = top ?: parseTlv(der)
        val parts = children(der, root)
        val publicKey = parts.firstOrNull { it.tag == TAG_CONTEXT_1 || it.tag == TAG_CONTEXT_1_IMPLICIT }
            ?: return null
        val body = when (publicKey.tag) {
            TAG_CONTEXT_1_IMPLICIT -> content(der, publicKey)
            else -> {
                val bitString = find(der, children(der, publicKey), TAG_BIT_STRING) ?: return null
                content(der, bitString)
            }
        }
        if (body.size <= 1) return null
        body.copyOfRange(1, body.size)
    }.getOrNull()

    /** SubjectPublicKeyInfo for an EC private key stored in SEC1 form. */
    fun ecPublicKeyInfo(sec1Der: ByteArray): ByteArray? = runCatching {
        val curveOid = findEcCurveOid(sec1Der) ?: return null
        val point = sec1PublicPoint(sec1Der) ?: return null
        ecPublicKeyInfo(curveOid, point)
    }.getOrNull()

    fun ecPublicKeyInfo(curveOid: String, uncompressedPoint: ByteArray): ByteArray =
        seq(seq(oid(OID_EC_PUBLIC_KEY), oid(curveOid)), bitString(uncompressedPoint))

    fun rsaPublicKeyInfo(modulus: BigInteger, publicExponent: BigInteger): ByteArray = seq(
        seq(oid(OID_RSA_ENCRYPTION), nullValue()),
        bitString(seq(integer(modulus), integer(publicExponent))),
    )

    /** Extracts SubjectPublicKeyInfo from a PKCS#1 RSAPrivateKey body. */
    fun rsaPublicKeyInfoFromPkcs1(pkcs1Der: ByteArray): ByteArray? = runCatching {
        val parts = children(pkcs1Der)
        require(parts.size >= 4) { "RSAPrivateKey needs at least 4 integers" }
        require(parts[0].tag == TAG_INTEGER) { "RSAPrivateKey must start with version" }
        require(parts[1].tag == TAG_INTEGER && parts[2].tag == TAG_INTEGER) {
            "RSAPrivateKey modulus/exponent must be INTEGERs"
        }
        val modulus = BigInteger(1, content(pkcs1Der, parts[1]))
        val exponent = BigInteger(1, content(pkcs1Der, parts[2]))
        rsaPublicKeyInfo(modulus, exponent)
    }.getOrNull()

    /**
     * Derives the canonical SubjectPublicKeyInfo for a private key given as PEM
     * DER bytes. This is what makes two keyboxes with the same key but different
     * (tampered) DeviceID collapse onto a single identity.
     *
     * @param algorithm value of the `algorithm` attribute of the keybox `<Key>`
     *   element; "ecdsa" and "rsa" are the only ones used in practice.
     * @return SPKI bytes, or null when the key cannot be interpreted.
     */
    fun publicKeyInfoOfPrivateKey(der: ByteArray, algorithm: String?, pemLabel: String? = null): ByteArray? =
        runCatching { derivePublicKeyInfo(der, algorithm, pemLabel) }.getOrNull()

    private fun derivePublicKeyInfo(der: ByteArray, algorithm: String?, pemLabel: String?): ByteArray? {
        val declared = classifyPrivateKey(pemLabel)
        val encoding = if (declared != PrivateKeyEncoding.UNKNOWN) declared else detectEncoding(der, algorithm)
        val normalized = if (encoding == PrivateKeyEncoding.PKCS8) der else toPkcs8(der, encoding)
        val inner = if (encoding == PrivateKeyEncoding.PKCS8) pkcs8Inner(der) else der
        val oid = if (encoding == PrivateKeyEncoding.PKCS8) pkcs8AlgorithmOid(der) else null
        val looksRsa = oid == OID_RSA_ENCRYPTION ||
            encoding == PrivateKeyEncoding.PKCS1_RSA ||
            algorithm?.contains("rsa", ignoreCase = true) == true

        if (looksRsa) {
            val pkcs1 = inner ?: der
            rsaPublicKeyInfoFromPkcs1(pkcs1)?.let { return it }
            // Last resort: let the JVM parse the PKCS#8 container and recover n/e.
            return runCatching {
                val key = KeyFactory.getInstance("RSA")
                    .generatePrivate(PKCS8EncodedKeySpec(normalized))
                val rsa = key as java.security.interfaces.RSAPrivateCrtKey
                rsaPublicKeyInfo(rsa.modulus, rsa.publicExponent)
            }.getOrNull()
        }

        val sec1 = inner ?: der
        ecPublicKeyInfo(sec1)?.let { return it }
        // The public point may be absent; recover it by scalar multiplication.
        // The curve OID is mandatory in SEC1, so prefer it over guessing.
        val curveOid = findEcCurveOid(sec1)
        return runCatching {
            val key = KeyFactory.getInstance("EC")
                .generatePrivate(PKCS8EncodedKeySpec(normalized)) as ECPrivateKey
            val curve = key.params
            val point = scalarMultiply(curve, key.s) ?: return null
            val size = ((curve.curve.field as ECFieldFp).p.bitLength() + 7) / 8
            ecPublicKeyInfo(
                curveOid ?: curveOidOf(curve),
                byteArrayOf(0x04) +
                    fixedUnsigned(point.affineX, size) +
                    fixedUnsigned(point.affineY, size),
            )
        }.getOrNull()
    }

    /** Guesses the on-wire private key encoding without relying on a PEM label. */
    fun detectEncoding(der: ByteArray, algorithm: String?): PrivateKeyEncoding {
        when (pkcs8AlgorithmOid(der)) {
            OID_EC_PUBLIC_KEY, OID_RSA_ENCRYPTION -> return PrivateKeyEncoding.PKCS8
        }
        if (algorithm?.contains("rsa", ignoreCase = true) == true) return PrivateKeyEncoding.PKCS1_RSA
        if (algorithm?.contains("ec", ignoreCase = true) == true) return PrivateKeyEncoding.SEC1_EC
        return if (lookLikeSec1(der)) PrivateKeyEncoding.SEC1_EC else PrivateKeyEncoding.PKCS1_RSA
    }

    private fun lookLikeSec1(der: ByteArray): Boolean = runCatching {
        val parts = children(der)
        parts.firstOrNull()?.tag == TAG_INTEGER &&
            parts.any { it.tag == TAG_CONTEXT_0 || it.tag == TAG_CONTEXT_1 }
    }.getOrDefault(false)

    /** Dotted OID of a named curve, derived from the JVM's own EC parameter table. */
    fun curveOidOf(params: ECParameterSpec): String {
        val fieldSize = (params.curve.field as ECFieldFp).p.bitLength()
        return when {
            fieldSize >= 521 -> "1.3.132.0.35" // secp521r1
            fieldSize >= 384 -> "1.3.132.0.34" // secp384r1
            else -> "1.2.840.10045.3.1.7" // secp256r1
        }
    }

    /** Affine double-and-add scalar multiplication; returns null for the point at infinity. */
    fun scalarMultiply(params: ECParameterSpec, scalar: BigInteger): ECPoint? {
        val p = (params.curve.field as ECFieldFp).p
        val a = params.curve.a.mod(p)
        val generator = params.generator
        var resultX: BigInteger? = null
        var resultY: BigInteger? = null

        fun add(
            x1: BigInteger, y1: BigInteger,
            x2: BigInteger, y2: BigInteger,
        ): Pair<BigInteger, BigInteger>? {
            if (x1 == x2 && (y1 + y2).mod(p) == BigInteger.ZERO) return null
            val lambda = if (x1 == x2 && y1 == y2) {
                (x1.multiply(x1).multiply(BigInteger.valueOf(3)).add(a))
                    .multiply(y1.multiply(BigInteger.valueOf(2)).modInverse(p))
            } else {
                (y2 - y1).multiply((x2 - x1).modInverse(p))
            }.mod(p)
            val x3 = (lambda.multiply(lambda) - x1 - x2).mod(p)
            val y3 = (lambda.multiply(x1 - x3) - y1).mod(p)
            return x3 to y3
        }

        var bit = scalar.bitLength() - 1
        while (bit >= 0) {
            if (resultX != null && resultY != null) {
                val doubled = add(resultX!!, resultY!!, resultX!!, resultY!!)
                resultX = doubled?.first
                resultY = doubled?.second
            }
            if (scalar.testBit(bit)) {
                if (resultX == null || resultY == null) {
                    resultX = generator.affineX
                    resultY = generator.affineY
                } else {
                    val sum = add(resultX!!, resultY!!, generator.affineX, generator.affineY)
                    resultX = sum?.first
                    resultY = sum?.second
                }
            }
            bit--
        }
        val x = resultX ?: return null
        val y = resultY ?: return null
        return ECPoint(x, y)
    }

    /** SubjectPublicKeyInfo of an already parsed [java.security.PublicKey]. */
    fun spkiOf(publicKey: java.security.PublicKey): ByteArray = publicKey.encoded

    /** Validates that [spki] really is a parseable SubjectPublicKeyInfo. */
    fun isParseablePublicKey(spki: ByteArray, algorithm: String): Boolean =
        runCatching { KeyFactory.getInstance(algorithm).generatePublic(X509EncodedKeySpec(spki)) }
            .isSuccess

    // ---------------------------------------------------------------- digests

    fun sha256(bytes: ByteArray): String = digest("SHA-256", bytes)

    /** Truncated digest, handy for filenames and badges. */
    fun sha256Short(bytes: ByteArray, length: Int = 16): String = sha256(bytes).take(length)

    fun digest(algorithm: String, bytes: ByteArray): String {
        val md = MessageDigest.getInstance(algorithm)
        val hash = md.digest(bytes)
        val sb = StringBuilder(hash.size * 2)
        for (byte in hash) {
            val value = byte.toInt() and 0xFF
            sb.append(HEX[value ushr 4]).append(HEX[value and 0x0F])
        }
        return sb.toString()
    }

    private const val HEX = "0123456789abcdef"
}
