package dev.hcy917.keyboxchecker.keybox

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Synthetic PKI fixtures.
 *
 * Everything here is generated at test time from the JDK's own key generators
 * and our minimal DER writer — the repository never ships a real keybox, a real
 * attestation certificate or a real private key.
 */
object TestPki {

    private const val TAG_EXPLICIT_0 = 0xA0
    private const val TAG_SET = 0x31
    private const val TAG_UTF8_STRING = 0x0C
    private const val TAG_UTC_TIME = 0x17

    private const val OID_COMMON_NAME = "2.5.4.3"
    private const val OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
    private const val OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"

    /** Google's own root name, so a fixture chain can be recognised as an attestation chain. */
    const val GOOGLE_ROOT_CN = "Google Hardware Attestation Root"

    const val NOT_BEFORE = 1_600_000_000_000L
    const val NOT_AFTER = 2_000_000_000_000L

    fun ecKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

    fun rsaKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }
            .generateKeyPair()

    /** Builds a real, signature-verifiable X.509 certificate with no external tooling. */
    fun certificate(
        subjectCommonName: String,
        subjectKey: PublicKey,
        issuerCommonName: String,
        issuerKey: PrivateKey,
        serial: BigInteger,
        notBeforeMillis: Long = NOT_BEFORE,
        notAfterMillis: Long = NOT_AFTER,
    ): ByteArray {
        val rsa = issuerKey.algorithm.equals("RSA", ignoreCase = true)
        val algorithm = if (rsa) {
            Der.seq(Der.oid(OID_SHA256_WITH_RSA), Der.nullValue())
        } else {
            Der.seq(Der.oid(OID_ECDSA_WITH_SHA256))
        }
        val tbs = Der.seq(
            Der.encodeTlv(TAG_EXPLICIT_0, Der.int(2)), // version: v3
            Der.integer(serial),
            algorithm,
            name(issuerCommonName),
            Der.seq(utcTime(notBeforeMillis), utcTime(notAfterMillis)),
            name(subjectCommonName),
            Der.spkiOf(subjectKey),
        )
        val signer = Signature.getInstance(if (rsa) "SHA256withRSA" else "SHA256withECDSA")
        signer.initSign(issuerKey)
        signer.update(tbs)
        return Der.seq(tbs, algorithm, Der.bitString(signer.sign()))
    }

    /** Self-signed certificate for [pair] carrying [commonName]. */
    fun selfSigned(pair: KeyPair, commonName: String, serial: Long = 1L): ByteArray =
        certificate(commonName, pair.public, commonName, pair.private, BigInteger.valueOf(serial))

    fun parse(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    fun pem(label: String, der: ByteArray): String = Pem.encode(label, der)

    /**
     * Re-encodes a PKCS#8 EC key as SEC1 with the optional `[1]` public point
     * removed, so the analyser has to recover the point by scalar
     * multiplication instead of reading it.
     */
    fun sec1WithoutPublicPoint(pkcs8: ByteArray): ByteArray {
        val inner = Der.pkcs8Inner(pkcs8) ?: error("not a PKCS#8 structure")
        val top = Der.parseTlv(inner)
        val kept = Der.children(inner, top).filter { it.tag != Der.TAG_CONTEXT_1 }
        return Der.encodeTlv(
            Der.TAG_SEQUENCE,
            Der.concat(kept.map { inner.copyOfRange(it.offset, it.contentEnd) }),
        )
    }

    // ------------------------------------------------------------------- XML

    /** One `<Keybox>` element, indented with [indent] leading spaces. */
    fun keyboxBlock(
        deviceId: String?,
        algorithm: String,
        privateKeyPem: String,
        chainPems: List<String>,
        indent: String = "  ",
        deviceIdAsElement: Boolean = false,
        prefix: String = "",
        extraKeyAttributes: String = "",
    ): String = buildString {
        val deviceAttribute =
            if (deviceId != null && !deviceIdAsElement) " DeviceID=\"$deviceId\"" else ""
        append("$indent<${prefix}Keybox$deviceAttribute>\n")
        if (deviceId != null && deviceIdAsElement) {
            append("$indent  <${prefix}DeviceID>$deviceId</${prefix}DeviceID>\n")
        }
        append("$indent  <${prefix}Key algorithm=\"$algorithm\"$extraKeyAttributes>\n")
        append("$indent    <${prefix}PrivateKey format=\"pem\">\n")
        append(privateKeyPem.trimEnd()).append('\n')
        append("$indent    </${prefix}PrivateKey>\n")
        append("$indent    <${prefix}CertificateChain>\n")
        append("$indent      <${prefix}NumberOfCertificates>${chainPems.size}</${prefix}NumberOfCertificates>\n")
        for (pem in chainPems) {
            append("$indent      <${prefix}Certificate format=\"pem\">\n")
            append(pem.trimEnd()).append('\n')
            append("$indent      </${prefix}Certificate>\n")
        }
        append("$indent    </${prefix}CertificateChain>\n")
        append("$indent  </${prefix}Key>\n")
        append("$indent</${prefix}Keybox>\n")
    }

    /** A keybox document shaped like the ones Google's attestation tooling emits. */
    fun keyboxXml(
        deviceId: String?,
        algorithm: String,
        privateKeyPem: String,
        chainPems: List<String>,
        numberOfKeyboxes: Int = 1,
        deviceIdAsElement: Boolean = false,
        namespaced: Boolean = false,
        rootElement: String = "AndroidAttestation",
    ): String {
        val namespace = if (namespaced) " xmlns:att=\"https://www.android.com/attestation/\"" else ""
        val prefix = if (namespaced) "att:" else ""
        return buildString {
            append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
            append("<$prefix$rootElement$namespace>\n")
            append("  <${prefix}NumberOfKeyboxes>$numberOfKeyboxes</${prefix}NumberOfKeyboxes>\n")
            append(
                keyboxBlock(
                    deviceId = deviceId,
                    algorithm = algorithm,
                    privateKeyPem = privateKeyPem,
                    chainPems = chainPems,
                    indent = "  ",
                    deviceIdAsElement = deviceIdAsElement,
                    prefix = prefix,
                ),
            )
            append("</$prefix$rootElement>\n")
        }
    }

    /** A single document carrying two `<Keybox>` elements. */
    fun multiKeyboxXml(
        deviceIds: List<String>,
        algorithm: String,
        privateKeyPem: String,
        chainPems: List<String>,
    ): String = buildString {
        append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        append("<AndroidAttestation>\n")
        append("  <NumberOfKeyboxes>${deviceIds.size}</NumberOfKeyboxes>\n")
        for (deviceId in deviceIds) {
            append(
                keyboxBlock(
                    deviceId = deviceId,
                    algorithm = algorithm,
                    privateKeyPem = privateKeyPem,
                    chainPems = chainPems,
                    indent = "  ",
                ),
            )
        }
        append("</AndroidAttestation>\n")
    }

    // --------------------------------------------------------------- private

    private fun name(commonName: String): ByteArray = Der.seq(
        Der.encodeTlv(
            TAG_SET,
            Der.seq(
                Der.oid(OID_COMMON_NAME),
                Der.encodeTlv(TAG_UTF8_STRING, commonName.toByteArray(Charsets.UTF_8)),
            ),
        ),
    )

    private fun utcTime(millis: Long): ByteArray {
        val format = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US)
        format.timeZone = TimeZone.getTimeZone("UTC")
        return Der.encodeTlv(TAG_UTC_TIME, format.format(Date(millis)).toByteArray(Charsets.US_ASCII))
    }
}
