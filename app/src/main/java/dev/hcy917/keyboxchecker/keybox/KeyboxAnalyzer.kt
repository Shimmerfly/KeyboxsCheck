package dev.hcy917.keyboxchecker.keybox

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Turns a parsed [Keybox] into revocation and identity facts.
 *
 * Two rules drive the whole design:
 *  * identity is derived from the key material, never from the `DeviceID`
 *    or the attestation properties, because those are trivially editable;
 *  * a key whose status could not be checked is reported as
 *    [RevocationStatus.UNKNOWN], never as clean.
 */
class KeyboxAnalyzer(
    private val revocation: RevocationSnapshot,
    private val nowMillis: () -> Long = System::currentTimeMillis,
) {

    fun analyze(
        fileName: String,
        contentSha256: String,
        keybox: Keybox,
        source: KeyboxSource,
    ): AnalyzedKeybox {
        val analyzedKeys = keybox.keys.map { analyzeKey(it) }
        return AnalyzedKeybox(
            fileName = fileName,
            contentSha256 = contentSha256,
            deviceId = keybox.deviceId?.trim()?.ifBlank { null },
            keys = analyzedKeys,
            chainFingerprint = fingerprintOf(analyzedKeys),
            source = source,
        )
    }

    fun failure(fileName: String, contentSha256: String, reason: String, source: KeyboxSource) =
        AnalyzedKeybox(
            fileName = fileName,
            contentSha256 = contentSha256,
            deviceId = null,
            keys = emptyList(),
            chainFingerprint = "",
            source = source,
            parseError = reason,
        )

    private fun analyzeKey(key: KeyboxKey): AnalyzedKey {
        val certificates = parseChain(key.chainPem)
        val identity = resolveIdentity(key, certificates)
        val chain = verifyChain(certificates)
        val revocationMatch = worstRevocation(certificates)

        val status = when {
            certificates.isEmpty() -> RevocationStatus.UNKNOWN
            !revocation.isUsable -> RevocationStatus.UNKNOWN
            else -> revocationMatch?.status ?: RevocationStatus.VALID
        }

        return AnalyzedKey(
            index = key.index,
            algorithm = key.declaredAlgorithm.ifBlank { "unknown" },
            keyId = identity.keyId,
            identitySource = identity.source,
            identityError = identity.error,
            status = status,
            matchedSerial = revocationMatch?.serialHex,
            revocationReason = revocationMatch?.reason,
            chainValid = chain.valid,
            chainError = chain.error,
            certificates = certificates.mapIndexed { index, certificate -> certificate.describe(index) },
        )
    }

    // --------------------------------------------------------------- identity

    private class Identity(
        val keyId: String,
        val source: IdentitySource,
        val error: String?,
    )

    private fun resolveIdentity(key: KeyboxKey, certificates: List<X509Certificate>): Identity {
        var error: String? = null

        key.privateKeyPem?.let { pem ->
            val block = Pem.decodeFirst(pem)
            if (block == null) {
                error = "私钥 PEM 无法解码"
            } else {
                val encoding = Der.classifyPrivateKey(block.label)
                    .takeIf { it != Der.PrivateKeyEncoding.UNKNOWN }
                    ?: Der.detectEncoding(block.der, key.algorithm)
                val spki = Der.publicKeyInfoOfPrivateKey(block.der, key.algorithm, block.label)
                if (spki != null) {
                    return Identity(Der.sha256(spki), IdentitySource.PRIVATE_KEY, null)
                }
                error = "私钥无法推导公钥（${encoding.name}）"
            }
        }

        certificates.firstOrNull()?.let { leaf ->
            runCatching { leaf.publicKey.encoded }
                .getOrNull()
                ?.takeIf { it.isNotEmpty() }
                ?.let { return Identity(Der.sha256(it), IdentitySource.LEAF_CERTIFICATE, error) }
        }

        val fallbackBytes = (key.privateKeyPem ?: key.chainPem.firstOrNull() ?: "")
            .toByteArray(Charsets.UTF_8)
        val suffix = "（退化为原始字节哈希）"
        return Identity(
            keyId = Der.sha256(fallbackBytes),
            source = IdentitySource.RAW_PEM,
            error = (error?.plus(suffix)) ?: "缺少可用密钥材料$suffix",
        )
    }

    // ------------------------------------------------------------ certificate

    private fun parseChain(chainPem: List<String>): List<X509Certificate> {
        if (chainPem.isEmpty()) return emptyList()
        val factory = runCatching { CertificateFactory.getInstance("X.509") }.getOrNull()
            ?: return emptyList()
        val certificates = ArrayList<X509Certificate>(chainPem.size)
        for (pem in chainPem) {
            val block = Pem.decodeFirst(pem, "CERTIFICATE") ?: continue
            runCatching {
                factory.generateCertificate(ByteArrayInputStream(block.der)) as X509Certificate
            }.getOrNull()?.let { certificates += it }
        }
        return orderLeafFirst(certificates)
    }

    /**
     * Keyboxes normally list the leaf first, but a few list the root first.
     * Normalise so index 0 is always the leaf.
     */
    private fun orderLeafFirst(certificates: List<X509Certificate>): List<X509Certificate> {
        if (certificates.size < 2) return certificates
        val first = certificates.first()
        val last = certificates.last()
        val firstIsCaIssuerOfLast = first.subjectX500Principal == last.issuerX500Principal
        val lastIsIssuerOfFirst = last.subjectX500Principal == first.issuerX500Principal
        return if (firstIsCaIssuerOfLast && !lastIsIssuerOfFirst) certificates.reversed() else certificates
    }

    private class ChainResult(val valid: Boolean?, val error: String?)

    private fun verifyChain(certificates: List<X509Certificate>): ChainResult {
        if (certificates.isEmpty()) return ChainResult(null, "没有可用证书")
        var allLinksVerified = true
        for (index in 0 until certificates.size - 1) {
            val child = certificates[index]
            val parent = certificates[index + 1]
            if (child.issuerX500Principal != parent.subjectX500Principal) {
                return ChainResult(false, "证书链断裂：${child.subjectX500Principal.name} 的签发者不匹配")
            }
            // X509Certificate.verify returns Unit, so success is signalled by the
            // absence of a thrown exception rather than by a value.
            val failure = runCatching { child.verify(parent.publicKey) }.exceptionOrNull()
            if (failure != null) {
                allLinksVerified = false
                return ChainResult(false, "证书签名校验未通过（第 ${index + 1} 级）：${failure.message}")
            }
        }

        val tail = certificates.last()
        val selfIssued = tail.subjectX500Principal == tail.issuerX500Principal
        val selfSigned = selfIssued && runCatching { tail.verify(tail.publicKey) }.isSuccess

        return when {
            selfSigned -> ChainResult(true, null)
            isKnownAttestationRoot(tail) -> ChainResult(allLinksVerified, null)
            else -> ChainResult(
                null,
                "链内链接校验通过，但根证书未被识别为 Google 证明根：${tail.subjectX500Principal.name}",
            )
        }
    }

    /** Subject CN fragments of the roots Google uses for key attestation. */
    private fun isKnownAttestationRoot(certificate: X509Certificate): Boolean {
        val subject = certificate.subjectX500Principal.name.uppercase()
        return KNOWN_ROOT_MARKERS.any { subject.contains(it) }
    }

    private fun worstRevocation(certificates: List<X509Certificate>): RevocationEntry? {
        if (!revocation.isUsable) return null
        var worst: RevocationEntry? = null
        for (certificate in certificates) {
            val entry = revocation.lookup(certificate.serialNumber) ?: continue
            if (entry.status.severity > (worst?.status?.severity ?: -1)) worst = entry
        }
        return worst
    }

    private fun X509Certificate.describe(index: Int) = CertificateInfo(
        index = index,
        subject = subjectX500Principal.name,
        issuer = issuerX500Principal.name,
        serialHex = serialNumber.toString(16).uppercase(),
        notBefore = notBefore.time,
        notAfter = notAfter.time,
        isCa = basicConstraints >= 0,
    )

    /** Stable per-keybox chain fingerprint: the serials of every certificate, in chain order. */
    private fun fingerprintOf(keys: List<AnalyzedKey>): String {
        val serials = keys.flatMap { key -> key.certificates.map { it.serialHex } }
        if (serials.isEmpty()) return ""
        return Der.sha256(serials.joinToString("|").toByteArray(Charsets.UTF_8))
    }

    private companion object {
        val KNOWN_ROOT_MARKERS = listOf(
            "GOOGLE HARDWARE ATTESTATION ROOT",
            "GOOGLE ATTESTATION CA1",
            "GOOGLE ATTESTATION ROOT",
            "GTS ROOT R1",
            "GTS ROOT R2",
            "GTS ROOT R3",
            "GTS ROOT R4",
        )
    }
}
