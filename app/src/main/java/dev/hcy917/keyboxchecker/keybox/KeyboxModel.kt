package dev.hcy917.keyboxchecker.keybox

import java.security.cert.X509Certificate

/** Google attestation status of a single certificate serial number. */
enum class RevocationStatus {
    /** Present in the status list with `REVOKED`. */
    REVOKED,

    /** Present with `SUSPENDED`. */
    SUSPENDED,

    /** Looked up successfully and absent from the list. */
    VALID,

    /** The status list could not be consulted, or the serial could not be resolved. */
    UNKNOWN;

    /** Severity rank used when a key carries several certificates. */
    val severity: Int
        get() = when (this) {
            REVOKED -> 3
            SUSPENDED -> 2
            UNKNOWN -> 1
            VALID -> 0
        }
}

enum class RevocationSource { NETWORK, CACHE, NONE }

/** One entry of `https://android.googleapis.com/attestation/status`. */
data class RevocationEntry(
    val serialHex: String,
    val status: RevocationStatus,
    val reason: String? = null,
    val expires: String? = null,
)

data class RevocationSnapshot(
    val entries: Map<String, RevocationEntry>,
    val source: RevocationSource,
    val fetchedAtMillis: Long,
    val expires: String? = null,
    val error: String? = null,
) {
    val isUsable: Boolean get() = source != RevocationSource.NONE

    /**
     * Number of distinct published entries.
     *
     * [entries] is a lookup index that holds several spellings of every serial,
     * so its size overstates what the publisher actually listed.
     */
    val entryCount: Int get() = entries.values.toSet().size

    fun lookup(serial: java.math.BigInteger?): RevocationEntry? {
        if (serial == null) return null
        return RevocationKeys.candidates(serial).firstNotNullOfOrNull { entries[it] }
    }

    companion object {
        val EMPTY = RevocationSnapshot(
            entries = emptyMap(),
            source = RevocationSource.NONE,
            fetchedAtMillis = 0L,
        )
    }
}

/**
 * Normalisation of certificate serial numbers.
 *
 * The published status list is not written in one encoding: measured against the
 * live list, 780 of 1759 entries are lowercase hex (`c35747a084470c3135aeefe2b8d40cd6`,
 * the 128-bit serials of hardware attestation certificates) while the remaining
 * 979 are plain decimal (`224403031710863989`). A certificate serial is an
 * arbitrary-precision integer, so every lookup tries both readings — hex and
 * decimal — plus padded and trimmed spellings, and never misses on formatting
 * alone.
 */
object RevocationKeys {
    /** Strips decoration (`0x`, `:`, spaces, dashes) and upper-cases the result. */
    fun canonical(raw: String): String = raw.trim()
        .removePrefix("0x")
        .removePrefix("0X")
        .filterNot { it == ':' || it == ' ' || it == '-' || it == '_' }
        .uppercase()

    /** Canonical form with leading zeros removed, for hex-keyed entries. */
    fun normalize(raw: String): String = canonical(raw).trimStart('0').ifEmpty { "0" }

    /** Decimal reading, or null when the value contains non-digits. */
    fun decimal(raw: String): String? {
        val canonical = canonical(raw)
        if (canonical.isEmpty() || !canonical.all { it in '0'..'9' }) return null
        return canonical.trimStart('0').ifEmpty { "0" }
    }

    /** Every spelling a serial could have been published under. */
    fun candidates(serial: java.math.BigInteger?): List<String> {
        if (serial == null) return emptyList()
        val hex = serial.toString(16).uppercase()
        val trimmed = hex.trimStart('0').ifEmpty { "0" }
        val decimal = serial.toString(10)
        return LinkedHashSet<String>(6).apply {
            add(trimmed)
            add(hex)
            add(decimal)
            add(hex.padStart(32, '0'))
            add(hex.padStart(40, '0'))
            add(decimal.trimStart('0').ifEmpty { "0" })
        }.toList()
    }
}

// ------------------------------------------------------------------ parsing

/** A single `<Key>` element of a keybox file. */
data class KeyboxKey(
    val index: Int,
    val algorithm: String?,
    val privateKeyPem: String?,
    val chainPem: List<String>,
) {
    val declaredAlgorithm: String
        get() = algorithm?.trim()?.lowercase().orEmpty()
}

/** A parsed keybox: one device identity plus one or more attestation keys. */
data class Keybox(
    val deviceId: String?,
    val keys: List<KeyboxKey>,
    val sourceName: String? = null,
)

/** Reason an XML file could not be read as a keybox. */
data class ParseFailure(val reason: String)

// ----------------------------------------------------------------- analysis

data class CertificateInfo(
    val index: Int,
    val subject: String,
    val issuer: String,
    val serialHex: String,
    val notBefore: Long,
    val notAfter: Long,
    val isCa: Boolean,
) {
    fun isExpired(nowMillis: Long): Boolean = nowMillis > notAfter
}

/** Provenance of a key identity hash, most trustworthy first. */
enum class IdentitySource { PRIVATE_KEY, LEAF_CERTIFICATE, RAW_PEM }

data class AnalyzedKey(
    val index: Int,
    val algorithm: String,
    val keyId: String,
    val identitySource: IdentitySource,
    val identityError: String? = null,
    val status: RevocationStatus,
    val matchedSerial: String? = null,
    val revocationReason: String? = null,
    /** Link verification along the chain, the way KeyboxChecker performs it. */
    val chainValid: Boolean?,
    val chainError: String? = null,
    /** Readable subject of the chain's root certificate. */
    val chainRoot: String? = null,
    /** Which pinned attestation root terminates the chain. */
    val rootStatus: RootStatus = RootStatus.NULL,
    /** Remote Key Provisioning: pinned RKP root, or the ProvisioningInfo extension. */
    val remoteProvisioned: Boolean = false,
    /** Whether the private key really belongs to the leaf certificate. */
    val privateKeyMatchesLeaf: Boolean? = null,
    /** True when any certificate of the chain is outside its validity period. */
    val expired: Boolean = false,
    val expiredCertificates: List<Int> = emptyList(),
    /** KeyboxChecker flags chains carrying more than three certificates. */
    val tooManyCertificates: Boolean = false,
    val certificates: List<CertificateInfo> = emptyList(),
) {
    val isRevoked: Boolean get() = status == RevocationStatus.REVOKED
}

/** One XML file after analysis. */
data class AnalyzedKeybox(
    val fileName: String,
    val contentSha256: String,
    val deviceId: String?,
    val keys: List<AnalyzedKey>,
    val chainFingerprint: String,
    val source: KeyboxSource,
    val parseError: String? = null,
    /** Set when another file in the same scan has byte-identical content. */
    val duplicateOf: String? = null,
) {
    val primaryKeyId: String? get() = keys.firstOrNull()?.keyId
    val status: RevocationStatus
        get() = keys.maxByOrNull { it.status.severity }?.status ?: RevocationStatus.UNKNOWN
    val isConfirmed: Boolean get() = parseError == null && keys.isNotEmpty()

    /** True when every key of this keybox was remotely provisioned. */
    val remoteProvisioned: Boolean
        get() = keys.isNotEmpty() && keys.all { it.remoteProvisioned }

    /** True when any certificate of any chain is outside its validity period. */
    val expired: Boolean get() = keys.any { it.expired }
}

enum class KeyboxSource { LOCAL_PATH, MANUAL }

/**
 * Two keyboxes that carry the same key material.
 *
 * Files are listed one by one, never merged into a group, so a repeated key is
 * reported as its own fact instead of hiding which file it came from. This is
 * what the save step consults before writing anything to the library.
 */
data class RepeatedKey(
    val keyId: String,
    val fileNames: List<String>,
) {
    val count: Int get() = fileNames.size
}

/** Fields the classifier intentionally ignores because they are user editable. */
val IGNORED_IDENTITY_FIELDS: List<String> = listOf(
    "DeviceID",
    "attestationApplicationId",
    "attestationIdBrand",
    "attestationIdDevice",
    "attestationIdProduct",
    "attestationIdSerial",
    "attestationIdImei",
    "attestationIdMeid",
    "attestationIdManufacturer",
    "attestationIdModel",
    "NumberOfKeyboxes",
    "Key@algorithm",
)

data class ScanStats(
    val filesScanned: Int = 0,
    val xmlFiles: Int = 0,
    val confirmedKeyboxes: Int = 0,
    val notKeybox: Int = 0,
    val unreadable: Int = 0,
    val duplicates: Int = 0,
)

data class ScanReport(
    val inputDescription: String,
    val generatedAtMillis: Long,
    val renderedAtIso: String,
    /** Every confirmed keybox, one entry per file, worst status first. */
    val keys: List<AnalyzedKeybox>,
    /** Keys carried by more than one of these files; empty when all differ. */
    val repeatedKeys: List<RepeatedKey>,
    val stats: ScanStats,
    val revocation: RevocationSnapshot,
)

data class ScanProgress(
    val processed: Int = 0,
    val total: Int = 0,
    val currentName: String = "",
    val phase: String = "",
) {
    val fraction: Float
        get() = if (total <= 0) 0f else (processed.toFloat() / total.toFloat()).coerceIn(0f, 1f)
}
