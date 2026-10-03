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
 * Google publishes serials as uppercase hex without leading zeros, while
 * `X509Certificate.serialNumber` is an arbitrary-precision integer and
 * hand-written keyboxes sometimes pad or lowercase the value. All candidate
 * spellings are indexed so a lookup never misses on formatting alone.
 */
object RevocationKeys {
    fun normalize(hex: String): String = hex.trim()
        .removePrefix("0x")
        .removePrefix("0X")
        .uppercase()
        .trimStart('0')
        .ifEmpty { "0" }

    fun candidates(serial: java.math.BigInteger): List<String> {
        val raw = serial.toString(16).uppercase().trimStart('0').ifEmpty { "0" }
        val candidates = LinkedHashSet<String>(4)
        candidates += raw
        candidates += raw.padStart(32, '0')
        candidates += raw.padStart(40, '0')
        candidates += serial.toString(16).uppercase()
        return candidates.toList()
    }

    /** Canonical key used when the value is already a hex string (e.g. from JSON). */
    fun canonical(hex: String): String = normalize(hex)
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
    val chainValid: Boolean?,
    val chainError: String? = null,
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
}

enum class KeyboxSource { LOCAL_PATH, TELEGRAM, MANUAL }

/**
 * A set of keyboxes that share one key identity. Device identifiers and other
 * trivially editable fields are deliberately excluded from the grouping key.
 */
data class KeyGroup(
    val keyId: String,
    val status: RevocationStatus,
    val members: List<AnalyzedKeybox>,
    val chainVariants: Int,
    val identicalChains: Boolean,
) {
    val memberCount: Int get() = members.size
    val deviceIds: List<String> get() = members.mapNotNull { it.deviceId }.distinct()
    val hasTamperedDeviceId: Boolean get() = deviceIds.size > 1
    val chainFingerprints: List<String> get() = members.map { it.chainFingerprint }.distinct()
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
    val keys: List<AnalyzedKeybox>,
    val groups: List<KeyGroup>,
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
