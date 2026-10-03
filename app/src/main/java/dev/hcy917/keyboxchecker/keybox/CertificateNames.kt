package dev.hcy917.keyboxchecker.keybox

/**
 * Readable rendering of X.500 names.
 *
 * Real keyboxes do not carry common names. Google's attestation roots are
 * identified by their `serialNumber` attribute — the Keymaster hardware
 * attestation root is `serialNumber=f92009e853b6b045` — and
 * `X500Principal.getName()` renders those as raw DER blobs such as
 * `2.5.4.5=#131066393230303965383533623662303435`. Names are decoded here so a
 * report reads `serialNumber=f92009e853b6b045` instead.
 *
 * Deciding *which* root a chain ends in is [RootKeys]' job: it compares pinned
 * public keys, the way both reference projects do.
 */
object CertificateNames {

    /** OIDs that show up in Android attestation chains. */
    private val SHORT_NAMES = mapOf(
        "2.5.4.3" to "CN",
        "2.5.4.4" to "SN",
        "2.5.4.5" to "serialNumber",
        "2.5.4.6" to "C",
        "2.5.4.7" to "L",
        "2.5.4.8" to "ST",
        "2.5.4.9" to "street",
        "2.5.4.10" to "O",
        "2.5.4.11" to "OU",
        "2.5.4.12" to "title",
        "2.5.4.42" to "givenName",
        "0.9.2342.19200300.100.1.25" to "DC",
        "1.2.840.113549.1.9.1" to "emailAddress",
    )

    /** One `oid=value` pair of a distinguished name. */
    data class Attribute(val oid: String, val name: String, val value: String)

    /** Splits an RFC 2253 name into attributes, decoding `#`-encoded values. */
    fun attributes(name: String): List<Attribute> {
        if (name.isBlank()) return emptyList()
        val attributes = ArrayList<Attribute>(4)
        val current = StringBuilder()
        var quoted = false
        var escaped = false
        for (character in name) {
            when {
                escaped -> { current.append(character); escaped = false }
                character == '\\' -> { current.append(character); escaped = true }
                character == '"' -> { quoted = !quoted; current.append(character) }
                character == ',' && !quoted -> {
                    parseAttribute(current.toString())?.let { attributes += it }
                    current.setLength(0)
                }
                else -> current.append(character)
            }
        }
        parseAttribute(current.toString())?.let { attributes += it }
        return attributes
    }

    /** `serialNumber=f92009e853b6b045, title=TEE` instead of raw DER blobs. */
    fun readable(name: String): String {
        val attributes = attributes(name)
        if (attributes.isEmpty()) return name
        return attributes.joinToString(", ") { "${it.name}=${it.value}" }
    }

    private fun parseAttribute(raw: String): Attribute? {
        val text = raw.trim()
        if (text.isEmpty()) return null
        val separator = text.indexOf('=')
        if (separator <= 0) return null
        val oid = text.substring(0, separator).trim()
        val value = text.substring(separator + 1).trim()
        return Attribute(
            oid = oid,
            name = SHORT_NAMES[oid] ?: oid,
            value = decodeValue(value),
        )
    }

    private fun decodeValue(value: String): String {
        if (!value.startsWith("#")) return value.trim('"')
        val bytes = hexToBytes(value.substring(1)) ?: return value
        return decodeDerString(bytes) ?: value
    }

    private fun decodeDerString(bytes: ByteArray): String? {
        val tlv = runCatching { Der.parseTlv(bytes) }.getOrNull() ?: return null
        val content = runCatching { Der.content(bytes, tlv) }.getOrNull() ?: return null
        return when (tlv.tag) {
            0x0C -> String(content, Charsets.UTF_8)
            0x12, 0x13, 0x16, 0x1A -> String(content, Charsets.US_ASCII)
            0x14 -> String(content, Charsets.ISO_8859_1)
            0x1E -> String(content, Charsets.UTF_16BE)
            else -> null
        }
    }

    private fun hexToBytes(hex: String): ByteArray? {
        if (hex.isEmpty() || hex.length % 2 != 0) return null
        val out = ByteArray(hex.length / 2)
        for (index in out.indices) {
            val high = Character.digit(hex[index * 2], 16)
            val low = Character.digit(hex[index * 2 + 1], 16)
            if (high < 0 || low < 0) return null
            out[index] = ((high shl 4) or low).toByte()
        }
        return out
    }
}
