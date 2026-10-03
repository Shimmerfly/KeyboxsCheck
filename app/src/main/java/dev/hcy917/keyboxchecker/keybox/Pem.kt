package dev.hcy917.keyboxchecker.keybox

import java.util.Base64

/** One `-----BEGIN X----- ... -----END X-----` block with its decoded DER body. */
class PemBlock(val label: String, val der: ByteArray) {
    override fun toString(): String = "PemBlock($label, ${der.size} bytes)"
}

/**
 * Tolerant PEM reader. Keybox files are frequently hand-edited, so the parser
 * accepts CRLF, missing trailing newlines and stray whitespace inside base64.
 */
object Pem {

    private val BLOCK = Regex(
        "-----BEGIN ([A-Za-z0-9 ]+)-----([\\s\\S]*?)-----END \\1-----",
        RegexOption.MULTILINE,
    )

    fun decodeBlocks(text: String): List<PemBlock> {
        val blocks = ArrayList<PemBlock>(2)
        for (match in BLOCK.findAll(text)) {
            val label = match.groupValues[1].trim()
            val body = match.groupValues[2]
            val der = runCatching { Base64.getMimeDecoder().decode(body) }.getOrNull() ?: continue
            if (der.isNotEmpty()) blocks += PemBlock(label, der)
        }
        return blocks
    }

    fun decodeFirst(text: String, vararg labels: String): PemBlock? {
        val all = decodeBlocks(text)
        if (labels.isEmpty()) return all.firstOrNull()
        val wanted = labels.map { it.uppercase() }.toSet()
        return all.firstOrNull { it.label.uppercase() in wanted } ?: all.firstOrNull()
    }

    fun encode(label: String, der: ByteArray): String {
        val base64 = Base64.getEncoder().encodeToString(der)
        val sb = StringBuilder()
        sb.append("-----BEGIN ").append(label).append("-----\n")
        var index = 0
        while (index < base64.length) {
            val end = minOf(index + 64, base64.length)
            sb.append(base64, index, end).append('\n')
            index = end
        }
        sb.append("-----END ").append(label).append("-----\n")
        return sb.toString()
    }

    fun looksLikePem(text: String): Boolean = text.contains("-----BEGIN ")

    /** Best-effort label for a key block, used only for diagnostics. */
    fun labelOfKeyBlock(text: String): String? = decodeBlocks(text)
        .firstOrNull { it.label.uppercase().contains("PRIVATE KEY") }
        ?.label
}
