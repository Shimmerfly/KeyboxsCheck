package dev.hcy917.keyboxchecker.keybox

import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.Node
import java.io.ByteArrayInputStream
import java.util.Base64
import javax.xml.parsers.DocumentBuilderFactory

sealed interface ParseOutcome {
    /** The XML is a keybox and at least one key was extracted. */
    data class Ok(val keybox: Keybox) : ParseOutcome

    /** The XML parsed but does not look like a keybox at all (e.g. `strings.xml`). */
    data class NotKeybox(val reason: String) : ParseOutcome
}

/**
 * Reads the `AndroidAttestation` family of keybox files.
 *
 * The format is loose in the wild: the namespace prefix, the `DeviceID`
 * placement (attribute vs child element) and the PEM labels all vary. The
 * parser therefore matches on local names only, tolerates both roots, and
 * accepts bare base64 bodies that are missing their PEM armor.
 */
object KeyboxParser {

    private const val KEYBOX_ROOT = "AndroidAttestation"
    private const val KEYBOX_ELEMENT = "Keybox"
    private const val KEY_ELEMENT = "Key"
    private const val PRIVATE_KEY = "PrivateKey"
    private const val CERTIFICATE = "Certificate"
    private const val CERTIFICATE_CHAIN = "CertificateChain"
    private const val DEVICE_ID = "DeviceID"
    private const val DEVICE_ID_ALT = "DeviceId"

    /** Hard cap so a hostile file cannot exhaust memory through entity expansion. */
    private const val MAX_TEXT_LENGTH = 4 * 1024 * 1024

    fun parse(text: String, fileName: String? = null): ParseOutcome {
        if (text.length > MAX_TEXT_LENGTH) {
            return ParseOutcome.NotKeybox("文件过大（>4MB），已跳过")
        }
        val document = parseDocument(text)
            ?: return ParseOutcome.NotKeybox("XML 解析失败")
        val root = document.documentElement
            ?: return ParseOutcome.NotKeybox("XML 缺少根元素")

        val rootName = root.localName ?: root.nodeName
        val keyboxElements = when (rootName) {
            KEYBOX_ROOT -> directChildren(root, KEYBOX_ELEMENT)
            KEYBOX_ELEMENT -> listOf(root)
            else -> {
                val nested = root.allDescendants(KEYBOX_ELEMENT)
                if (nested.isEmpty()) {
                    return ParseOutcome.NotKeybox("根元素 <$rootName> 不是 keybox")
                }
                nested
            }
        }
        if (keyboxElements.isEmpty()) {
            return ParseOutcome.NotKeybox("未找到 <$KEYBOX_ELEMENT> 元素")
        }

        val deviceIds = LinkedHashSet<String>()
        val keys = ArrayList<KeyboxKey>()
        for (element in keyboxElements) {
            element.deviceId()?.takeIf { it.isNotBlank() }?.let { deviceIds += it }
            for (keyElement in directChildren(element, KEY_ELEMENT)) {
                keys += parseKey(keyElement, keys.size)
            }
        }
        if (keys.isEmpty()) {
            return ParseOutcome.NotKeybox("keybox 内没有任何 <$KEY_ELEMENT>")
        }

        return ParseOutcome.Ok(
            Keybox(
                deviceId = deviceIds.joinToString(KEYBOX_DEVICE_SEPARATOR).ifBlank { null },
                keys = keys,
                sourceName = fileName,
            ),
        )
    }

    /** True when the document parses as XML at all; used to tell "broken" from "unrelated". */
    fun isWellFormed(text: String): Boolean = parseDocument(text) != null

    private fun parseKey(element: Element, index: Int): KeyboxKey {
        val algorithm = attrIgnoreCase(element, "algorithm")
        val privateKeyElement = directChildren(element, PRIVATE_KEY).firstOrNull()
        val privateKeyPem = privateKeyElement?.textContent?.let {
            normalizePem(it, keyLabelFor(algorithm))
        }
        val chainElement = directChildren(element, CERTIFICATE_CHAIN).firstOrNull()
        val certificateElements = if (chainElement != null) {
            directChildren(chainElement, CERTIFICATE)
        } else {
            directChildren(element, CERTIFICATE)
        }
        val chain = certificateElements.mapNotNull { certificate ->
            certificate.textContent?.let { normalizePem(it, "CERTIFICATE") }
        }
        return KeyboxKey(
            index = index,
            algorithm = algorithm,
            privateKeyPem = privateKeyPem,
            chainPem = chain,
        )
    }

    private fun normalizePem(raw: String, label: String): String {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return trimmed
        if (Pem.looksLikePem(trimmed)) return trimmed
        val body = trimmed.filterNot { it.isWhitespace() }
        val decoded = runCatching { Base64.getMimeDecoder().decode(body) }.getOrNull()
            ?: return trimmed
        if (decoded.isEmpty()) return trimmed
        return Pem.encode(label, decoded)
    }

    private fun keyLabelFor(algorithm: String?): String = when {
        algorithm?.contains("rsa", ignoreCase = true) == true -> "RSA PRIVATE KEY"
        algorithm?.contains("ec", ignoreCase = true) == true -> "EC PRIVATE KEY"
        else -> "PRIVATE KEY"
    }

    private fun parseDocument(text: String): Document? {
        // Hardening against XXE: keybox files are untrusted input.
        //
        // Android's XML parser does not implement every Xerces feature name, and
        // asking for an unsupported one throws ParserConfigurationException. An
        // unconditional setFeature therefore made *every* keybox unparsable on a
        // real device while passing on the JVM. Each feature is now best effort,
        // and the DOCTYPE guard that actually stops external entities is applied
        // to the text itself, which works on both platforms.
        if (text.contains("<!DOCTYPE", ignoreCase = true)) return null
        val factory = DocumentBuilderFactory.newInstance()
        runCatching { factory.isNamespaceAware = true }
        runCatching { factory.isExpandEntityReferences = false }
        runCatching { factory.isXIncludeAware = false }
        setFeatureQuietly(factory, "http://apache.org/xml/features/disallow-doctype-decl", true)
        setFeatureQuietly(factory, "http://xml.org/sax/features/external-general-entities", false)
        setFeatureQuietly(factory, "http://xml.org/sax/features/external-parameter-entities", false)
        return runCatching {
            factory.newDocumentBuilder()
                .parse(ByteArrayInputStream(text.toByteArray(Charsets.UTF_8)))
        }.getOrNull()
    }

    private fun setFeatureQuietly(factory: DocumentBuilderFactory, name: String, value: Boolean) {
        runCatching { factory.setFeature(name, value) }
    }

    private fun Element.deviceId(): String? =
        attrIgnoreCase(this, DEVICE_ID)
            ?: attrIgnoreCase(this, DEVICE_ID_ALT)
            ?: directChildren(this, DEVICE_ID).firstOrNull()?.textContent?.trim()

    private fun attrIgnoreCase(element: Element, name: String): String? {
        val attributes = element.attributes
        for (index in 0 until attributes.length) {
            val attribute = attributes.item(index)
            val local = attribute.localName ?: attribute.nodeName
            if (local.equals(name, ignoreCase = true)) return attribute.nodeValue
        }
        return null
    }

    private fun directChildren(element: Element, localName: String): List<Element> {
        val result = ArrayList<Element>(2)
        val nodes = element.childNodes
        for (index in 0 until nodes.length) {
            val node = nodes.item(index)
            if (node.nodeType != Node.ELEMENT_NODE) continue
            val child = node as Element
            val name = child.localName ?: child.nodeName.substringAfterLast(':')
            if (name == localName) result += child
        }
        return result
    }

    private fun Element.allDescendants(localName: String, depth: Int = 0): List<Element> {
        if (depth > 8) return emptyList()
        val result = ArrayList<Element>(2)
        val nodes = childNodes
        for (index in 0 until nodes.length) {
            val node = nodes.item(index)
            if (node.nodeType != Node.ELEMENT_NODE) continue
            val child = node as Element
            val name = child.localName ?: child.nodeName.substringAfterLast(':')
            if (name == localName) result += child
            result += child.allDescendants(localName, depth + 1)
        }
        return result
    }

    /** Joins several DeviceIDs of one file so the UI can still show them. */
    const val KEYBOX_DEVICE_SEPARATOR = " | "
}
