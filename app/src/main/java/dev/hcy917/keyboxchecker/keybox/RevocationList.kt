package dev.hcy917.keyboxchecker.keybox

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

/** Pluggable text fetcher so the cache/refresh logic is testable without a network. */
fun interface HttpTextFetcher {
    fun get(url: String): String
}

/**
 * Reader for the Google attestation revocation list:
 * `https://android.googleapis.com/attestation/status`.
 *
 * The response is a JSON object of `{ "<serial>": { "status": ..., "reason": ... } }`.
 *
 * Serial formatting varies far more than the documentation suggests. Measured
 * against the live document, 780 of 1759 entries are lowercase 128-bit hex
 * (`c35747a084470c3135aeefe2b8d40cd6`) and 979 are plain decimal
 * (`224403031710863989`). Every entry is therefore indexed under its canonical,
 * trimmed and decimal spellings, and lookups try all of them.
 */
object RevocationList {

    const val DEFAULT_URL = "https://android.googleapis.com/attestation/status"

    /** Refresh window when the document carries no usable `expires`. */
    const val DEFAULT_TTL_MILLIS = 24L * 60L * 60L * 1000L

    /** Parses the list body. Unknown statuses degrade to [RevocationStatus.UNKNOWN]. */
    fun parseEntries(json: String): Map<String, RevocationEntry> {
        val root = JSONObject(json)
        val entriesObject = root.optJSONObject("entries") ?: return emptyMap()
        val result = LinkedHashMap<String, RevocationEntry>(entriesObject.length() * 2)
        for (serial in entriesObject.keys()) {
            val entry = entriesObject.optJSONObject(serial) ?: continue
            val status = statusOf(entry.optString("status", ""))
            val record = RevocationEntry(
                serialHex = RevocationKeys.normalize(serial),
                status = status,
                reason = entry.optString("reason").takeIf { it.isNotBlank() && it != "null" },
                expires = entry.optString("expires").takeIf { it.isNotBlank() && it != "null" },
            )
            // Indexed under every spelling a lookup might produce for a serial:
            // canonical, leading-zero trimmed, as-written and decimal.
            result[RevocationKeys.canonical(serial)] = record
            result[RevocationKeys.normalize(serial)] = record
            result[serial.trim()] = record
            result[serial.trim().uppercase()] = record
            RevocationKeys.decimal(serial)?.let { result[it] = record }
        }
        return result
    }

    fun parseExpires(json: String): String? = runCatching {
        JSONObject(json).optString("expires").takeIf { it.isNotBlank() && it != "null" }
    }.getOrNull()

    fun statusOf(raw: String): RevocationStatus = when (raw.trim().uppercase()) {
        "REVOKED" -> RevocationStatus.REVOKED
        "SUSPENDED" -> RevocationStatus.SUSPENDED
        "" -> RevocationStatus.UNKNOWN
        else -> RevocationStatus.UNKNOWN
    }

    /** True when the response has no `entries` member at all (shape mismatch). */
    fun looksLikeStatusDocument(json: String): Boolean =
        runCatching { JSONObject(json).has("entries") }.getOrDefault(false)
}

/**
 * Loads the revocation list with an on-disk cache.
 *
 * Failure policy: a usable cache is always preferred over reporting `VALID`
 * for a key we simply could not check. With no cache at all, every key becomes
 * [RevocationStatus.UNKNOWN] rather than silently appearing clean.
 */
class RevocationListLoader(
    private val client: OkHttpClient,
    private val cacheFile: File?,
    private val urls: List<String> = listOf(RevocationList.DEFAULT_URL),
    private val ttlMillis: Long = RevocationList.DEFAULT_TTL_MILLIS,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val fetcher: HttpTextFetcher = OkHttpTextFetcher(client),
) {

    fun load(forceRefresh: Boolean = false): RevocationSnapshot {
        val cached = readCache()
        if (!forceRefresh && cached != null && !isStale(cached)) {
            return cached.snapshot.copy(source = RevocationSource.CACHE)
        }

        val errors = ArrayList<String>(2)
        for (url in urls) {
            val body = runCatching { fetcher.get(url) }
                .onFailure { errors += "${url}: ${it.message ?: it::class.java.simpleName}" }
                .getOrNull()
                ?: continue

            val entries = runCatching { RevocationList.parseEntries(body) }
                .onFailure { errors += "${url}: JSON 解析失败（${it.message}）" }
                .getOrNull()
                ?: continue

            if (entries.isEmpty() && !RevocationList.looksLikeStatusDocument(body)) {
                errors += "$url: 响应不是吊销列表"
                continue
            }

            val expires = RevocationList.parseExpires(body)
            val snapshot = RevocationSnapshot(
                entries = entries,
                source = RevocationSource.NETWORK,
                fetchedAtMillis = nowMillis(),
                expires = expires,
            )
            writeCache(body, snapshot.fetchedAtMillis)
            return snapshot
        }

        // Network unusable: fall back to whatever cache exists, clearly marked stale.
        if (cached != null) {
            return cached.snapshot.copy(
                source = RevocationSource.CACHE,
                error = errors.joinToString("; ").ifBlank { "刷新失败，使用本地缓存" },
            )
        }
        return RevocationSnapshot.EMPTY.copy(error = errors.joinToString("; ").ifBlank { "无法获取吊销列表" })
    }

    private fun isStale(cached: CachedList): Boolean {
        val now = nowMillis()
        val expiresMillis = cached.snapshot.expires?.let(::parseIsoMillis)
        if (expiresMillis != null) return now > expiresMillis
        return now - cached.snapshot.fetchedAtMillis > ttlMillis
    }

    private fun readCache(): CachedList? {
        val file = cacheFile ?: return null
        if (!file.isFile) return null
        return runCatching {
            val json = file.readText()
            val entries = RevocationList.parseEntries(json)
            if (entries.isEmpty()) return null
            CachedList(
                RevocationSnapshot(
                    entries = entries,
                    source = RevocationSource.CACHE,
                    fetchedAtMillis = file.lastModified(),
                    expires = RevocationList.parseExpires(json),
                ),
            )
        }.getOrNull()
    }

    private fun writeCache(body: String, fetchedAt: Long) {
        val file = cacheFile ?: return
        runCatching {
            file.parentFile?.mkdirs()
            file.writeText(body)
            file.setLastModified(fetchedAt)
        }
    }

    private class CachedList(val snapshot: RevocationSnapshot)

    companion object {
        /** Lenient RFC-3339 (`2025-04-01T00:00:00Z`) parsing without extra dependencies. */
        fun parseIsoMillis(value: String): Long? = runCatching {
            java.time.Instant.parse(value).toEpochMilli()
        }.recoverCatching {
            java.time.OffsetDateTime.parse(value).toInstant().toEpochMilli()
        }.getOrNull()
    }
}

/** Default fetcher; OkHttp decompresses the gzip response transparently. */
class OkHttpTextFetcher(private val client: OkHttpClient) : HttpTextFetcher {
    override fun get(url: String): String {
        val request = Request.Builder()
            .url(url)
            .header("Accept", "application/json")
            .header("Cache-Control", "no-cache")
            .get()
            .build()
        client.newBuilder()
            .callTimeout(30, TimeUnit.SECONDS)
            .build()
            .newCall(request)
            .execute()
            .use { response ->
                if (!response.isSuccessful) {
                    throw java.io.IOException("HTTP ${response.code} for $url")
                }
                return response.body.string()
            }
    }
}
