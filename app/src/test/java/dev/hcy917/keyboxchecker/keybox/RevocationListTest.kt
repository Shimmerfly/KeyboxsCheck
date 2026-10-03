package dev.hcy917.keyboxchecker.keybox

import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.math.BigInteger

/**
 * Serial formatting is the one thing that reliably breaks revocation matching,
 * and a table we could not reach must never be mistaken for a clean table.
 */
class RevocationListTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private val sampleJson = """
        {
          "entries": {
            "0000ABCD": { "status": "REVOKED", "reason": "KEY_COMPROMISE" },
            "beef": { "status": "SUSPENDED" },
            "1234": { "status": "WAT" }
          },
          "expires": "2099-01-01T00:00:00Z"
        }
    """.trimIndent()

    private fun loader(
        file: File?,
        fetcher: HttpTextFetcher,
        now: () -> Long = System::currentTimeMillis,
    ) = RevocationListLoader(
        client = OkHttpClient(),
        cacheFile = file,
        urls = listOf("https://example.invalid/status"),
        nowMillis = now,
        fetcher = fetcher,
    )

    @Test
    fun `entries are indexed under every spelling of the serial`() {
        val entries = RevocationList.parseEntries(sampleJson)
        assertTrue(entries.isNotEmpty())
        val snapshot = RevocationSnapshot(entries, RevocationSource.NETWORK, 0L)

        assertEquals(RevocationStatus.REVOKED, snapshot.lookup(BigInteger("ABCD", 16))?.status)
        assertEquals(RevocationStatus.REVOKED, snapshot.lookup(BigInteger("00000000ABCD", 16))?.status)
        assertEquals(RevocationStatus.REVOKED, snapshot.lookup(BigInteger("0000ABCD", 16))?.status)
        assertEquals(RevocationStatus.SUSPENDED, snapshot.lookup(BigInteger("BEEF", 16))?.status)
        assertNotNull(snapshot.lookup(BigInteger("BEEF", 16)))
    }

    @Test
    fun `an unknown status degrades to unknown instead of valid`() {
        val entries = RevocationList.parseEntries(sampleJson)
        val snapshot = RevocationSnapshot(entries, RevocationSource.NETWORK, 0L)
        assertEquals(RevocationStatus.UNKNOWN, snapshot.lookup(BigInteger("1234", 16))?.status)
        assertNull(snapshot.lookup(BigInteger("FFFF", 16)))
        assertNull(snapshot.lookup(null))
    }

    @Test
    fun `status and expires helpers are tolerant`() {
        assertEquals(RevocationStatus.REVOKED, RevocationList.statusOf("revoked"))
        assertEquals(RevocationStatus.SUSPENDED, RevocationList.statusOf(" Suspended "))
        assertEquals(RevocationStatus.UNKNOWN, RevocationList.statusOf(""))
        assertEquals(RevocationStatus.UNKNOWN, RevocationList.statusOf("bogus"))
        assertEquals("2099-01-01T00:00:00Z", RevocationList.parseExpires(sampleJson))
        assertNull(RevocationList.parseExpires("not json"))
        assertTrue(RevocationList.looksLikeStatusDocument(sampleJson))
        assertFalse(RevocationList.looksLikeStatusDocument("{}"))
    }

    @Test
    fun `an empty table is usable and reports nothing revoked`() {
        val entries = RevocationList.parseEntries("""{"entries":{}}""")
        val snapshot = RevocationSnapshot(entries, RevocationSource.NETWORK, 0L)
        assertTrue(snapshot.isUsable)
        assertNull(snapshot.lookup(BigInteger.ONE))
    }

    @Test
    fun `a successful fetch is served from the network and cached`() {
        val cache = File(temporaryFolder.newFolder(), "revocation.json")
        val snapshot = loader(cache, HttpTextFetcher { sampleJson }).load()
        assertEquals(RevocationSource.NETWORK, snapshot.source)
        assertNull(snapshot.error)
        assertEquals(RevocationStatus.REVOKED, snapshot.lookup(BigInteger("ABCD", 16))?.status)
        assertTrue(cache.isFile)
        assertTrue(cache.readText().contains("KEY_COMPROMISE"))
    }

    @Test
    fun `a fresh cache is reused without touching the network`() {
        val cache = File(temporaryFolder.newFolder(), "revocation.json")
        cache.writeText(sampleJson)
        cache.setLastModified(System.currentTimeMillis())
        val snapshot = loader(cache, HttpTextFetcher { error("the network must not be used") }).load()
        assertEquals(RevocationSource.CACHE, snapshot.source)
        assertNull(snapshot.error)
        assertEquals(RevocationStatus.REVOKED, snapshot.lookup(BigInteger("ABCD", 16))?.status)
    }

    @Test
    fun `an expired cache is refetched`() {
        val cache = File(temporaryFolder.newFolder(), "revocation.json")
        cache.writeText("""{"entries":{"AAAA":{"status":"REVOKED"}},"expires":"2000-01-01T00:00:00Z"}""")
        cache.setLastModified(System.currentTimeMillis())
        val snapshot = loader(cache, HttpTextFetcher { sampleJson }).load()
        assertEquals(RevocationSource.NETWORK, snapshot.source)
        assertEquals(RevocationStatus.REVOKED, snapshot.lookup(BigInteger("ABCD", 16))?.status)
    }

    @Test
    fun `without a cache an unreachable table yields unknown not valid`() {
        val snapshot = loader(null, HttpTextFetcher { throw java.io.IOException("offline") }).load()
        assertEquals(RevocationSource.NONE, snapshot.source)
        assertFalse(snapshot.isUsable)
        assertNotNull(snapshot.error)
        assertTrue(snapshot.entries.isEmpty())
    }

    @Test
    fun `a stale cache is used but flagged`() {
        val cache = File(temporaryFolder.newFolder(), "revocation.json")
        // No `expires` member, so freshness falls back to the TTL and mtime.
        cache.writeText("""{"entries":{"0000ABCD":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}""")
        cache.setLastModified(0L)
        val snapshot = loader(cache, HttpTextFetcher { throw java.io.IOException("offline") }).load()
        assertEquals(RevocationSource.CACHE, snapshot.source)
        assertTrue(snapshot.isUsable)
        assertNotNull(snapshot.error)
        assertEquals(RevocationStatus.REVOKED, snapshot.lookup(BigInteger("ABCD", 16))?.status)
    }

    @Test
    fun `a body that is not a status document is rejected`() {
        val snapshot = loader(null, HttpTextFetcher { """{"error":"nope"}""" }).load()
        assertEquals(RevocationSource.NONE, snapshot.source)
        assertNotNull(snapshot.error)
    }

    @Test
    fun `an empty cache file is ignored`() {
        val cache = File(temporaryFolder.newFolder(), "revocation.json")
        cache.writeText("""{"entries":{}}""")
        val snapshot = loader(cache, HttpTextFetcher { sampleJson }).load()
        assertEquals(RevocationSource.NETWORK, snapshot.source)
    }
}
