package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale
import java.util.zip.ZipInputStream

/**
 * The library is what the "saved" section shows, so the naming rule it decodes
 * has to round-trip exactly what [KeyboxRepository.nextKeyboxName] writes.
 */
class SavedLibraryTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    // ------------------------------------------------------------------ names

    @Test
    fun `a saved name decodes into a day, a kind and five digits`() {
        val parsed = SavedLibrary.parseName("20261003N58052.xml")
        assertEquals("58052", parsed!!.serial)
        assertEquals(SavedKind.LOCAL, parsed.kind)

        val calendar = Calendar.getInstance().apply { timeInMillis = parsed.dateMillis }
        assertEquals(2026, calendar.get(Calendar.YEAR))
        assertEquals(Calendar.OCTOBER, calendar.get(Calendar.MONTH))
        assertEquals(3, calendar.get(Calendar.DAY_OF_MONTH))
        assertEquals(0, calendar.get(Calendar.HOUR_OF_DAY))
        assertEquals(0, calendar.get(Calendar.MINUTE))
    }

    @Test
    fun `an R marker means the keybox was remotely provisioned`() {
        assertEquals(SavedKind.REMOTE, SavedLibrary.parseName("20261003R00001.xml")!!.kind)
        // The marker is written uppercase but accepted either way.
        assertEquals(SavedKind.REMOTE, SavedLibrary.parseName("20261003r00001.xml")!!.kind)
    }

    @Test
    fun `anything that does not follow the rule is not claimed as a name`() {
        assertNull(SavedLibrary.parseName("kb.xml"))
        assertNull(SavedLibrary.parseName("20261003N5805.xml"))
        assertNull(SavedLibrary.parseName("20261003N58052.pem"))
        assertNull(SavedLibrary.parseName("20261003X58052.xml"))
        assertNull(SavedLibrary.parseName("20261003N580A2.xml"))
    }

    @Test
    fun `a date that never happened is rejected rather than rolled over`() {
        // Calendar would silently turn this into March 3rd; the library must not.
        assertNull(SavedLibrary.parseName("20260231N00001.xml"))
        assertNull(SavedLibrary.parseName("20261301N00001.xml"))
    }

    @Test
    fun `a name produced by the save path decodes back to the same day`() {
        val now = 1_790_000_000_000L
        val stored = SimpleDateFormat("yyyyMMdd", Locale.US).format(java.util.Date(now))
        val parsed = SavedLibrary.parseName("${stored}N00007.xml")!!
        val expected = Calendar.getInstance().apply { timeInMillis = now }
        val actual = Calendar.getInstance().apply { timeInMillis = parsed.dateMillis }
        assertEquals(expected.get(Calendar.YEAR), actual.get(Calendar.YEAR))
        assertEquals(expected.get(Calendar.MONTH), actual.get(Calendar.MONTH))
        assertEquals(expected.get(Calendar.DAY_OF_MONTH), actual.get(Calendar.DAY_OF_MONTH))
    }

    // ----------------------------------------------------------------- listing

    @Test
    fun `the folder listing becomes one entry per keybox, newest first`() {
        val listed = SavedLibrary.of(
            listOf(
                file("20261001N00001.xml"),
                file("20261003R00002.xml"),
                file("20261002N00003.xml"),
            ),
        )

        assertEquals(
            listOf("20261003R00002.xml", "20261002N00003.xml", "20261001N00001.xml"),
            listed.map { it.relativePath },
        )
        assertEquals(SavedKind.REMOTE, listed[0].kind)
        assertTrue(listed.all { it.named })
    }

    @Test
    fun `keyboxes saved on the same day are ordered by their five digits`() {
        val listed = SavedLibrary.of(
            listOf(file("20261003N12000.xml"), file("20261003N99000.xml"), file("20261003N00001.xml")),
        )

        assertEquals(
            listOf("20261003N99000.xml", "20261003N12000.xml", "20261003N00001.xml"),
            listed.map { it.fileName },
        )
    }

    @Test
    fun `a file dropped in by hand is listed but not treated as named`() {
        val listed = SavedLibrary.of(listOf(file("keybox.xml", modifiedMillis = 1_700_000_000_000L)))

        assertEquals(1, listed.size)
        assertFalse(listed.single().named)
        assertEquals("keybox.xml", listed.single().fileName)
        assertEquals("", listed.single().serial)
        // An unnamed file still has to sort somewhere: its mtime stands in.
        assertEquals(1_700_000_000_000L, listed.single().savedAtMillis)
    }

    @Test
    fun `anything that is not an xml file stays out of the library`() {
        assertFalse(SavedLibrary.isKeyboxFile("notes.txt"))
        assertFalse(SavedLibrary.isKeyboxFile("classification.json"))
        assertTrue(SavedLibrary.isKeyboxFile("20261003N58052.XML"))

        val listed = SavedLibrary.of(
            listOf(file("20261003N58052.xml"), file("notes.txt"), file("report.md")),
        )

        assertEquals(listOf("20261003N58052.xml"), listed.map { it.fileName })
    }

    @Test
    fun `an empty listing is an empty library`() {
        assertEquals(emptyList<SavedKeybox>(), SavedLibrary.of(emptyList()))
    }

    @Test
    fun `the size comes straight from the listing`() {
        val listed = SavedLibrary.of(listOf(file("20261003N58052.xml", sizeBytes = 4096L)))
        assertEquals(4096L, listed.single().sizeBytes)
    }

    private fun file(
        name: String,
        sizeBytes: Long = 1024L,
        modifiedMillis: Long = 0L,
    ) = SavedFile(name = name, sizeBytes = sizeBytes, modifiedMillis = modifiedMillis)
}

/**
 * The export is the only way a collection leaves the device, so what it puts in
 * the zip — and what it does when an entry is unusable — is worth pinning down.
 */
class SavedArchiveTest {

    @Test
    fun `writing puts every keybox in the zip with its contents intact`() {
        val bytes = ByteArrayOutputStream()
        val written = SavedArchive.write(
            listOf(
                item("20261003N58052.xml", "<keybox/>"),
                item("20261004N00001.xml", "<keybox id='2'/>"),
            ),
            bytes,
        )

        assertEquals(2, written)
        val entries = readZip(bytes.toByteArray())
        assertEquals(setOf("20261003N58052.xml", "20261004N00001.xml"), entries.keys)
        assertEquals("<keybox/>", entries["20261003N58052.xml"])
        assertEquals("<keybox id='2'/>", entries["20261004N00001.xml"])
    }

    @Test
    fun `repeated paths are packed once`() {
        val bytes = ByteArrayOutputStream()
        val written = SavedArchive.write(
            listOf(item("20261003N58052.xml", "<keybox/>"), item("20261003N58052.xml", "<keybox/>")),
            bytes,
        )

        assertEquals(1, written)
    }

    @Test
    fun `an entry with no name is skipped instead of aborting the archive`() {
        val bytes = ByteArrayOutputStream()
        val written = SavedArchive.write(
            listOf(item("", "<keybox/>"), item("20261003N58052.xml", "<keybox/>")),
            bytes,
        )

        assertEquals(1, written)
        assertEquals(setOf("20261003N58052.xml"), readZip(bytes.toByteArray()).keys)
    }

    @Test
    fun `an empty collection still writes a valid, empty zip`() {
        val bytes = ByteArrayOutputStream()
        assertEquals(0, SavedArchive.write(emptyList(), bytes))
        assertEquals(emptyMap<String, String>(), readZip(bytes.toByteArray()))
    }

    @Test
    fun `the suggested name is a date and a time, not a bare number`() {
        val name = SavedArchive.suggestedName(1_790_000_000_000L)
        assertTrue(name.startsWith("keyboxes-"))
        assertTrue(name.endsWith(".zip"))
        assertTrue(Regex("""^keyboxes-\d{8}-\d{4}\.zip$""").matches(name))
    }

    private fun item(path: String, text: String) = SavedArchive.Item(
        path = path,
        modifiedMillis = 0L,
        bytes = text.toByteArray(Charsets.UTF_8),
    )

    /** Reads a zip back into entry name -> text content. */
    private fun readZip(bytes: ByteArray): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        ZipInputStream(bytes.inputStream()).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                out[entry.name] = zip.readBytes().toString(Charsets.UTF_8)
                zip.closeEntry()
            }
        }
        return out
    }
}
