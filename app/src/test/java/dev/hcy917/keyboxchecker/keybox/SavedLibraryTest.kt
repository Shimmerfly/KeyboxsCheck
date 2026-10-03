package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
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
    fun `listing walks the device folders and reports the path used on disk`() {
        val root = temporaryFolder.newFolder("keyboxes")
        val folder = File(root, "localdev1").apply { mkdirs() }
        File(folder, "20261001N00001.xml").writeText("<k/>")
        File(folder, "20261003R00002.xml").writeText("<k/>")
        File(root, "report.md").writeText("report")

        val listed = SavedLibrary.list(root)

        assertEquals(2, listed.size)
        assertEquals(
            listOf("localdev1/20261003R00002.xml", "localdev1/20261001N00001.xml"),
            listed.map { it.relativePath },
        )
        assertEquals("localdev1", listed[0].deviceFolder)
        assertEquals(SavedKind.REMOTE, listed[0].kind)
        assertTrue(listed.all { it.named })
        assertTrue(listed.all { it.sizeBytes > 0 })
    }

    @Test
    fun `a file dropped in by hand is listed but not treated as named`() {
        val root = temporaryFolder.newFolder("keyboxes")
        File(root, "handmade.xml").writeText("<k/>")

        val listed = SavedLibrary.list(root)

        assertEquals(1, listed.size)
        assertFalse(listed.single().named)
        assertEquals("handmade.xml", listed.single().fileName)
        assertEquals("", listed.single().serial)
        // An unnamed file still has to sort somewhere: its mtime stands in.
        assertEquals(File(root, "handmade.xml").lastModified(), listed.single().savedAtMillis)
    }

    @Test
    fun `non xml files and deeper folders are ignored`() {
        val root = temporaryFolder.newFolder("keyboxes")
        val folder = File(root, "localdev1").apply { mkdirs() }
        File(folder, "20261001N00001.xml").writeText("<k/>")
        File(folder, "notes.txt").writeText("x")
        val deeper = File(folder, "nested").apply { mkdirs() }
        File(deeper, "20261002N00002.xml").writeText("<k/>")

        val listed = SavedLibrary.list(root)

        assertEquals(listOf("localdev1/20261001N00001.xml"), listed.map { it.relativePath })
    }

    @Test
    fun `an empty or missing library lists nothing instead of failing`() {
        assertEquals(emptyList<SavedKeybox>(), SavedLibrary.list(temporaryFolder.newFolder("empty")))
        assertEquals(emptyList<SavedKeybox>(), SavedLibrary.list(File(temporaryFolder.root, "absent")))
    }

    @Test
    fun `the newest keybox comes first`() {
        val root = temporaryFolder.newFolder("keyboxes")
        listOf("20260101N00001.xml", "20261231N00002.xml", "20260615R00003.xml").forEach {
            File(root, it).writeText("<k/>")
        }

        assertEquals(
            listOf("20261231N00002.xml", "20260615R00003.xml", "20260101N00001.xml"),
            SavedLibrary.list(root).map { it.fileName },
        )
    }
}

/**
 * The export is the only way a collection leaves the device, so what it puts in
 * the zip — and what it does when a file is missing — is worth pinning down.
 */
class SavedArchiveTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `the archive carries the keyboxes and the reports that sit beside them`() {
        val root = temporaryFolder.newFolder("keyboxes")
        val folder = File(root, "localdev1").apply { mkdirs() }
        File(folder, "20261003N58052.xml").writeText("<keybox/>")
        File(root, "classification.json").writeText("{}")
        File(root, "report.md").writeText("# report")

        val listed = SavedLibrary.list(root)
        val names = SavedArchive.entries(root, listed)

        assertEquals(
            listOf("localdev1/20261003N58052.xml", "classification.json", "report.md"),
            names,
        )
    }

    @Test
    fun `reports that were never written are not announced`() {
        val root = temporaryFolder.newFolder("keyboxes")
        File(root, "20261003N58052.xml").writeText("<keybox/>")

        assertEquals(
            listOf("20261003N58052.xml"),
            SavedArchive.entries(root, SavedLibrary.list(root)),
        )
    }

    @Test
    fun `writing puts every entry in the zip with its contents intact`() {
        val root = temporaryFolder.newFolder("keyboxes")
        val folder = File(root, "localdev1").apply { mkdirs() }
        File(folder, "20261003N58052.xml").writeText("<keybox/>")
        File(root, "report.md").writeText("# report")

        val bytes = ByteArrayOutputStream()
        val written = SavedArchive.write(
            root,
            listOf("localdev1/20261003N58052.xml", "report.md"),
            bytes,
        )

        assertEquals(2, written)
        val entries = readZip(bytes.toByteArray())
        assertEquals(setOf("localdev1/20261003N58052.xml", "report.md"), entries.keys)
        assertEquals("<keybox/>", entries["localdev1/20261003N58052.xml"])
        assertEquals("# report", entries["report.md"])
    }

    @Test
    fun `a keybox deleted between listing and packing does not abort the archive`() {
        val root = temporaryFolder.newFolder("keyboxes")
        File(root, "20261003N58052.xml").writeText("<keybox/>")

        val bytes = ByteArrayOutputStream()
        val written = SavedArchive.write(
            root,
            listOf("20261003N58052.xml", "gone/20261004N00001.xml"),
            bytes,
        )

        assertEquals(1, written)
        assertEquals(setOf("20261003N58052.xml"), readZip(bytes.toByteArray()).keys)
    }

    @Test
    fun `repeated paths are packed once`() {
        val root = temporaryFolder.newFolder("keyboxes")
        File(root, "20261003N58052.xml").writeText("<keybox/>")

        val bytes = ByteArrayOutputStream()
        val written = SavedArchive.write(
            root,
            listOf("20261003N58052.xml", "20261003N58052.xml"),
            bytes,
        )

        assertEquals(1, written)
    }

    @Test
    fun `the suggested name is a date and a time, not a bare number`() {
        val name = SavedArchive.suggestedName(1_790_000_000_000L)
        assertTrue(name.startsWith("keyboxes-"))
        assertTrue(name.endsWith(".zip"))
        assertTrue(Regex("""^keyboxes-\d{8}-\d{4}\.zip$""").matches(name))
    }

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
