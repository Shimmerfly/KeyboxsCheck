package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

/**
 * The library lives in a root-only folder, so everything the app does there is a
 * `su` command. The command lines and the parsing of their output are the parts
 * that can be checked without a rooted device, and they are the parts where a
 * mistake would be silent.
 */
class RootShellTest {

    private fun shell() = RootShell { File(System.getProperty("java.io.tmpdir"), "root-scratch") }

    @Test
    fun `each su dialect gets its own argument list`() {
        val shell = shell()

        assertEquals(
            listOf("su", "-c", "id"),
            shell.argv(RootShell.Invocation.COMMAND, "id"),
        )
        assertEquals(
            listOf("su", "0", "sh", "-c", "id"),
            shell.argv(RootShell.Invocation.UID_SHELL, "id"),
        )
    }

    @Test
    fun `a su outside the path is used by its full name`() {
        val shell = shell()

        assertEquals(
            listOf("/system/xbin/su", "0", "sh", "-c", "id"),
            shell.argv("/system/xbin/su", RootShell.Invocation.UID_SHELL, "id"),
        )
        // Nothing has answered yet, so the plain name is what would be tried.
        assertEquals("su", shell.binary)
        assertNull(shell.invocation)
    }

    @Test
    fun `a quoted name cannot break out of the command`() {
        val shell = shell()

        assertEquals("'plain.xml'", shell.quote("plain.xml"))
        // The only escape a single-quoted string needs: close, escape, reopen.
        assertEquals("'it'\\''s.xml'", shell.quote("it's.xml"))
        assertEquals("''", shell.quote(""))
    }

    @Test
    fun `recursive XML search quotes its path and bounds its depth`() {
        val shell = shell()

        assertEquals(
            "find '/storage/emulated/0/my folder' -maxdepth 17 -type f -iname '*.xml' -print 2>/dev/null",
            shell.findXmlCommand("/storage/emulated/0/my folder", 17),
        )
        assertEquals(
            "find '/tmp/it'\\''s' -maxdepth 0 -type f -iname '*.xml' -print 2>/dev/null",
            shell.findXmlCommand("/tmp/it's", 0),
        )
    }

    @Test
    fun `a stat line becomes a name, a size and a modification time`() {
        val shell = shell()

        val file = shell.parseListing("20261003N58052.xml|11027|1790000000")!!
        assertEquals("20261003N58052.xml", file.name)
        assertEquals(11027L, file.sizeBytes)
        // `stat -c %Y` is seconds; the rest of the app works in milliseconds.
        assertEquals(1_790_000_000_000L, file.modifiedMillis)
    }

    @Test
    fun `a file stat could not describe still has a name`() {
        val shell = shell()

        val file = shell.parseListing("keybox.xml||")!!
        assertEquals("keybox.xml", file.name)
        assertEquals(0L, file.sizeBytes)
        assertEquals(0L, file.modifiedMillis)
    }

    @Test
    fun `anything that is not one entry is ignored`() {
        val shell = shell()

        assertNull(shell.parseListing(""))
        assertNull(shell.parseListing("no pipes here"))
        assertNull(shell.parseListing("only|two"))
        assertNull(shell.parseListing("too|many|parts|here"))
        // A directory is not a keybox, and `for f in *.xml` never yields a path.
        assertNull(shell.parseListing("nested/keybox.xml|1|2"))
    }

    @Test
    fun `a listing with blank lines keeps only the real entries`() {
        val shell = shell()
        val output = "a.xml|10|100\n\n \nb.xml|20|200\n"

        assertEquals(
            listOf("a.xml", "b.xml"),
            output.lineSequence().mapNotNull { shell.parseListing(it) }.map { it.name }.toList(),
        )
    }
}
