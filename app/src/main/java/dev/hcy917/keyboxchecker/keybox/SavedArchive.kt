package dev.hcy917.keyboxchecker.keybox

import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Packs a whole saved collection into one zip, so it can leave the device as a
 * single file.
 *
 * The library sits in a folder only root can read, so the entries arrive here
 * already read into memory rather than as paths this class could open itself.
 *
 * Pure JVM: the archive is built from names and bytes, and the Android layer
 * only supplies the destination stream.
 */
object SavedArchive {

    /** One keybox on its way into the zip. */
    class Item(
        /** Path inside the zip, relative to the library root. */
        val path: String,
        val modifiedMillis: Long,
        val bytes: ByteArray,
    )

    /** `keyboxes-20261003-1536.zip`. */
    fun suggestedName(nowMillis: Long): String {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date(nowMillis))
        return "keyboxes-$stamp.zip"
    }

    /**
     * Writes [items] into a zip on [out] and closes it.
     *
     * A repeated name is written once, and nothing else is filtered: the caller
     * has already decided what the archive should carry. Returns the number of
     * entries actually written.
     */
    fun write(items: List<Item>, out: OutputStream): Int {
        var written = 0
        val seen = HashSet<String>()
        ZipOutputStream(out).use { zip ->
            for (item in items) {
                val path = normalise(item.path)
                if (path.isEmpty() || !seen.add(path)) continue
                val entry = ZipEntry(path)
                if (item.modifiedMillis > 0L) entry.time = item.modifiedMillis
                zip.putNextEntry(entry)
                zip.write(item.bytes)
                zip.closeEntry()
                written++
            }
        }
        return written
    }

    /** Zip entries always use `/`, whatever the platform separator is. */
    private fun normalise(relative: String): String =
        relative.replace('\\', '/').trimStart('/')
}
