package dev.hcy917.keyboxchecker.keybox

import java.io.File
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Packs a whole saved collection into one zip, so it can leave the device as a
 * single file regardless of how many device folders it holds.
 *
 * Pure JVM: the archive is built from relative paths, and the Android layer only
 * supplies the destination stream.
 */
object SavedArchive {

    /** The reports the library keeps beside the device folders. */
    val REPORT_FILES = listOf("classification.json", "report.md")

    /** `keyboxes-20261003-1536.zip`. */
    fun suggestedName(nowMillis: Long): String {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date(nowMillis))
        return "keyboxes-$stamp.zip"
    }

    /**
     * Everything the library holds: the keyboxes themselves plus the reports
     * that sit next to them. Order is stable so two exports of the same
     * collection are comparable.
     */
    fun entries(root: File, keyboxes: List<SavedKeybox>): List<String> {
        val out = ArrayList<String>(keyboxes.size + REPORT_FILES.size)
        keyboxes.forEach { out += it.relativePath }
        REPORT_FILES.forEach { if (File(root, it).isFile) out += it }
        return out
    }

    /**
     * Writes [relativePaths] into a zip on [out] and closes it.
     *
     * A file that disappeared between listing and packing is skipped instead of
     * aborting the archive, so one deleted keybox cannot cost the user the rest
     * of the collection. Returns the number of entries actually written.
     */
    fun write(root: File, relativePaths: List<String>, out: OutputStream): Int {
        var written = 0
        ZipOutputStream(out).use { zip ->
            for (relative in relativePaths.distinct()) {
                val file = File(root, relative)
                if (!file.isFile) continue
                val entry = ZipEntry(normalise(relative))
                entry.time = file.lastModified()
                zip.putNextEntry(entry)
                file.inputStream().use { input -> input.copyTo(zip) }
                zip.closeEntry()
                written++
            }
        }
        return written
    }

    /** Zip entries always use `/`, whatever the platform separator is. */
    private fun normalise(relative: String): String =
        relative.replace(File.separatorChar, '/').trimStart('/')
}
