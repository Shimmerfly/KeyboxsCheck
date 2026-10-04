package dev.hcy917.keyboxchecker.keybox

import java.util.Calendar
import java.util.Locale

/** How a saved keybox was provisioned, as encoded by the `R`/`N` marker of its name. */
enum class SavedKind { LOCAL, REMOTE }

/** One file the library folder holds, as the directory listing described it. */
data class SavedFile(
    val name: String,
    val sizeBytes: Long,
    val modifiedMillis: Long,
)

/**
 * One keybox already written by "save confirmed".
 *
 * Everything the library shows is derived from the file name that
 * [KeyboxRepository] produced — `yyyyMMdd` + `R|N` + five digits — plus the file
 * itself, so listing the library never has to parse a keybox again.
 *
 * The library is flat: keyboxes are dropped straight into the module's folder,
 * with no folder per device, so [relativePath] is normally just [fileName]. A
 * keybox put there by hand (`keybox.xml`) keeps its own name and is listed as
 * unnamed.
 */
data class SavedKeybox(
    val fileName: String,
    /** Path relative to the library root; the same as [fileName] in a flat library. */
    val relativePath: String,
    /** Midnight of the day the name claims; the file's mtime when the name is foreign. */
    val savedAtMillis: Long,
    val kind: SavedKind,
    /** The five digits of the name, empty when the name follows no rule. */
    val serial: String,
    /**
     * False when the name does not match `yyyyMMddR|N#####`, i.e. the file was
     * written by an older build or dropped into the folder by hand.
     */
    val named: Boolean,
    val sizeBytes: Long,
) {
    val remoteProvisioned: Boolean get() = kind == SavedKind.REMOTE
}

/**
 * Lists and names the keyboxes already on disk.
 *
 * Pure JVM on purpose: the naming rule is exactly what the library renders, so
 * it is unit-tested next to the rest of the engine instead of through the UI.
 * Listing itself is left to the caller because the library lives in a folder
 * only root can read.
 */
object SavedLibrary {

    private val NAME_PATTERN = Regex("""^(\d{4})(\d{2})(\d{2})([RNrn])(\d{5})\.xml$""")

    /** The parsed half of a `yyyyMMddR|N#####.xml` name. */
    data class ParsedName(
        val dateMillis: Long,
        val kind: SavedKind,
        val serial: String,
    )

    /** Every listed keybox of [files], newest first. */
    fun of(files: List<SavedFile>): List<SavedKeybox> {
        val out = files.filter { isKeyboxFile(it.name) }.map { describe(it) }
        return out.sortedWith(
            compareByDescending<SavedKeybox> { it.savedAtMillis }
                .thenByDescending { it.serial },
        )
    }

    /** Only keyboxes take part in the library; anything else in there is left alone. */
    fun isKeyboxFile(name: String): Boolean = name.endsWith(".xml", ignoreCase = true)

    /**
     * Reads `20261003N58052.xml` back into a date, a kind and five digits.
     *
     * Returns null for anything that does not follow the rule, and for calendar
     * dates that do not exist (`20260231`), so a malformed name can never make
     * the library claim a keybox was saved on a day that never happened.
     */
    fun parseName(fileName: String): ParsedName? {
        val match = NAME_PATTERN.matchEntire(fileName.trim()) ?: return null
        val year = match.groupValues[1].toInt()
        val month = match.groupValues[2].toInt()
        val day = match.groupValues[3].toInt()
        if (month !in 1..12 || day !in 1..31) return null

        val calendar = Calendar.getInstance()
        calendar.clear()
        calendar.set(year, month - 1, day, 0, 0, 0)
        if (calendar.get(Calendar.YEAR) != year ||
            calendar.get(Calendar.MONTH) != month - 1 ||
            calendar.get(Calendar.DAY_OF_MONTH) != day
        ) {
            return null
        }

        val kind = if (match.groupValues[4].uppercase(Locale.US) == "R") {
            SavedKind.REMOTE
        } else {
            SavedKind.LOCAL
        }
        return ParsedName(calendar.timeInMillis, kind, match.groupValues[5])
    }

    private fun describe(file: SavedFile): SavedKeybox {
        val parsed = parseName(file.name)
        return SavedKeybox(
            fileName = file.name,
            relativePath = file.name,
            savedAtMillis = parsed?.dateMillis ?: file.modifiedMillis,
            kind = parsed?.kind ?: SavedKind.LOCAL,
            serial = parsed?.serial.orEmpty(),
            named = parsed != null,
            sizeBytes = file.sizeBytes,
        )
    }
}
