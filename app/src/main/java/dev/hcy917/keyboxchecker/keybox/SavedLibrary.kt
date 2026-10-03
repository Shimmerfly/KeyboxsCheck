package dev.hcy917.keyboxchecker.keybox

import java.io.File
import java.util.Calendar
import java.util.Locale

/** How a saved keybox was provisioned, as encoded by the `R`/`N` marker of its name. */
enum class SavedKind { LOCAL, REMOTE }

/**
 * One keybox already written by "save confirmed".
 *
 * Everything the library shows is derived from the file name that
 * [KeyboxRepository] produced — `yyyyMMdd` + `R|N` + five digits — plus the file
 * itself, so listing the library never has to parse a keybox again.
 */
data class SavedKeybox(
    val fileName: String,
    /** `localdev1/20261003N58052.xml`, relative to the library root. */
    val relativePath: String,
    /** Folder the keybox was filed under, i.e. the DeviceID it was saved with. */
    val deviceFolder: String,
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
 */
object SavedLibrary {

    /** Device folders sit directly under the library root. */
    const val MAX_DEPTH = 2

    private val NAME_PATTERN = Regex("""^(\d{4})(\d{2})(\d{2})([RNrn])(\d{5})\.xml$""")

    /** The parsed half of a `yyyyMMddR|N#####.xml` name. */
    data class ParsedName(
        val dateMillis: Long,
        val kind: SavedKind,
        val serial: String,
    )

    /** Every saved keybox under [root], newest first. */
    fun list(root: File): List<SavedKeybox> {
        val out = ArrayList<SavedKeybox>()
        val stack = ArrayDeque<Pair<File, Int>>()
        stack += root to 0
        while (stack.isNotEmpty()) {
            val (directory, depth) = stack.removeLast()
            val children = directory.listFiles() ?: continue
            for (child in children) {
                if (child.isDirectory) {
                    // Two levels take part: the output folder and the single
                    // device folder the keyboxes are written into. Anything
                    // nested deeper was not put there by the save path.
                    if (depth + 1 < MAX_DEPTH) stack += child to (depth + 1)
                    continue
                }
                if (!isKeyboxFile(child.name)) continue
                out += describe(root, child)
            }
        }
        return out.sortedWith(
            compareByDescending<SavedKeybox> { it.savedAtMillis }
                .thenByDescending { it.serial },
        )
    }

    /** The keyboxes inside [root] that share one day and kind, for grouping in the UI. */
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

    private fun describe(root: File, file: File): SavedKeybox {
        val relative = runCatching { file.relativeTo(root).path }.getOrDefault(file.name)
        val parsed = parseName(file.name)
        val folder = relative.substringBeforeLast(File.separatorChar, "")
        return SavedKeybox(
            fileName = file.name,
            relativePath = relative,
            deviceFolder = folder,
            savedAtMillis = parsed?.dateMillis ?: file.lastModified(),
            kind = parsed?.kind ?: SavedKind.LOCAL,
            serial = parsed?.serial.orEmpty(),
            named = parsed != null,
            sizeBytes = file.length(),
        )
    }
}
