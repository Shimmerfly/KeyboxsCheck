package dev.hcy917.keyboxchecker.keybox

/**
 * Facts about the keys carried by a scan.
 *
 * A scan result lists its files one by one: two keyboxes are never merged into
 * a single row, because the row would then hide which file the reader has to
 * look at. Ties between files are reported instead of resolved — [repeatedKeys]
 * names the files that carry one and the same key, and it is exactly this list
 * the save step consults before it writes anything to the library.
 */
object KeyboxClassifier {

    /**
     * Keys that more than one file carries, worst first then by file name.
     *
     * Files whose key cannot be identified are left out: nothing can be claimed
     * about a key that was never derived.
     */
    fun repeatedKeys(keyboxes: List<AnalyzedKeybox>): List<RepeatedKey> {
        val byKey = LinkedHashMap<String, MutableList<String>>()
        for (keybox in keyboxes) {
            val keyId = keybox.primaryKeyId ?: continue
            byKey.getOrPut(keyId) { ArrayList() }.add(keybox.fileName)
        }
        return byKey
            .filterValues { it.size > 1 }
            .map { (keyId, names) -> RepeatedKey(keyId, names.sorted()) }
            .sortedWith(compareByDescending<RepeatedKey> { it.count }.thenBy { it.fileNames.first() })
    }

    /**
     * Marks every file whose bytes already appeared in this scan.
     *
     * This is deliberately idempotent: a first occurrence always ends up with
     * `duplicateOf == null`, even when the incoming list was already marked.
     * The report is rebuilt from a previous report (for example when a channel
     * import is merged in), and a stale marking on the survivor would otherwise
     * pair every copy up with another one, leaving the whole group unsaveable.
     *
     * Byte identity is only the first, cheapest tie: two files that differ by a
     * single editable character still carry the same key, which [repeatedKeys]
     * and the save step take care of.
     *
     * @return the relabelled list (first occurrence keeps `duplicateOf == null`)
     *   together with the number of duplicates found.
     */
    fun markDuplicates(keyboxes: List<AnalyzedKeybox>): DuplicateMarking {
        val seen = HashMap<String, String>(keyboxes.size)
        var duplicates = 0
        val result = keyboxes.map { keybox ->
            val digest = keybox.contentSha256
            if (digest.isEmpty()) return@map keybox
            val first = seen[digest]
            if (first == null) {
                seen[digest] = keybox.fileName
                if (keybox.duplicateOf == null) keybox else keybox.copy(duplicateOf = null)
            } else {
                duplicates++
                keybox.copy(duplicateOf = first)
            }
        }
        return DuplicateMarking(result, duplicates)
    }

    class DuplicateMarking(val keyboxes: List<AnalyzedKeybox>, val duplicateCount: Int)

    fun stats(
        filesScanned: Int,
        xmlFiles: Int,
        keyboxes: List<AnalyzedKeybox>,
        notKeybox: Int,
        unreadable: Int,
        duplicateCount: Int,
    ): ScanStats = ScanStats(
        filesScanned = filesScanned,
        xmlFiles = xmlFiles,
        confirmedKeyboxes = keyboxes.count { it.isConfirmed },
        notKeybox = notKeybox,
        unreadable = unreadable,
        duplicates = duplicateCount,
    )
}
