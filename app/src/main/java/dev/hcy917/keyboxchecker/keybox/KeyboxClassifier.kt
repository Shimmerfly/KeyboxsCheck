package dev.hcy917.keyboxchecker.keybox

/**
 * Groups analysed keyboxes by *key identity*.
 *
 * The `DeviceID`, the attestation properties and every other field a user can
 * edit with a text editor are deliberately excluded from the grouping key —
 * they are reported per member so two files with the same key but different
 * DeviceIDs are visibly flagged as one identity with a rewritten label.
 */
object KeyboxClassifier {

    /** A keybox with no key at all cannot be grouped; it is reported separately. */
    fun classify(keyboxes: List<AnalyzedKeybox>): List<KeyGroup> {
        val grouped = LinkedHashMap<String, MutableList<AnalyzedKeybox>>()
        for (keybox in keyboxes) {
            val keyId = keybox.primaryKeyId ?: continue
            grouped.getOrPut(keyId) { ArrayList() }.add(keybox)
        }

        val groups = grouped.map { (keyId, members) ->
            val variants = members.map { it.chainFingerprint }.filter { it.isNotEmpty() }.distinct()
            KeyGroup(
                keyId = keyId,
                status = members.maxByOrNull { it.status.severity }?.status ?: RevocationStatus.UNKNOWN,
                members = members.sortedBy { it.fileName },
                chainVariants = variants.size,
                identicalChains = variants.size <= 1,
            )
        }

        return groups.sortedWith(
            compareByDescending<KeyGroup> { it.status.severity }
                .thenByDescending { it.memberCount }
                .thenBy { it.keyId },
        )
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
