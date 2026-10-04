package dev.hcy917.keyboxchecker.keybox

/**
 * Decides which confirmed keyboxes "save" may actually write.
 *
 * Only a key the revocation list has cleared is written. An expired certificate
 * and a published revocation both mean the key is dead to a device, and a key
 * whose status could not be established is not written either: "the list could
 * not be reached" is not a reason to hand a device a key that may be revoked.
 *
 * A keybox is identified by its key material, not by its bytes: two files that
 * carry the same key are the same certificate to the device, however much their
 * editable `DeviceID` or attestation properties differ. Writing both would leave
 * the library holding one key twice, so the plan keeps the first file it can
 * write for a key and reports every later one as [Outcome.REPEATED_KEY]. A file
 * carries up to two keys (an ECDSA and an RSA one), so every key it holds takes
 * part in that comparison.
 *
 * The comparison deliberately spans more than the batch in hand: a key that is
 * already in the library is reported as [Outcome.IN_LIBRARY] and is not written
 * again, so re-running a scan never grows the library with copies of a key it
 * already holds.
 */
object SavePlanner {

    enum class Outcome {
        SAVED,
        NOT_KEYBOX,
        CONTENT_DUPLICATE,
        EXPIRED,
        REVOKED,
        SUSPENDED,

        /** The revocation list could not clear this key, so it is not written. */
        UNCHECKED,
        IN_LIBRARY,
        REPEATED_KEY,
        MISSING_CONTENT,
    }

    data class Decision(
        val keybox: AnalyzedKeybox,
        val outcome: Outcome,
        /** The twin file, the library copy, or why the key was revoked. */
        val detail: String? = null,
    ) {
        val saveable: Boolean get() = outcome == Outcome.SAVED
    }

    /**
     * @param availableDigests content hashes whose bytes are still captured, so
     *   that a file whose content was dropped is not reported as writable.
     * @param libraryKeys key ids already saved locally, mapped to the file that
     *   holds them (a path relative to the library root).
     */
    fun plan(
        keys: List<AnalyzedKeybox>,
        availableDigests: Set<String>,
        libraryKeys: Map<String, String>,
    ): List<Decision> {
        val decisions = ArrayList<Decision>(keys.size)
        // key id -> the one file this run writes for it
        val chosen = HashMap<String, String>()

        for (keybox in keys) {
            if (!keybox.isConfirmed) {
                decisions += Decision(keybox, Outcome.NOT_KEYBOX)
                continue
            }
            if (keybox.duplicateOf != null) {
                decisions += Decision(keybox, Outcome.CONTENT_DUPLICATE, keybox.duplicateOf)
                continue
            }
            // Expiry is a property of this file alone, so it is reported as such
            // even when a twin file would have been skipped for another reason.
            if (keybox.expired) {
                decisions += Decision(keybox, Outcome.EXPIRED)
                continue
            }

            val worst = keybox.keys.maxByOrNull { it.status.severity }
            when (worst?.status) {
                RevocationStatus.REVOKED -> {
                    decisions += Decision(keybox, Outcome.REVOKED, worst.revocationReason)
                    continue
                }
                RevocationStatus.SUSPENDED -> {
                    decisions += Decision(keybox, Outcome.SUSPENDED, worst.revocationReason)
                    continue
                }
                RevocationStatus.UNKNOWN -> {
                    decisions += Decision(keybox, Outcome.UNCHECKED)
                    continue
                }
                else -> Unit
            }

            val keyIds = keybox.keys.map { it.keyId }
            keyIds.firstNotNullOfOrNull { libraryKeys[it] }?.let {
                decisions += Decision(keybox, Outcome.IN_LIBRARY, it)
                continue
            }
            keyIds.firstNotNullOfOrNull { chosen[it] }?.let {
                decisions += Decision(keybox, Outcome.REPEATED_KEY, it)
                continue
            }
            if (keybox.contentSha256 !in availableDigests) {
                decisions += Decision(keybox, Outcome.MISSING_CONTENT)
                continue
            }
            keyIds.forEach { chosen[it] = keybox.fileName }
            decisions += Decision(keybox, Outcome.SAVED)
        }
        return decisions
    }
}
