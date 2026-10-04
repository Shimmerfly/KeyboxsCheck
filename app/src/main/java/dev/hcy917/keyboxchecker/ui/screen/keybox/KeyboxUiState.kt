package dev.hcy917.keyboxchecker.ui.screen.keybox

import androidx.compose.runtime.Immutable
import dev.hcy917.keyboxchecker.keybox.AnalyzedKeybox
import dev.hcy917.keyboxchecker.keybox.RepeatedKey
import dev.hcy917.keyboxchecker.keybox.RevocationSource
import dev.hcy917.keyboxchecker.keybox.ScanProgress
import dev.hcy917.keyboxchecker.keybox.ScanReport

/**
 * Everything the keybox screen renders.
 *
 * [report] already carries the per-file list and the repeated keys, so the UI
 * never has to recompute them: the classifier runs once per scan.
 */
@Immutable
data class KeyboxUiState(
    val path: String = "",
    val pickedTreeLabel: String? = null,
    /** Names of the individually picked files, when that is how input was given. */
    val pickedFileNames: List<String> = emptyList(),
    /** Written into every saved keybox as its `DeviceID`. */
    val localDeviceId: String = "",
    val isScanning: Boolean = false,
    val progress: ScanProgress? = null,
    val report: ScanReport? = null,
    /** One entry per file, never merged: the same key may appear twice here. */
    val certificates: List<AnalyzedKeybox> = emptyList(),
    /** Keys carried by more than one of the scanned files. */
    val repeatedKeys: List<RepeatedKey> = emptyList(),
    val expandedFiles: Set<String> = emptySet(),
    /**
     * Where confirmed keyboxes are written: the TEESimulator module's folder.
     * It is root-only, and there is nothing to choose, so this is read-only.
     */
    val outputDir: String = "",
    /** Null until root has been asked for; false once it has been refused. */
    val rootReady: Boolean? = null,
    val revocationSource: RevocationSource = RevocationSource.NONE,
    val revocationEntries: Int = 0,
    val revocationFetchedAt: Long = 0L,
    val revocationExpires: String? = null,
    val revocationError: String? = null,
    val message: String? = null,
    val notes: List<String> = emptyList(),
)

@Immutable
data class KeyboxActions(
    val onPathChanged: (String) -> Unit,
    val onPickDirectory: () -> Unit,
    val onPickFiles: () -> Unit,
    val onLocalDeviceIdChanged: (String) -> Unit,
    val onScan: () -> Unit,
    val onCancel: () -> Unit,
    val onRefreshRevocation: () -> Unit,
    val onSaveConfirmed: () -> Unit,
    val onToggleFile: (String) -> Unit,
    /** Asks for root again, in case the prompt was dismissed earlier. */
    val onRequestRoot: () -> Unit,
)

/**
 * The other scanned files that carry any of [keybox]'s keys, if any.
 *
 * Every key of the file is looked at: a keybox holds an ECDSA and an RSA key, and
 * two files are the same certificate as soon as one of those keys matches.
 */
fun KeyboxUiState.twinNames(keybox: AnalyzedKeybox): List<String> {
    val keyIds = keybox.keys.map { it.keyId }.toSet()
    if (keyIds.isEmpty()) return emptyList()
    return repeatedKeys
        .filter { it.keyId in keyIds }
        .flatMap { it.fileNames }
        .filter { it != keybox.fileName }
        .distinct()
        .sorted()
}
