package dev.hcy917.keyboxchecker.ui.screen.keybox

import androidx.compose.runtime.Immutable
import dev.hcy917.keyboxchecker.keybox.KeyGroup
import dev.hcy917.keyboxchecker.keybox.RevocationSource
import dev.hcy917.keyboxchecker.keybox.ScanProgress
import dev.hcy917.keyboxchecker.keybox.ScanReport

/**
 * Everything the keybox screen renders.
 *
 * [report] already carries the grouped view, so the UI never has to regroup:
 * the classifier runs once per scan inside the repository.
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
    val groups: List<KeyGroup> = emptyList(),
    val expandedGroups: Set<String> = emptySet(),
    val outputDir: String = "",
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
    val onToggleGroup: (String) -> Unit,
)
