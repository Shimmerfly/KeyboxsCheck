package dev.hcy917.keyboxchecker.ui.screen.saved

import android.net.Uri
import dev.hcy917.keyboxchecker.keybox.RevocationSource
import dev.hcy917.keyboxchecker.keybox.RevocationStatus
import dev.hcy917.keyboxchecker.keybox.SavedKind
import dev.hcy917.keyboxchecker.keybox.SavedKeybox
import dev.hcy917.keyboxchecker.keybox.ScanProgress
import java.io.File

/**
 * One keybox in the library, together with what the last on-demand revocation
 * check said about it. [status] stays null until the user asks for a check,
 * because the library is a plain folder listing and must not hit the network on
 * its own.
 */
data class SavedEntry(
    val keybox: SavedKeybox,
    val status: RevocationStatus? = null,
    val reason: String? = null,
    val keyId: String? = null,
) {
    /**
     * Revoked *and* suspended count as "no longer usable", which is what the
     * one-tap delete removes. An expired keybox already reports REVOKED, so it
     * is covered too.
     */
    val isRevoked: Boolean
        get() = status == RevocationStatus.REVOKED || status == RevocationStatus.SUSPENDED
}

/** A zip waiting to be handed to another app once its `content://` uri exists. */
data class PendingShare(val uri: Uri, val file: File, val name: String)

data class SavedUiState(
    val entries: List<SavedEntry> = emptyList(),
    val outputDir: String = "",
    val isChecking: Boolean = false,
    val isBusy: Boolean = false,
    val progress: ScanProgress? = null,
    /** True once a check has run, so "unknown" can be told apart from "not asked yet". */
    val checked: Boolean = false,
    val revocationSource: RevocationSource = RevocationSource.NONE,
    val revocationEntries: Int = 0,
    val revocationFetchedAt: Long = 0L,
    val revocationError: String? = null,
    val message: String? = null,
    val notes: List<String> = emptyList(),
    val pendingShare: PendingShare? = null,
) {
    /**
     * Files the check could confirm as revoked — the only ones the bulk delete
     * touches. Empty until a check has run, so the button can never remove a
     * keybox nothing has looked at.
     */
    val revokedPaths: List<String>
        get() = if (checked) entries.filter { it.isRevoked }.map { it.keybox.relativePath } else emptyList()

    val totalBytes: Long get() = entries.sumOf { it.keybox.sizeBytes }
}

data class SavedActions(
    val onRefresh: () -> Unit,
    val onCheck: () -> Unit,
    val onCancel: () -> Unit,
    val onDeleteRevoked: () -> Unit,
    val onExportZip: () -> Unit,
    val onShare: () -> Unit,
    val onShareLaunched: () -> Unit,
    val onDismissMessage: () -> Unit,
)

/** Remote-provisioned keyboxes are worth calling out: they are the ones that rotate. */
internal val SavedEntry.remoteProvisioned: Boolean get() = keybox.kind == SavedKind.REMOTE
