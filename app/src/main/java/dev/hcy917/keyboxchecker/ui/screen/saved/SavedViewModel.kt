package dev.hcy917.keyboxchecker.ui.screen.saved

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.keybox.KeyboxRepository
import dev.hcy917.keyboxchecker.keybox.ScanEvent
import dev.hcy917.keyboxchecker.keybox.ScanReport
import dev.hcy917.keyboxchecker.templateApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.coroutines.cancellation.CancellationException

/**
 * Backs the "saved" section: the keyboxes the app has already written, plus the
 * two bulk actions that only make sense over a whole collection — checking every
 * saved keybox against the revocation list at once, and deleting the ones that
 * no longer work.
 *
 * Listing is deliberately offline. The library is a folder; opening the page
 * must never depend on the network, so revocation is only ever consulted when
 * the user taps the check button.
 */
class SavedViewModel : ViewModel() {

    private val repository = KeyboxRepository(templateApp, templateApp.okhttpClient)

    private val _uiState = MutableStateFlow(SavedUiState())
    val uiState: StateFlow<SavedUiState> = _uiState.asStateFlow()

    private var job: Job? = null

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch {
            val listed = withContext(Dispatchers.IO) { repository.listSaved() }
            val outputDir = runCatching { repository.defaultOutputDir().absolutePath }.getOrDefault("")
            _uiState.update { current ->
                // A re-listing keeps verdicts for files that are still there, so
                // adding a keybox elsewhere does not blank the previous check.
                val previous = current.entries.associateBy { it.keybox.relativePath }
                val entries = listed.map { keybox ->
                    val old = previous[keybox.relativePath]
                    SavedEntry(
                        keybox = keybox,
                        status = old?.status,
                        reason = old?.reason,
                        keyId = old?.keyId,
                    )
                }
                current.copy(
                    entries = entries,
                    outputDir = outputDir,
                )
            }
        }
    }

    // ------------------------------------------------------------------- check

    /**
     * Re-reads every saved keybox and asks the revocation list about it.
     *
     * The library is scanned with exactly the same engine the keybox page uses,
     * so a verdict here means the same thing as a verdict there. Files that
     * disappear between listing and scanning keep their previous verdict rather
     * than being reported as unknown.
     */
    fun onCheck() {
        if (_uiState.value.isChecking) return
        job = viewModelScope.launch {
            _uiState.update { it.copy(isChecking = true, message = null, notes = emptyList()) }
            val snapshot = withContext(Dispatchers.IO) { repository.loadRevocation(false) }
            val root = repository.defaultOutputDir()

            var report: ScanReport? = null
            try {
                repository.scanPath(root, root.absolutePath, snapshot).collect { event ->
                    when (event) {
                        is ScanEvent.Progress -> _uiState.update { it.copy(progress = event.progress) }
                        is ScanEvent.Done -> report = event.report
                    }
                }
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (error: Throwable) {
                _uiState.update {
                    it.copy(
                        isChecking = false,
                        progress = null,
                        message = error.message ?: templateApp.getString(R.string.saved_check_failed),
                    )
                }
                return@launch
            }

            val analysed = report?.keys?.associateBy { it.fileName }.orEmpty()
            _uiState.update { current ->
                val entries = current.entries.map { entry ->
                    val keybox = analysed[entry.keybox.relativePath] ?: return@map entry
                    // The group verdict is the worst one, so the reason to show is
                    // the reason of that same key.
                    val worst = keybox.keys.maxByOrNull { it.status.severity }
                    entry.copy(
                        status = worst?.status ?: keybox.status,
                        reason = worst?.revocationReason,
                        keyId = keybox.primaryKeyId,
                    )
                }
                current.copy(
                    entries = entries,
                    isChecking = false,
                    progress = null,
                    checked = true,
                    revocationSource = snapshot.source,
                    revocationEntries = snapshot.entryCount,
                    revocationFetchedAt = snapshot.fetchedAtMillis,
                    revocationError = snapshot.error,
                    message = null,
                    notes = buildList {
                        add(templateApp.getString(R.string.saved_check_done, entries.count { it.status != null }))
                        val revoked = entries.count { it.isRevoked }
                        if (revoked > 0) add(templateApp.getString(R.string.saved_check_revoked, revoked))
                        snapshot.error?.let { add(it) }
                    },
                )
            }
        }
    }

    fun onCancel() {
        job?.cancel()
        job = null
        _uiState.update { it.copy(isChecking = false, progress = null) }
    }

    // ------------------------------------------------------------------ delete

    /** Removes every keybox the last check confirmed as revoked or suspended. */
    fun onDeleteRevoked() {
        val paths = _uiState.value.revokedPaths
        if (paths.isEmpty()) {
            message(templateApp.getString(R.string.saved_nothing_to_delete))
            return
        }
        delete(paths)
    }

    private fun delete(paths: List<String>) {
        job = viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, message = null, notes = emptyList()) }
            val result = withContext(Dispatchers.IO) { repository.deleteSaved(paths) }
            val removed = result.deleted.toSet()
            _uiState.update { current ->
                val entries = current.entries.filterNot { it.keybox.relativePath in removed }
                current.copy(
                    entries = entries,
                    isBusy = false,
                    // Nothing revoked can be left once everything revoked is gone.
                    checked = current.checked && entries.any { it.status != null },
                    message = templateApp.getString(R.string.saved_deleted, result.deleted.size),
                    notes = result.failed.map { templateApp.getString(R.string.saved_delete_failed, it) },
                )
            }
        }
    }

    // ------------------------------------------------------------------ export

    /** Relative paths of everything the archive should carry, reports included. */
    fun archiveEntries(): List<String> =
        repository.savedArchiveEntries(_uiState.value.entries.map { it.keybox })

    fun suggestedArchiveName(): String = repository.savedArchiveName()

    /** Called once the user has chosen where the zip goes. */
    fun onExportTo(uri: Uri) {
        if (_uiState.value.isBusy) return
        job = viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, message = null, notes = emptyList()) }
            val entries = archiveEntries()
            if (entries.isEmpty()) {
                _uiState.update {
                    it.copy(isBusy = false, message = templateApp.getString(R.string.saved_nothing_to_export))
                }
                return@launch
            }
            val result = runCatching {
                withContext(Dispatchers.IO) { repository.exportArchive(entries, uri) }
            }
            _uiState.update { current ->
                result.fold(
                    onSuccess = { written ->
                        current.copy(
                            isBusy = false,
                            message = templateApp.getString(R.string.saved_exported, written),
                        )
                    },
                    onFailure = { error ->
                        current.copy(
                            isBusy = false,
                            message = error.message
                                ?: templateApp.getString(R.string.saved_export_failed),
                        )
                    },
                )
            }
        }
    }

    /**
     * Packs the library into a cache file and publishes its `content://` uri, so
     * the screen can hand it to the system share sheet.
     */
    fun onShare() {
        if (_uiState.value.isBusy) return
        job = viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, message = null, notes = emptyList()) }
            val entries = archiveEntries()
            if (entries.isEmpty()) {
                _uiState.update {
                    it.copy(isBusy = false, message = templateApp.getString(R.string.saved_nothing_to_export))
                }
                return@launch
            }
            val pending = runCatching {
                withContext(Dispatchers.IO) {
                    val name = repository.savedArchiveName()
                    val file: File = repository.cacheArchive(entries, name)
                    PendingShare(repository.shareUri(file), file, name)
                }
            }
            _uiState.update { current ->
                pending.fold(
                    onSuccess = { current.copy(isBusy = false, pendingShare = it) },
                    onFailure = { error ->
                        current.copy(
                            isBusy = false,
                            message = error.message
                                ?: templateApp.getString(R.string.saved_export_failed),
                        )
                    },
                )
            }
        }
    }

    /** The chooser has been launched; the uri does not need to outlive it. */
    fun onShareLaunched() {
        _uiState.update { it.copy(pendingShare = null) }
    }

    fun onDismissMessage() {
        _uiState.update { it.copy(message = null, notes = emptyList()) }
    }

    private fun message(text: String) {
        _uiState.update { it.copy(message = text) }
    }
}
