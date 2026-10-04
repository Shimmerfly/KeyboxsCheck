package dev.hcy917.keyboxchecker.ui.screen.saved

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.keybox.KeyboxRepository
import dev.hcy917.keyboxchecker.keybox.SavedKeybox
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

/**
 * Backs the "saved" section: the keyboxes the TEESimulator module serves, plus
 * the bulk actions that only make sense over a whole collection — checking every
 * saved keybox against the revocation list at once, deleting the ones that no
 * longer work, and choosing which one the module should use.
 *
 * The folder belongs to the module and is root-only, so listing goes through
 * `su` and the first visit asks for root. Listing is deliberately offline: the
 * library is a folder, opening the page must never depend on the network, so
 * revocation is only consulted when the user taps the check button.
 */
class SavedViewModel : ViewModel() {

    private val repository = KeyboxRepository(templateApp, templateApp.okhttpClient)

    private val _uiState = MutableStateFlow(SavedUiState(libraryPath = repository.libraryPath()))
    val uiState: StateFlow<SavedUiState> = _uiState.asStateFlow()

    private var job: Job? = null

    /** Whether root has been asked for already, so it is only ever asked once. */
    private var prompted = false

    init {
        refresh()
    }

    fun refresh() {
        // The first visit may ask for root, because there is nothing to show
        // without it; later visits only look at what has already been granted,
        // so switching tabs never fires a fresh prompt.
        val prompt = !prompted
        prompted = true
        viewModelScope.launch { reload(prompt = prompt) }
    }

    /**
     * Re-reads the folder and the module's config.
     *
     * A re-listing keeps verdicts for files that are still there, so saving a
     * keybox on another page does not blank the previous check.
     */
    private suspend fun reload(prompt: Boolean) {
        val libraryPath = repository.libraryPath()
        val ready = withContext(Dispatchers.IO) {
            if (prompt) repository.rootAvailable() else repository.rootGranted()
        }
        if (!ready) {
            _uiState.update {
                it.copy(
                    entries = emptyList(),
                    libraryPath = libraryPath,
                    rootReady = false,
                    rootChecked = true,
                    configReady = false,
                )
            }
            return
        }

        val listed = withContext(Dispatchers.IO) { repository.listSaved() }
        val config = withContext(Dispatchers.IO) { repository.readTeessimConfig() }
        val selected = config?.selected.orEmpty()

        _uiState.update { current ->
            val previous = current.entries.associateBy { it.keybox.relativePath }
            val entries = listed.map { keybox ->
                val old = previous[keybox.relativePath]
                SavedEntry(
                    keybox = keybox,
                    status = old?.status,
                    reason = old?.reason,
                    keyId = old?.keyId,
                    selected = keybox.fileName in selected,
                    selectedBy = config?.profilesUsing(keybox.fileName).orEmpty(),
                )
            }
            current.copy(
                entries = entries,
                libraryPath = libraryPath,
                rootReady = true,
                rootChecked = true,
                configReady = config != null,
            )
        }
    }

    // -------------------------------------------------------------------- root

    /** Asks for root again after the prompt was dismissed. */
    fun onRequestRoot() {
        if (_uiState.value.isBusy) return
        job = viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, message = null, notes = emptyList()) }
            val granted = withContext(Dispatchers.IO) { repository.requestRoot() }
            _uiState.update {
                it.copy(
                    isBusy = false,
                    message = templateApp.getString(
                        if (granted) R.string.saved_root_granted else R.string.saved_root_denied,
                    ),
                )
            }
            reload(prompt = false)
        }
    }

    // ------------------------------------------------------------------- check

    /**
     * Re-reads every saved keybox and asks the revocation list about it.
     *
     * The library is analysed with exactly the same engine the keybox page uses,
     * so a verdict here means the same thing as a verdict there.
     */
    fun onCheck() {
        if (_uiState.value.isChecking) return
        job = viewModelScope.launch {
            _uiState.update { it.copy(isChecking = true, message = null, notes = emptyList()) }
            val snapshot = withContext(Dispatchers.IO) { repository.loadRevocation(false) }
            val analysed = runCatching {
                withContext(Dispatchers.IO) { repository.analyzeSaved(snapshot) }
            }.getOrElse { error ->
                _uiState.update {
                    it.copy(
                        isChecking = false,
                        progress = null,
                        message = error.message ?: templateApp.getString(R.string.saved_check_failed),
                    )
                }
                return@launch
            }

            _uiState.update { current ->
                val entries = current.entries.map { entry ->
                    val keybox = analysed[entry.keybox.relativePath] ?: return@map entry
                    // The file verdict is the worst key in it, so the reason to
                    // show is the reason of that same key.
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

    // ------------------------------------------------------------------ select

    /**
     * Makes [fileName] the keybox the module serves.
     *
     * The module keeps one keybox per profile and the app offers one choice, so
     * every profile is pointed at the file; the screen confirms that wording
     * before calling this.
     */
    fun onMakeCurrent(fileName: String) {
        if (_uiState.value.isBusy) return
        job = viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, message = null, notes = emptyList()) }
            val done = withContext(Dispatchers.IO) { repository.setTeessimKeybox(fileName) }
            _uiState.update {
                it.copy(
                    isBusy = false,
                    message = templateApp.getString(
                        if (done) R.string.saved_make_current_done else R.string.saved_make_current_failed,
                        fileName,
                    ),
                )
            }
            if (done) reload(prompt = false)
        }
    }

    // ------------------------------------------------------------------ export

    /** The keyboxes the archive should carry. */
    fun archiveKeyboxes(): List<SavedKeybox> = _uiState.value.entries.map { it.keybox }

    fun suggestedArchiveName(): String = repository.savedArchiveName()

    /** Called once the user has chosen where the zip goes. */
    fun onExportTo(uri: Uri) {
        if (_uiState.value.isBusy) return
        job = viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, message = null, notes = emptyList()) }
            val keyboxes = archiveKeyboxes()
            if (keyboxes.isEmpty()) {
                _uiState.update {
                    it.copy(isBusy = false, message = templateApp.getString(R.string.saved_nothing_to_export))
                }
                return@launch
            }
            val result = runCatching {
                withContext(Dispatchers.IO) { repository.exportArchive(keyboxes, uri) }
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
     * Packs the library into a file and publishes its `content://` uri, so the
     * screen can hand it to the system share sheet.
     */
    fun onShare() {
        if (_uiState.value.isBusy) return
        job = viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, message = null, notes = emptyList()) }
            val keyboxes = archiveKeyboxes()
            if (keyboxes.isEmpty()) {
                _uiState.update {
                    it.copy(isBusy = false, message = templateApp.getString(R.string.saved_nothing_to_export))
                }
                return@launch
            }
            val pending = runCatching {
                withContext(Dispatchers.IO) {
                    val name = repository.savedArchiveName()
                    val file: File = repository.cacheArchive(keyboxes, name)
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
