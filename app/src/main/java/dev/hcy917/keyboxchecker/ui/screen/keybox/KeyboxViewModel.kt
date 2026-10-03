package dev.hcy917.keyboxchecker.ui.screen.keybox

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.hcy917.keyboxchecker.keybox.KeyboxRepository
import dev.hcy917.keyboxchecker.keybox.RevocationSnapshot
import dev.hcy917.keyboxchecker.keybox.ScanEvent
import dev.hcy917.keyboxchecker.keybox.ScanStats
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
 * Drives one keybox scan and the "save confirmed" step.
 *
 * The local device id is stored in private SharedPreferences and is the
 * `DeviceID` written into every saved keybox, so a collection gathered from any
 * number of sources comes out uniform.
 */
class KeyboxViewModel : ViewModel() {

    private val repository = KeyboxRepository(templateApp, templateApp.okhttpClient)

    private val prefs
        get() = templateApp.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val _uiState = MutableStateFlow(buildInitialState())
    val uiState: StateFlow<KeyboxUiState> = _uiState.asStateFlow()

    private var revocation: RevocationSnapshot = RevocationSnapshot.EMPTY
    private var scanJob: Job? = null

    /** Set when the user picks a directory through the Storage Access Framework. */
    private var treeUri: Uri? = null

    init {
        loadRevocation(force = false)
    }

    // ------------------------------------------------------------------ intents

    fun onPathChanged(value: String) {
        // Typing a path abandons a previously picked tree.
        treeUri = null
        prefs.edit().putString(KEY_PATH, value).apply()
        _uiState.update { it.copy(path = value, pickedTreeLabel = null) }
    }

    fun onTreePicked(uri: Uri) {
        treeUri = uri
        val persisted = repository.takePersistable(uri)
        prefs.edit().putString(KEY_TREE_URI, uri.toString()).apply()
        _uiState.update {
            it.copy(
                pickedTreeLabel = uri.lastPathSegment ?: uri.toString(),
                message = if (persisted) null else "无法长期保留该目录的访问权限，重新打开应用后可能需要再次选择",
            )
        }
    }

    fun onLocalDeviceIdChanged(value: String) {
        prefs.edit().putString(KEY_LOCAL_DEVICE_ID, value).apply()
        _uiState.update { it.copy(localDeviceId = value) }
    }

    fun onToggleGroup(keyId: String) {
        _uiState.update { state ->
            val expanded = state.expandedGroups.toMutableSet()
            if (!expanded.add(keyId)) expanded.remove(keyId)
            state.copy(expandedGroups = expanded)
        }
    }

    fun onCancelScan() {
        scanJob?.cancel()
        _uiState.update { it.copy(isScanning = false, progress = null) }
    }

    fun onRefreshRevocation() {
        loadRevocation(force = true)
        setMessage("吊销列表已更新，重新扫描后生效")
    }

    // --------------------------------------------------------------------- scan

    fun onScan() {
        if (_uiState.value.isScanning) return
        val target = treeUri
        val path = _uiState.value.path.trim()
        if (target == null && path.isEmpty()) {
            setMessage("请先输入目录路径，或通过「选择目录」授权一个目录")
            return
        }

        scanJob = viewModelScope.launch {
            _uiState.update {
                it.copy(isScanning = true, message = null, notes = emptyList(), progress = null)
            }
            val snapshot = ensureRevocation()
            val root = if (target == null) File(path) else null
            val description = root?.absolutePath ?: "SAF:${target}"
            try {
                val events = if (target != null) {
                    repository.scanTree(target, description, snapshot)
                } else {
                    repository.scanPath(root!!, description, snapshot)
                }
                events.collect { event ->
                    when (event) {
                        is ScanEvent.Progress ->
                            _uiState.update { it.copy(progress = event.progress) }

                        is ScanEvent.Done -> _uiState.update {
                            it.copy(
                                report = event.report,
                                groups = event.report.groups,
                                progress = null,
                                notes = scanNotes(event.report.stats),
                            )
                        }
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                setMessage(error.message ?: "扫描失败")
            } finally {
                _uiState.update { it.copy(isScanning = false, progress = null) }
            }
        }
    }

    // -------------------------------------------------------------------- saving

    fun onSaveConfirmed() {
        val state = _uiState.value
        val report = state.report
        if (report == null) {
            setMessage("请先扫描目录后再保存")
            return
        }
        if (state.localDeviceId.isBlank()) {
            setMessage("请先填写本机 ID，保存时会写入 keybox 的 DeviceID")
            return
        }
        viewModelScope.launch {
            val directory = File(state.outputDir.ifBlank { repository.defaultOutputDir().absolutePath })
            val result = withContext(Dispatchers.IO) {
                repository.saveConfirmed(report, directory, state.localDeviceId)
            }
            val notes = buildList {
                add("输出目录：${result.directory.absolutePath}")
                if (result.saved.isEmpty()) add("没有写入任何文件")
                addAll(result.saved.map { "已保存 $it" })
                addAll(result.skipped.map { "跳过 $it" })
                addAll(result.failed.map { "失败 $it" })
                addAll(result.reportFiles.map { "已写出报告 ${it.name}" })
            }
            _uiState.update { it.copy(message = "保存完成", notes = notes) }
        }
    }

    // ------------------------------------------------------------------ internal

    private fun buildInitialState(): KeyboxUiState {
        val stored = prefs.getString(KEY_OUTPUT_DIR, null)
        return KeyboxUiState(
            path = prefs.getString(KEY_PATH, "").orEmpty(),
            localDeviceId = prefs.getString(KEY_LOCAL_DEVICE_ID, "").orEmpty(),
            outputDir = stored ?: runCatching { repository.defaultOutputDir().absolutePath }.getOrDefault(""),
        )
    }

    private fun loadRevocation(force: Boolean) {
        viewModelScope.launch {
            val snapshot = withContext(Dispatchers.IO) { repository.loadRevocation(force) }
            applyRevocation(snapshot)
        }
    }

    private suspend fun ensureRevocation(): RevocationSnapshot {
        if (revocation.isUsable) return revocation
        val snapshot = withContext(Dispatchers.IO) { repository.loadRevocation(false) }
        applyRevocation(snapshot)
        return snapshot
    }

    private fun applyRevocation(snapshot: RevocationSnapshot) {
        revocation = snapshot
        _uiState.update {
            it.copy(
                revocationSource = snapshot.source,
                revocationEntries = snapshot.entryCount,
                revocationFetchedAt = snapshot.fetchedAtMillis,
                revocationExpires = snapshot.expires,
                revocationError = snapshot.error,
            )
        }
    }

    private fun scanNotes(stats: ScanStats): List<String> = buildList {
        add("候选文件 ${stats.filesScanned} 个，其中 XML ${stats.xmlFiles} 个")
        add("确认为 keybox ${stats.confirmedKeyboxes} 个")
        if (stats.duplicates > 0) add("内容完全重复 ${stats.duplicates} 个")
        if (stats.notKeybox > 0) add("XML 但不是 keybox ${stats.notKeybox} 个")
        if (stats.unreadable > 0) add("无法读取 ${stats.unreadable} 个")
    }

    private fun setMessage(text: String) {
        _uiState.update { it.copy(message = text) }
    }

    private companion object {
        const val PREFS = "settings"
        const val KEY_PATH = "keybox_path"
        const val KEY_TREE_URI = "keybox_tree_uri"
        const val KEY_OUTPUT_DIR = "keybox_output_dir"
        const val KEY_LOCAL_DEVICE_ID = "keybox_local_device_id"
    }
}
