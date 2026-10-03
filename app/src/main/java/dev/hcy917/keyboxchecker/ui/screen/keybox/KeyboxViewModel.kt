package dev.hcy917.keyboxchecker.ui.screen.keybox

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.hcy917.keyboxchecker.keybox.AnalyzedKeybox
import dev.hcy917.keyboxchecker.keybox.KeyboxRepository
import dev.hcy917.keyboxchecker.keybox.ReportWriter
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
 * Drives one keybox scan.
 *
 * The ViewModel owns two independent result sets — the local scan and the
 * Telegram channel — and recombines them through [ReportWriter] so both sources
 * end up in one classification. The Telegram bot token is written to private
 * SharedPreferences only; it never reaches a report, a log or version control.
 */
class KeyboxViewModel : ViewModel() {

    private val repository = KeyboxRepository(templateApp, templateApp.okhttpClient)

    private val prefs
        get() = templateApp.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val _uiState = MutableStateFlow(buildInitialState())
    val uiState: StateFlow<KeyboxUiState> = _uiState.asStateFlow()

    private var revocation: RevocationSnapshot = RevocationSnapshot.EMPTY
    private var scanJob: Job? = null
    private var importJob: Job? = null

    /** Set when the user picks a directory through the Storage Access Framework. */
    private var treeUri: Uri? = null

    private var localKeys: List<AnalyzedKeybox> = emptyList()
    private var localStats = ScanStats()
    private var localDescription = ""
    private var telegramKeys: List<AnalyzedKeybox> = emptyList()
    private var telegramDocuments = 0
    private var telegramErrors = 0

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

    fun onBotTokenChanged(value: String) {
        prefs.edit().putString(KEY_BOT_TOKEN, value).apply()
        _uiState.update { it.copy(tgBotToken = value) }
    }

    fun onChannelChanged(value: String) {
        prefs.edit().putString(KEY_CHANNEL, value).apply()
        _uiState.update { it.copy(tgChannel = value) }
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
        importJob?.cancel()
        _uiState.update { it.copy(isScanning = false, isImporting = false, progress = null) }
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
            localDescription = description
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

                        is ScanEvent.Done -> {
                            localKeys = event.report.keys
                            localStats = event.report.stats
                            // A fresh local scan invalidates the previous channel import.
                            telegramKeys = emptyList()
                            telegramDocuments = 0
                            telegramErrors = 0
                            rebuild(notes = scanNotes(event.report.stats))
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

    // ----------------------------------------------------------------- telegram

    fun onImportFromTelegram() {
        if (_uiState.value.isImporting) return
        val token = _uiState.value.tgBotToken.trim()
        val channel = _uiState.value.tgChannel.trim()
        if (token.isEmpty()) {
            setMessage("请先填写 Telegram Bot Token")
            return
        }
        if (channel.isEmpty()) {
            setMessage("请先填写频道 ID 或用户名（私有频道请用 -100 开头的数字 ID）")
            return
        }

        importJob = viewModelScope.launch {
            _uiState.update { it.copy(isImporting = true, message = null) }
            val snapshot = ensureRevocation()
            val offset = prefs.getString(KEY_UPDATE_OFFSET, null)?.toLongOrNull()
            try {
                val result = repository.importFromTelegram(token, channel, snapshot, offset) { name ->
                    _uiState.update {
                        it.copy(progress = dev.hcy917.keyboxchecker.keybox.ScanProgress(0, 0, name, "正在拉取频道文件"))
                    }
                }
                result.nextOffset?.let { prefs.edit().putString(KEY_UPDATE_OFFSET, it.toString()).apply() }
                telegramKeys = result.analyzed
                telegramDocuments += result.documentsFound
                telegramErrors += result.errors.size
                rebuild(notes = result.errors)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                setMessage(error.message ?: "从频道导入失败")
            } finally {
                _uiState.update { it.copy(isImporting = false, progress = null) }
            }
        }
    }

    // -------------------------------------------------------------------- saving

    fun onSaveConfirmed() {
        val report = _uiState.value.report
        if (report == null) {
            setMessage("请先扫描目录或从频道导入后再保存")
            return
        }
        viewModelScope.launch {
            val directory = File(
                _uiState.value.outputDir.ifBlank { repository.defaultOutputDir().absolutePath },
            )
            val result = withContext(Dispatchers.IO) { repository.saveConfirmed(report, directory) }
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
            tgBotToken = prefs.getString(KEY_BOT_TOKEN, "").orEmpty(),
            tgChannel = prefs.getString(KEY_CHANNEL, "").orEmpty(),
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

    /**
     * Recombines both result sets into one report. Rebuilding from the union is
     * what makes local files and channel files comparable: grouping, duplicate
     * detection and chain variants are all recomputed across the two sources.
     */
    private fun rebuild(notes: List<String>, message: String? = null) {
        val report = ReportWriter.assemble(
            inputDescription = describeInput(),
            analyzed = localKeys + telegramKeys,
            revocation = revocation,
            filesScanned = localStats.filesScanned + telegramDocuments,
            xmlFiles = localStats.xmlFiles + telegramDocuments,
            notKeybox = localStats.notKeybox,
            unreadable = localStats.unreadable + telegramErrors,
        )
        _uiState.update {
            it.copy(
                report = report,
                groups = report.groups,
                progress = null,
                message = message ?: it.message,
                notes = notes,
            )
        }
    }

    private fun describeInput(): String {
        val parts = ArrayList<String>(2)
        if (localDescription.isNotBlank()) parts += localDescription
        if (telegramDocuments > 0 || telegramKeys.isNotEmpty()) {
            parts += "Telegram:${_uiState.value.tgChannel.trim().ifEmpty { "?" }}"
        }
        return parts.joinToString(" + ").ifEmpty { "未指定输入" }
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
        const val KEY_BOT_TOKEN = "tg_bot_token"
        const val KEY_CHANNEL = "tg_channel_id"
        const val KEY_UPDATE_OFFSET = "tg_update_offset"
    }
}
