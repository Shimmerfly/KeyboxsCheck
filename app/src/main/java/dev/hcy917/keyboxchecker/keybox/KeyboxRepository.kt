package dev.hcy917.keyboxchecker.keybox

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import dev.hcy917.keyboxchecker.data.network.TelegramApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import java.io.File
import java.io.InputStream
import java.nio.charset.StandardCharsets

/** What a scan emits: progress while walking, then the finished report. */
sealed interface ScanEvent {
    data class Progress(val progress: ScanProgress) : ScanEvent
    data class Done(val report: ScanReport) : ScanEvent
}

/** Outcome of writing the confirmed keyboxes and the two report files. */
data class SaveResult(
    val directory: File,
    val saved: List<String>,
    val skipped: List<String>,
    val failed: List<String>,
    val reportFiles: List<File>,
)

/** Outcome of one Telegram channel poll. */
data class TelegramImport(
    val analyzed: List<AnalyzedKeybox>,
    val documentsFound: Int,
    val downloaded: Int,
    val errors: List<String>,
    val nextOffset: Long?,
)

/**
 * The only layer allowed to touch `android.*`.
 *
 * Everything about *deciding* what a keybox is lives in the pure-JVM engine
 * next to this file; this class only enumerates files, reads bytes, talks to
 * Telegram and writes results back to storage.
 */
class KeyboxRepository(
    private val context: Context,
    private val okHttpClient: OkHttpClient,
    private val nowMillis: () -> Long = System::currentTimeMillis,
) {

    /**
     * Raw bytes of every confirmed keybox seen during the most recent scan,
     * keyed by content digest. Keeping them here means "save confirmed" never
     * has to re-walk a SAF tree (which may have been revoked in the meantime).
     */
    private val capturedBytes = LinkedHashMap<String, ByteArray>()
    private var capturedTotal = 0L

    // --------------------------------------------------------------- revocation

    fun revocationCacheFile(): File = File(context.cacheDir, REVOCATION_CACHE_NAME)

    /** Loads the Google attestation status list, preferring a fresh cache. */
    fun loadRevocation(forceRefresh: Boolean = false): RevocationSnapshot {
        val loader = RevocationListLoader(
            client = okHttpClient,
            cacheFile = revocationCacheFile(),
            nowMillis = nowMillis,
        )
        return loader.load(forceRefresh)
    }

    // -------------------------------------------------------------------- scan

    /** Scans an absolute path. Used with the MANAGE_EXTERNAL_STORAGE grant. */
    fun scanPath(
        root: File,
        inputDescription: String,
        revocation: RevocationSnapshot,
    ): Flow<ScanEvent> = flow {
        emit(ScanEvent.Progress(ScanProgress(total = 0, phase = PHASE_ENUMERATING)))
        val candidates = collectFiles(root)
        emitAll(scanCandidates(candidates, inputDescription, revocation, KeyboxSource.LOCAL_PATH))
    }.flowOn(Dispatchers.IO)

    /** Scans a directory the user picked through the Storage Access Framework. */
    fun scanTree(
        treeUri: Uri,
        inputDescription: String,
        revocation: RevocationSnapshot,
    ): Flow<ScanEvent> = flow {
        emit(ScanEvent.Progress(total = 0, phase = PHASE_ENUMERATING))
        val candidates = collectDocuments(treeUri)
        emitAll(scanCandidates(candidates, inputDescription, revocation, KeyboxSource.LOCAL_PATH))
    }.flowOn(Dispatchers.IO)

    private fun scanCandidates(
        candidates: List<Candidate>,
        inputDescription: String,
        revocation: RevocationSnapshot,
        source: KeyboxSource,
    ): Flow<ScanEvent> = flow {
        resetCaptured()
        val analyzer = KeyboxAnalyzer(revocation, nowMillis)
        val analyzed = ArrayList<AnalyzedKeybox>(candidates.size)
        var notKeybox = 0
        var unreadable = 0

        emit(ScanEvent.Progress(ScanProgress(0, candidates.size, "", PHASE_SCANNING)))
        candidates.forEachIndexed { index, candidate ->
            currentCoroutineContext().ensureActive()
            emit(
                ScanEvent.Progress(
                    ScanProgress(index, candidates.size, candidate.displayName, PHASE_SCANNING),
                ),
            )
            val bytes = candidate.read()
            if (bytes == null) {
                unreadable++
                return@forEachIndexed
            }
            val text = decodeXml(bytes)
            if (text == null) {
                unreadable++
                return@forEachIndexed
            }
            val digest = Der.sha256(bytes)
            when (val outcome = KeyboxParser.parse(text, candidate.displayName)) {
                is ParseOutcome.Ok -> {
                    val result = analyzer.analyze(candidate.displayName, digest, outcome.keybox, source)
                    analyzed += result
                    if (result.isConfirmed) capture(digest, bytes)
                }

                is ParseOutcome.NotKeybox -> notKeybox++
            }
        }
        emit(ScanEvent.Progress(ScanProgress(candidates.size, candidates.size, "", PHASE_FINISHED)))

        emit(
            ScanEvent.Done(
                ReportWriter.assemble(
                    inputDescription = inputDescription,
                    analyzed = analyzed,
                    revocation = revocation,
                    filesScanned = candidates.size,
                    xmlFiles = candidates.size,
                    notKeybox = notKeybox,
                    unreadable = unreadable,
                    nowMillis = nowMillis(),
                ),
            ),
        )
    }

    // ---------------------------------------------------------------- telegram

    /**
     * Pulls the `.xml` documents the bot can see in [channel] and analyses them
     * with the same engine as a local scan, so both sets land in one report.
     */
    suspend fun importFromTelegram(
        botToken: String,
        channel: String,
        revocation: RevocationSnapshot,
        offset: Long?,
        onDocument: (String) -> Unit = {},
    ): TelegramImport = withContext(Dispatchers.IO) {
        val api = TelegramApi(okHttpClient, botToken)
        val batch = try {
            api.pollChannel(channel, offset)
        } catch (error: Exception) {
            return@withContext TelegramImport(
                analyzed = emptyList(),
                documentsFound = 0,
                downloaded = 0,
                errors = listOf(error.message ?: "拉取频道消息失败"),
                nextOffset = offset,
            )
        }

        val analyzer = KeyboxAnalyzer(revocation, nowMillis)
        val analyzed = ArrayList<AnalyzedKeybox>()
        val errors = ArrayList<String>()
        val seen = HashSet<String>()
        var downloaded = 0

        for (document in batch.documents) {
            currentCoroutineContext().ensureActive()
            if (!seen.add(document.fileUniqueId)) continue
            onDocument(document.fileName)

            val bytes = try {
                api.downloadDocument(document)
            } catch (error: Exception) {
                errors += "${document.fileName}：${error.message ?: "下载失败"}"
                continue
            }
            downloaded++

            val text = decodeXml(bytes)
            if (text == null) {
                errors += "${document.fileName}：无法解码文本内容"
                continue
            }
            when (val outcome = KeyboxParser.parse(text, document.fileName)) {
                is ParseOutcome.Ok -> {
                    val digest = Der.sha256(bytes)
                    val result = analyzer.analyze(document.fileName, digest, outcome.keybox, KeyboxSource.TELEGRAM)
                    analyzed += result
                    if (result.isConfirmed) capture(digest, bytes)
                }

                is ParseOutcome.NotKeybox -> errors += "${document.fileName}：${outcome.reason}"
            }
        }

        TelegramImport(
            analyzed = analyzed,
            documentsFound = batch.documents.size,
            downloaded = downloaded,
            errors = errors,
            nextOffset = batch.nextOffset,
        )
    }

    // ------------------------------------------------------------------- saving

    /** `getExternalFilesDir` when available, otherwise the private files dir. */
    fun defaultOutputDir(): File =
        context.getExternalFilesDir(OUTPUT_DIR_NAME) ?: File(context.filesDir, OUTPUT_DIR_NAME)

    fun takePersistable(uri: Uri): Boolean = runCatching {
        context.contentResolver.takePersistableUriPermission(
            uri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION,
        )
        true
    }.getOrDefault(false)

    /**
     * Writes every confirmed, non-duplicate keybox plus the two report files.
     *
     * Nothing is dropped silently: files we cannot write and files we skip are
     * both reported back so the UI can show them.
     */
    fun saveConfirmed(report: ScanReport, targetDir: File): SaveResult {
        val saved = ArrayList<String>()
        val skipped = ArrayList<String>()
        val failed = ArrayList<String>()

        for (keybox in report.keys) {
            val relative = "${deviceFolder(keybox.deviceId)}/${safeFileName(keybox.fileName)}"
            if (!keybox.isConfirmed) {
                skipped += "$relative（未确认为 keybox）"
                continue
            }
            if (keybox.duplicateOf != null) {
                skipped += "$relative（与 ${keybox.duplicateOf} 内容相同）"
                continue
            }
            val bytes = capturedBytes[keybox.contentSha256]
            if (bytes == null) {
                skipped += "$relative（内容已不在缓存中，请重新扫描后再保存）"
                continue
            }
            val destination = uniqueDestination(File(targetDir, relative), keybox.primaryKeyId)
            try {
                destination.parentFile?.mkdirs()
                destination.writeBytes(bytes)
                saved += destination.relativeTo(targetDir).path
            } catch (error: Exception) {
                failed += "$relative（${error.message ?: "写入失败"}）"
            }
        }

        val reportFiles = try {
            exportReport(report, targetDir)
        } catch (error: Exception) {
            failed += "报告写入失败：${error.message ?: error::class.java.simpleName}"
            emptyList()
        }

        return SaveResult(
            directory = targetDir,
            saved = saved,
            skipped = skipped,
            failed = failed,
            reportFiles = reportFiles,
        )
    }

    /** Writes `classification.json` and `report.md` into [targetDir]. */
    fun exportReport(report: ScanReport, targetDir: File): List<File> {
        targetDir.mkdirs()
        val stamp = ReportWriter.suggestedFileName("classification", "json", report.generatedAtMillis)
        val json = File(targetDir, "classification.json")
        val markdown = File(targetDir, "report.md")
        json.writeText(ReportWriter.toJson(report), Charsets.UTF_8)
        markdown.writeText(ReportWriter.toMarkdown(report), Charsets.UTF_8)
        // Keep a timestamped copy of the JSON so successive scans do not clobber each other.
        val archived = File(targetDir, "classification-$stamp.json")
        if (archived.absolutePath != json.absolutePath) {
            runCatching { archived.writeText(ReportWriter.toJson(report), Charsets.UTF_8) }
        }
        return listOf(json, markdown)
    }

    // -------------------------------------------------------------- enumeration

    private class Candidate(val displayName: String, val read: () -> ByteArray?)

    private fun collectFiles(root: File): List<Candidate> {
        val out = ArrayList<Candidate>()
        if (!root.exists()) return out
        if (root.isFile) {
            return if (isXmlName(root.name)) listOf(fileCandidate(root, root.name)) else emptyList()
        }

        val stack = ArrayDeque<Triple<File, Int, String?>>()
        stack.addLast(Triple(root, 0, null))
        while (stack.isNotEmpty()) {
            val (directory, depth, parentName) = stack.removeLast()
            if (depth > MAX_DEPTH) continue
            val children = directory.listFiles() ?: continue
            for (child in children) {
                if (child.isDirectory) {
                    if (shouldSkipDirectory(child.name, parentName)) continue
                    if (isSymbolicLink(child)) continue
                    stack.addLast(Triple(child, depth + 1, child.name))
                } else if (child.isFile && isXmlName(child.name)) {
                    out += fileCandidate(child, child.relativeTo(root).path)
                }
            }
        }
        return out
    }

    private fun fileCandidate(file: File, displayName: String): Candidate = Candidate(displayName) {
        if (file.length() > MAX_FILE_BYTES) {
            null
        } else {
            runCatching { file.readBytes() }.getOrNull()
        }
    }

    /**
     * Walks a SAF tree by hand: `androidx.documentfile` is deliberately not a
     * dependency of this project.
     */
    private fun collectDocuments(treeUri: Uri): List<Candidate> {
        val out = ArrayList<Candidate>()
        val rootId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull()
            ?: return out
        val stack = ArrayDeque<Triple<String, Int, String?>>()
        stack.addLast(Triple(rootId, 0, null))

        while (stack.isNotEmpty()) {
            val (documentId, depth, parentName) = stack.removeLast()
            if (depth > MAX_DEPTH) continue
            val childrenUri = runCatching {
                DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, documentId)
            }.getOrNull() ?: continue

            val cursor = runCatching {
                context.contentResolver.query(childrenUri, DOCUMENT_PROJECTION, null, null, null)
            }.getOrNull() ?: continue

            cursor.use { rows ->
                while (rows.moveToNext()) {
                    val childId = rows.getString(0) ?: continue
                    val name = rows.getString(1) ?: continue
                    val mimeType = rows.getString(2)
                    if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                        if (shouldSkipDirectory(name, parentName)) continue
                        stack.addLast(Triple(childId, depth + 1, name))
                    } else if (isXmlName(name)) {
                        val documentUri = runCatching {
                            DocumentsContract.buildDocumentUriUsingTree(treeUri, childId)
                        }.getOrNull() ?: continue
                        out += Candidate(name) { readDocument(documentUri) }
                    }
                }
            }
        }
        return out
    }

    private fun readDocument(uri: Uri): ByteArray? = runCatching {
        context.contentResolver.openInputStream(uri)?.use { stream ->
            stream.readCapped(MAX_FILE_BYTES)
        }
    }.getOrNull()

    // ----------------------------------------------------------------- helpers

    @Synchronized
    private fun capture(digest: String, bytes: ByteArray) {
        if (capturedTotal + bytes.size > MAX_CAPTURED_BYTES) return
        capturedBytes[digest] = bytes
        capturedTotal += bytes.size
    }

    @Synchronized
    private fun resetCaptured() {
        capturedBytes.clear()
        capturedTotal = 0L
    }

    private fun decodeXml(bytes: ByteArray): String? {
        if (bytes.isEmpty()) return null
        val text = when {
            bytes.size >= 3 && bytes[0] == UTF8_BOM_0 && bytes[1] == UTF8_BOM_1 && bytes[2] == UTF8_BOM_2 ->
                String(bytes, 3, bytes.size - 3, StandardCharsets.UTF_8)

            bytes.size >= 2 && bytes[0] == BOM_FF && bytes[1] == BOM_FE ->
                String(bytes, 2, bytes.size - 2, StandardCharsets.UTF_16LE)

            bytes.size >= 2 && bytes[0] == BOM_FE && bytes[1] == BOM_FF ->
                String(bytes, 2, bytes.size - 2, StandardCharsets.UTF_16BE)

            else -> runCatching { String(bytes, StandardCharsets.UTF_8) }.getOrNull()
        }
        return text?.takeIf { it.isNotBlank() }
    }

    private fun uniqueDestination(base: File, keyId: String?): File {
        if (!base.exists()) return base
        val suffix = keyId?.take(8) ?: "dup"
        val dot = base.name.lastIndexOf('.')
        val stem = if (dot > 0) base.name.substring(0, dot) else base.name
        val extension = if (dot > 0) base.name.substring(dot) else ""
        var index = 0
        while (true) {
            val extra = if (index == 0) "-$suffix" else "-$suffix-$index"
            val candidate = File(base.parentFile, "$stem$extra$extension")
            if (!candidate.exists()) return candidate
            index++
        }
    }

    private companion object {

        const val MAX_FILE_BYTES = 4L * 1024L * 1024L
        const val MAX_CAPTURED_BYTES = 64L * 1024L * 1024L
        const val MAX_DEPTH = 16
        const val REVOCATION_CACHE_NAME = "revocation.json"
        const val OUTPUT_DIR_NAME = "keyboxes"
        const val PHASE_ENUMERATING = "正在枚举文件"
        const val PHASE_SCANNING = "正在解析 keybox"
        const val PHASE_FINISHED = "分析完成"

        const val UTF8_BOM_0: Byte = 0xEF.toByte()
        const val UTF8_BOM_1: Byte = 0xBB.toByte()
        const val UTF8_BOM_2: Byte = 0xBF.toByte()
        const val BOM_FF: Byte = 0xFF.toByte()
        const val BOM_FE: Byte = 0xFE.toByte()

        val SKIPPED_DIRECTORIES = setOf(".git", ".gradle", ".idea", "node_modules", "build")

        /**
         * Skipping every `data` directory would silently drop real keybox
         * folders, so only the two Android directories that are unreadable
         * without special access are excluded.
         */
        fun shouldSkipDirectory(name: String, parentName: String?): Boolean {
            if (name in SKIPPED_DIRECTORIES) return true
            return parentName.equals("Android", ignoreCase = true) &&
                (name.equals("data", ignoreCase = true) || name.equals("obb", ignoreCase = true))
        }

        val DOCUMENT_PROJECTION = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
        )

        fun isXmlName(name: String): Boolean = name.endsWith(".xml", ignoreCase = true)

        fun isSymbolicLink(file: File): Boolean = runCatching {
            java.nio.file.Files.isSymbolicLink(file.toPath())
        }.getOrDefault(false)

        fun deviceFolder(deviceId: String?): String {
            val cleaned = deviceId?.trim().orEmpty()
                .replace(Regex("[^A-Za-z0-9._-]"), "_")
                .trim('_')
            return cleaned.ifEmpty { "unknown" }
        }

        fun safeFileName(name: String): String {
            val cleaned = name.substringAfterLast('/').substringAfterLast('\\')
                .replace(Regex("[^A-Za-z0-9._-]"), "_")
                .trim('.')
            return cleaned.ifEmpty { "keybox.xml" }
        }
    }
}

/** Reads at most [limit] bytes; returns null when the source is larger. */
private fun InputStream.readCapped(limit: Long): ByteArray? {
    val buffer = java.io.ByteArrayOutputStream()
    val chunk = ByteArray(64 * 1024)
    var total = 0L
    while (true) {
        val read = read(chunk)
        if (read < 0) break
        total += read
        if (total > limit) return null
        buffer.write(chunk, 0, read)
    }
    return buffer.toByteArray()
}
