package dev.hcy917.keyboxchecker.keybox

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import androidx.core.content.FileProvider
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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.random.Random

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

/** Outcome of deleting saved keyboxes from the library. */
data class DeleteResult(
    val deleted: List<String>,
    val failed: List<String>,
)

/**
 * The only layer allowed to touch `android.*`.
 *
 * Everything about *deciding* what a keybox is lives in the pure-JVM engine
 * next to this file; this class only enumerates files, reads bytes and writes
 * results back to storage.
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

    /**
     * Scans any mix of targets in one pass.
     *
     * A single keybox is as valid an input as a whole tree, so the three ways of
     * naming files — a granted SAF tree, plain paths (directories or individual
     * files) and individually picked SAF documents — are unioned rather than
     * treated as alternatives. Duplicates across the three are left alone: the
     * classifier already collapses byte-identical content.
     */
    fun scan(
        treeUri: Uri?,
        paths: List<String>,
        documents: List<Uri>,
        inputDescription: String,
        revocation: RevocationSnapshot,
    ): Flow<ScanEvent> = flow {
        emit(ScanEvent.Progress(ScanProgress(0, 0, "", PHASE_ENUMERATING)))
        val candidates = ArrayList<Candidate>()
        treeUri?.let { candidates += collectDocuments(it) }
        for (path in paths) {
            val trimmed = path.trim()
            if (trimmed.isNotEmpty()) candidates += collectFiles(File(trimmed))
        }
        for (uri in documents) candidates += documentCandidate(uri)
        emitAll(scanCandidates(candidates, inputDescription, revocation, KeyboxSource.LOCAL_PATH))
    }.flowOn(Dispatchers.IO)

    /** Scans an absolute path. Used with the MANAGE_EXTERNAL_STORAGE grant. */
    fun scanPath(
        root: File,
        inputDescription: String,
        revocation: RevocationSnapshot,
    ): Flow<ScanEvent> = scan(
        treeUri = null,
        paths = listOf(root.absolutePath),
        documents = emptyList(),
        inputDescription = inputDescription,
        revocation = revocation,
    )

    /** Scans a directory the user picked through the Storage Access Framework. */
    fun scanTree(
        treeUri: Uri,
        inputDescription: String,
        revocation: RevocationSnapshot,
    ): Flow<ScanEvent> = scan(
        treeUri = treeUri,
        paths = emptyList(),
        documents = emptyList(),
        inputDescription = inputDescription,
        revocation = revocation,
    )

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
     * Writes every confirmed, unexpired keybox that is not already held, plus
     * the report files.
     *
     * A keybox is judged by the key it carries, never by its bytes: two files
     * whose editable `DeviceID` (or a stray space) differ are still the same
     * certificate to the device, so only the first of them is written and the
     * other is reported as a repeat. The same comparison is made against the
     * library that is already on disk, so re-scanning a folder never grows the
     * collection with copies of a key it already holds.
     *
     * Saved files are neutralised: they are renamed to `yyyyMMddR|N#####` (R for
     * a remotely provisioned keybox, N otherwise, five digits that are unique
     * within the day) and their `DeviceID` is replaced with [localDeviceId], so
     * a collection pulled from several sources looks uniform and carries no
     * source device identity.
     *
     * Nothing is dropped silently: files we cannot write and files we skip are
     * both reported back so the UI can show them.
     */
    fun saveConfirmed(
        report: ScanReport,
        targetDir: File,
        localDeviceId: String,
    ): SaveResult {
        val saved = ArrayList<String>()
        val skipped = ArrayList<String>()
        val failed = ArrayList<String>()
        val deviceId = localDeviceId.trim()

        if (deviceId.isEmpty()) {
            report.keys.forEach { skipped += "${it.fileName}（未填写本机 ID）" }
            return SaveResult(targetDir, saved, skipped, failed, emptyList())
        }

        val folder = File(targetDir, deviceFolder(deviceId))
        val taken = existingNames(targetDir)
        val plan = SavePlanner.plan(
            keys = report.keys,
            availableDigests = capturedBytes.keys,
            libraryKeys = libraryKeyIds(targetDir),
        )

        for (decision in plan) {
            val keybox = decision.keybox
            if (!decision.saveable) {
                skipped += "${keybox.fileName}（${skipReason(decision)}）"
                continue
            }
            val bytes = capturedBytes[keybox.contentSha256]
            if (bytes == null) {
                skipped += "${keybox.fileName}（内容已不在缓存中，请重新扫描后再保存）"
                continue
            }
            val rewritten = rewriteDeviceId(bytes, deviceId)
            if (rewritten == null) {
                skipped += "${keybox.fileName}（无法改写 DeviceID）"
                continue
            }
            val name = nextKeyboxName(taken, keybox.remoteProvisioned, nowMillis())
            val destination = File(folder, "$name.xml")
            try {
                destination.parentFile?.mkdirs()
                destination.writeBytes(rewritten)
                taken += "$name.xml"
                saved += destination.relativeTo(targetDir).path
            } catch (error: Exception) {
                failed += "${keybox.fileName}（${error.message ?: "写入失败"}）"
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

    /** Why a planned file was not written, in the words of the notes list. */
    private fun skipReason(decision: SavePlanner.Decision): String = when (decision.outcome) {
        SavePlanner.Outcome.NOT_KEYBOX -> "未确认为 keybox"
        SavePlanner.Outcome.CONTENT_DUPLICATE -> "与 ${decision.detail} 内容相同"
        SavePlanner.Outcome.EXPIRED -> "证书已过期，不保存"
        SavePlanner.Outcome.IN_LIBRARY -> "本地库中已有同一个密钥：${decision.detail}"
        SavePlanner.Outcome.REPEATED_KEY -> "与 ${decision.detail} 是同一个密钥"
        SavePlanner.Outcome.MISSING_CONTENT -> "内容已不在缓存中，请重新扫描后再保存"
        SavePlanner.Outcome.SAVED -> "已保存"
    }

    /**
     * Key ids the library already holds, mapped to the file that carries them.
     *
     * The saved files are re-read and re-analysed here instead of being
     * remembered from the last save, so a key written by an older build, or a
     * keybox copied into the folder by hand, is recognised just the same. Only
     * the key identity is read: the revocation list is deliberately not
     * consulted, so this stays offline and fast.
     */
    private fun libraryKeyIds(root: File): Map<String, String> {
        if (!root.isDirectory) return emptyMap()
        val ids = HashMap<String, String>()
        val offline = RevocationSnapshot(emptyMap(), RevocationSource.NONE, 0L)
        val analyzer = KeyboxAnalyzer(offline, nowMillis)
        for (entry in SavedLibrary.list(root)) {
            val file = File(root, entry.relativePath)
            if (file.length() > MAX_FILE_BYTES) continue
            val bytes = runCatching { file.readBytes() }.getOrNull() ?: continue
            val text = decodeXml(bytes) ?: continue
            val outcome = KeyboxParser.parse(text, entry.relativePath)
            if (outcome !is ParseOutcome.Ok) continue
            val keybox = analyzer.analyze(
                entry.relativePath,
                Der.sha256(bytes),
                outcome.keybox,
                KeyboxSource.LOCAL_PATH,
            )
            keybox.primaryKeyId?.let { ids.putIfAbsent(it, entry.relativePath) }
        }
        return ids
    }

    /** Writes `classification.json` and `report.md` into [targetDir]. */
    fun exportReport(report: ScanReport, targetDir: File): List<File> {
        targetDir.mkdirs()
        val json = File(targetDir, "classification.json")
        val markdown = File(targetDir, "report.md")
        json.writeText(ReportWriter.toJson(report), Charsets.UTF_8)
        markdown.writeText(ReportWriter.toMarkdown(report), Charsets.UTF_8)
        // Keep a timestamped copy of the JSON so successive scans do not clobber each other.
        val archived = File(
            targetDir,
            ReportWriter.suggestedFileName("classification", "json", report.generatedAtMillis),
        )
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

    private fun documentCandidate(uri: Uri): Candidate =
        Candidate(documentLabel(uri)) { readDocument(uri) }

    /** The name a picked SAF document shows in the results table. */
    fun documentLabel(uri: Uri): String = displayNameOf(uri)
        ?: uri.lastPathSegment?.substringAfterLast('/')?.takeIf { it.isNotBlank() }
        ?: uri.toString()

    private fun displayNameOf(uri: Uri): String? = runCatching {
        context.contentResolver
            .query(uri, arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)
            ?.use { rows -> if (rows.moveToFirst()) rows.getString(0) else null }
    }.getOrNull()

    // ------------------------------------------------------------------ library

    /** The keyboxes already written by "save confirmed", newest first. */
    fun listSaved(): List<SavedKeybox> = SavedLibrary.list(defaultOutputDir())

    /** Relative paths the archive of [keyboxes] should carry. */
    fun savedArchiveEntries(keyboxes: List<SavedKeybox>): List<String> =
        SavedArchive.entries(defaultOutputDir(), keyboxes)

    fun savedArchiveName(): String = SavedArchive.suggestedName(nowMillis())

    /** Packs the library into a document the user chose through the SAF. */
    fun exportArchive(entries: List<String>, uri: Uri): Int {
        val stream = context.contentResolver.openOutputStream(uri)
            ?: throw IllegalStateException("无法写入所选位置")
        return stream.use { SavedArchive.write(defaultOutputDir(), entries, it) }
    }

    /**
     * Packs the library into the app cache so it can be handed to another app
     * through a `content://` uri. The cache is the only place a `FileProvider`
     * path is declared for, and the OS clears it on its own schedule.
     */
    fun cacheArchive(entries: List<String>, name: String): File {
        val directory = File(context.cacheDir, EXPORT_DIR_NAME).apply { mkdirs() }
        val file = File(directory, name)
        file.outputStream().use { SavedArchive.write(defaultOutputDir(), entries, it) }
        return file
    }

    /** The `content://` uri other apps can read [file] from. */
    fun shareUri(file: File): Uri = FileProvider.getUriForFile(
        context,
        "${context.packageName}.fileprovider",
        file,
    )

    /**
     * Deletes saved keyboxes and prunes the device folders they leave empty, so
     * a library that has had everything revoked deleted does not keep a trail of
     * empty directories behind.
     */
    fun deleteSaved(relativePaths: List<String>): DeleteResult {
        val root = defaultOutputDir()
        val deleted = ArrayList<String>()
        val failed = ArrayList<String>()
        for (relative in relativePaths.distinct()) {
            val file = File(root, relative)
            val removed = runCatching { file.delete() }.getOrDefault(false)
            if (removed) {
                deleted += relative
                file.parentFile?.let { parent ->
                    if (parent != root && parent.list()?.isEmpty() == true) {
                        runCatching { parent.delete() }
                    }
                }
            } else {
                failed += relative
            }
        }
        return DeleteResult(deleted, failed)
    }

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

    /** Every file name already present under [targetDir], lower-cased, depth ≤ 2. */
    private fun existingNames(targetDir: File): MutableSet<String> {
        val names = HashSet<String>()
        val stack = ArrayDeque<Pair<File, Int>>()
        stack += targetDir to 0
        while (stack.isNotEmpty()) {
            val (directory, depth) = stack.removeLast()
            val children = directory.listFiles() ?: continue
            for (child in children) {
                if (child.isDirectory) {
                    if (depth < 2) stack += child to (depth + 1)
                } else {
                    names += child.name.lowercase(Locale.US)
                }
            }
        }
        return names
    }

    /**
     * `yyyyMMdd` + `R` (remotely provisioned) or `N` + five digits, e.g.
     * `20261003R12345`.
     *
     * The digits are drawn at random and re-drawn while the result collides with
     * anything already saved that day, so a batch of keyboxes never overwrites an
     * earlier one.
     */
    private fun nextKeyboxName(
        taken: MutableSet<String>,
        remoteProvisioned: Boolean,
        nowMillis: Long,
    ): String {
        val date = SimpleDateFormat("yyyyMMdd", Locale.US).format(Date(nowMillis))
        val letter = if (remoteProvisioned) "R" else "N"
        repeat(MAX_NAME_ATTEMPTS) {
            val digits = Random.nextInt(100_000).toString().padStart(5, '0')
            val name = "$date$letter$digits"
            if ("$name.xml" !in taken) return name
        }
        // Exhausting 100000 random draws means the day is almost full; fall back
        // to a linear probe so the loop always terminates.
        var counter = 0
        while (true) {
            val name = "$date$letter" + counter.toString().padStart(5, '0')
            if ("$name.xml" !in taken) return name
            counter++
        }
    }

    /** Returns the keybox with its `DeviceID` replaced, still UTF-8 XML. */
    private fun rewriteDeviceId(bytes: ByteArray, deviceId: String): ByteArray? {
        val text = decodeXml(bytes) ?: return null
        return rewriteDeviceIdIn(text, deviceId).toByteArray(StandardCharsets.UTF_8)
    }

    private fun rewriteDeviceIdIn(xml: String, deviceId: String): String {
        if (DEVICE_ID_ATTRIBUTE.containsMatchIn(xml)) {
            return DEVICE_ID_ATTRIBUTE.replace(xml) { match ->
                match.groupValues[1] + "=\"" + deviceId + "\""
            }
        }
        if (DEVICE_ID_ELEMENT.containsMatchIn(xml)) {
            return DEVICE_ID_ELEMENT.replace(xml) { match ->
                val prefix = match.groupValues[1]
                "<${prefix}DeviceID>$deviceId</${prefix}DeviceID>"
            }
        }
        // No identifier at all: give every <Keybox> the attribute.
        return KEYBOX_ELEMENT.replace(xml) { match ->
            "<" + match.groupValues[1] + "Keybox DeviceID=\"" + deviceId + "\"" + match.groupValues[2]
        }
    }

    private companion object {

        const val MAX_FILE_BYTES = 4L * 1024L * 1024L
        const val MAX_CAPTURED_BYTES = 64L * 1024L * 1024L
        const val MAX_DEPTH = 16
        const val MAX_NAME_ATTEMPTS = 500
        const val REVOCATION_CACHE_NAME = "revocation.json"
        const val OUTPUT_DIR_NAME = "keyboxes"
        const val EXPORT_DIR_NAME = "exports"
        const val PHASE_ENUMERATING = "正在枚举文件"
        const val PHASE_SCANNING = "正在解析 keybox"
        const val PHASE_FINISHED = "分析完成"

        val DEVICE_ID_ATTRIBUTE =
            Regex("""((?:[\w.-]+:)?(?:DeviceID|DeviceId))\s*=\s*"[^"]*"""", RegexOption.IGNORE_CASE)

        val DEVICE_ID_ELEMENT = Regex(
            "<((?:[\\w.-]+:)?)(?:DeviceID|DeviceId)\\s*>[^<]*</\\1(?:DeviceID|DeviceId)\\s*>",
            setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
        )

        val KEYBOX_ELEMENT = Regex("<((?:[\\w.-]+:)?)Keybox(\\s[^>]*|/?>)", RegexOption.IGNORE_CASE)

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
