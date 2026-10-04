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

/** Outcome of writing the confirmed keyboxes into the library. */
data class SaveResult(
    /** The library folder the files went into. */
    val directory: String,
    val saved: List<String>,
    val skipped: List<String>,
    val failed: List<String>,
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

    /** Everything about the library folder goes through `su`. */
    private val root = RootShell { scratchDir() }

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
            if (trimmed.isNotEmpty()) candidates += collectRootFiles(trimmed)
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

    /**
     * A directory the app can write and read back, used to stage files that
     * root produces.
     *
     * The external files dir is preferred because files root creates there are
     * relabelled for the owning app, which makes them readable without the app
     * having to fight SELinux over its own cache.
     */
    /**
     * Where root stages files it copies out of the module folder.
     *
     * Deliberately the app's own storage rather than external storage: the
     * emulated external volume is a FUSE mount where `chmod` and writes by
     * another uid behave differently per device, while the internal directory is
     * an ordinary file system both root and the app can reach.
     */
    private fun scratchDir(): File = File(context.cacheDir, SCRATCH_DIR_NAME)

    fun takePersistable(uri: Uri): Boolean = runCatching {
        context.contentResolver.takePersistableUriPermission(
            uri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION,
        )
        true
    }.getOrDefault(false)

    /**
     * Writes every confirmed, unexpired keybox that is not already held into the
     * library the TEESimulator module reads.
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
     * Only keyboxes are written: the folder belongs to the module, so a report
     * would be litter it never asked for. Nothing is dropped silently either —
     * files we cannot write and files we skip are both reported back so the UI
     * can show them.
     */
    fun saveConfirmed(
        report: ScanReport,
        localDeviceId: String,
    ): SaveResult {
        val saved = ArrayList<String>()
        val skipped = ArrayList<String>()
        val failed = ArrayList<String>()
        val deviceId = localDeviceId.trim()
        val library = LIBRARY_DIR

        fun skipAll(reason: String): SaveResult {
            report.keys.forEach { skipped += "${it.fileName}（$reason）" }
            return SaveResult(library, saved, skipped, failed)
        }

        if (deviceId.isEmpty()) return skipAll("未填写本机 ID")

        // Nothing is saved on a status nobody could establish. Without the list
        // every key reads as UNKNOWN, and writing "I could not check this" into
        // the library is worse than writing nothing at all.
        if (!report.revocation.isUsable) {
            return skipAll("吊销列表不可用，无法确认是否已被吊销，暂不保存")
        }

        // The library belongs to the TEESimulator module and is root-only.
        if (!root.available()) return skipAll("需要 root 权限才能写入 $library，暂不保存")
        if (!root.exists(library) && !root.makeDirectory(library)) {
            return skipAll("无法创建 $library，暂不保存")
        }

        val listed = root.listXml(library)
        if (listed == null) return skipAll("无法读取 $library，暂不保存")

        val taken = listed.mapTo(HashSet()) { it.name.lowercase(Locale.US) }
        val plan = SavePlanner.plan(
            keys = report.keys,
            availableDigests = capturedBytes.keys,
            libraryKeys = libraryKeyIds(listed),
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
            val fileName = "$name.xml"
            if (root.writeBytes("$library/$fileName", rewritten)) {
                taken += fileName.lowercase(Locale.US)
                saved += fileName
            } else {
                failed += "${keybox.fileName}（写入 $library 失败）"
            }
        }

        return SaveResult(library, saved, skipped, failed)
    }

    /** Why a planned file was not written, in the words of the notes list. */
    private fun skipReason(decision: SavePlanner.Decision): String = when (decision.outcome) {
        SavePlanner.Outcome.NOT_KEYBOX -> "未确认为 keybox"
        SavePlanner.Outcome.CONTENT_DUPLICATE -> "与 ${decision.detail} 内容相同"
        SavePlanner.Outcome.EXPIRED -> "证书已过期，不保存"
        SavePlanner.Outcome.REVOKED ->
            decision.detail?.let { "已被吊销（$it），不保存" } ?: "已被吊销，不保存"
        SavePlanner.Outcome.SUSPENDED ->
            decision.detail?.let { "已被暂停（$it），暂不保存" } ?: "已被暂停，暂不保存"
        SavePlanner.Outcome.UNCHECKED -> "未能确认吊销状态，暂不保存"
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
    private fun libraryKeyIds(listed: List<RootShell.RemoteFile>): Map<String, String> {
        val ids = HashMap<String, String>()
        val analyzer = KeyboxAnalyzer(OFFLINE_REVOCATION, nowMillis)
        for (file in listed) {
            if (file.sizeBytes > MAX_FILE_BYTES) continue
            val bytes = root.readBytes("$LIBRARY_DIR/${file.name}") ?: continue
            val text = decodeXml(bytes) ?: continue
            val outcome = KeyboxParser.parse(text, file.name)
            if (outcome !is ParseOutcome.Ok) continue
            val keybox = analyzer.analyze(
                file.name,
                Der.sha256(bytes),
                outcome.keybox,
                KeyboxSource.LOCAL_PATH,
            )
            keybox.keys.forEach { ids.putIfAbsent(it.keyId, file.name) }
        }
        return ids
    }

    // -------------------------------------------------------------- enumeration

    private class Candidate(val displayName: String, val read: () -> ByteArray?)

    /** Enumerates and reads a typed input path through `su`, not app permissions. */
    private fun collectRootFiles(path: String): List<Candidate> {
        if (!root.available()) {
            throw IllegalStateException("需要 root 权限才能扫描输入路径，请在授权提示中允许 root 后重试")
        }
        val rootPath = File(path).absolutePath.trimEnd('/').ifEmpty { "/" }
        val files = root.findXmlFiles(rootPath, MAX_DEPTH + 1)
            ?: throw IllegalStateException("root 无法枚举输入路径：$rootPath")

        return files.asSequence()
            .filterNot { shouldSkipRootPath(rootPath, it) }
            .map { filePath ->
                val displayName = when {
                    filePath == rootPath -> File(filePath).name.ifBlank { filePath }
                    rootPath == "/" -> filePath.removePrefix("/")
                    filePath.startsWith("$rootPath/") -> filePath.removePrefix("$rootPath/")
                    else -> File(filePath).name
                }
                Candidate(displayName) { root.readBytes(filePath, MAX_FILE_BYTES) }
            }
            .toList()
    }

    /** Keeps the existing directory exclusions while enumeration runs as root. */
    private fun shouldSkipRootPath(rootPath: String, filePath: String): Boolean {
        if (filePath == rootPath) return false
        val relative = when {
            rootPath == "/" -> filePath.removePrefix("/")
            filePath.startsWith("$rootPath/") -> filePath.removePrefix("$rootPath/")
            else -> return false
        }
        val directories = relative.split('/').dropLast(1)
        var parentName: String? = null
        for (directory in directories) {
            if (shouldSkipDirectory(directory, parentName)) return true
            parentName = directory
        }
        return false
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

    /**
     * The folder the TEESimulator module reads keyboxes from.
     *
     * It belongs to the module and is only reachable through `su`; the app never
     * writes anything else there, because a stray file would be litter in
     * somebody else's directory.
     */
    fun libraryPath(): String = LIBRARY_DIR

    /** Whether root can be obtained. Asks the user the first time. */
    fun rootAvailable(): Boolean = root.available()

    /**
     * Whether root has already been granted, without ever asking again.
     *
     * Re-entering a page must not fire a fresh prompt every time, so screens ask
     * this and only call [rootAvailable] or [requestRoot] from a button.
     */
    fun rootGranted(): Boolean = root.invocation != null

    /** Asks again, in case the user just granted or denied the prompt. */
    fun requestRoot(): Boolean = root.probe() != null

    /** The keyboxes already written by "save confirmed", newest first. */
    fun listSaved(): List<SavedKeybox> = SavedLibrary.of(listLibraryFiles())

    private fun listLibraryFiles(): List<SavedFile> =
        root.listXml(LIBRARY_DIR)
            ?.map { SavedFile(name = it.name, sizeBytes = it.sizeBytes, modifiedMillis = it.modifiedMillis) }
            .orEmpty()

    /**
     * Re-reads the saved keyboxes and analyses them with [revocation].
     *
     * The library is a root-only folder, so this reads each file through `su`
     * and parses it in memory with exactly the engine the keybox page uses; a
     * verdict here therefore means the same thing as a verdict there.
     */
    fun analyzeSaved(revocation: RevocationSnapshot): Map<String, AnalyzedKeybox> {
        val listed = root.listXml(LIBRARY_DIR).orEmpty()
        val analyzer = KeyboxAnalyzer(revocation, nowMillis)
        val out = LinkedHashMap<String, AnalyzedKeybox>()
        for (file in listed) {
            if (file.sizeBytes > MAX_FILE_BYTES) continue
            val bytes = root.readBytes("$LIBRARY_DIR/${file.name}") ?: continue
            val text = decodeXml(bytes) ?: continue
            val parsed = KeyboxParser.parse(text, file.name)
            if (parsed !is ParseOutcome.Ok) continue
            out[file.name] = analyzer.analyze(
                file.name,
                Der.sha256(bytes),
                parsed.keybox,
                KeyboxSource.LOCAL_PATH,
            )
        }
        return out
    }

    fun savedArchiveName(): String = SavedArchive.suggestedName(nowMillis())

    /** Reads the keyboxes an archive should carry, through root. */
    private fun archiveItems(keyboxes: List<SavedKeybox>): List<SavedArchive.Item> =
        keyboxes.mapNotNull { keybox ->
            val bytes = root.readBytes("$LIBRARY_DIR/${keybox.relativePath}") ?: return@mapNotNull null
            SavedArchive.Item(
                path = keybox.relativePath,
                modifiedMillis = keybox.savedAtMillis,
                bytes = bytes,
            )
        }

    /** Packs the library into a document the user chose through the SAF. */
    fun exportArchive(keyboxes: List<SavedKeybox>, uri: Uri): Int {
        val stream = context.contentResolver.openOutputStream(uri)
            ?: throw IllegalStateException("无法写入所选位置")
        return stream.use { SavedArchive.write(archiveItems(keyboxes), it) }
    }

    /**
     * Packs the library into a file the app itself can hand out, so it can be
     * shared through a `content://` uri. The app's own storage is the only place
     * a `FileProvider` path is declared for.
     */
    fun cacheArchive(keyboxes: List<SavedKeybox>, name: String): File {
        val directory = File(context.cacheDir, EXPORT_DIR_NAME).apply { mkdirs() }
        val file = File(directory, name)
        file.outputStream().use { SavedArchive.write(archiveItems(keyboxes), it) }
        return file
    }

    /** The `content://` uri other apps can read [file] from. */
    fun shareUri(file: File): Uri = FileProvider.getUriForFile(
        context,
        "${context.packageName}.fileprovider",
        file,
    )

    /** Deletes the named keyboxes from the library. */
    fun deleteSaved(relativePaths: List<String>): DeleteResult {
        val deleted = ArrayList<String>()
        val failed = ArrayList<String>()
        for (relative in relativePaths.distinct()) {
            if (root.delete("$LIBRARY_DIR/$relative")) {
                deleted += relative
            } else {
                failed += relative
            }
        }
        return DeleteResult(deleted, failed)
    }

    // ------------------------------------------------------------ module config

    /** What `/data/adb/teesim/config.json` says, or null when it cannot be read. */
    fun readTeessimConfig(): TeessimConfig.Document? {
        val text = root.readText("$LIBRARY_DIR/${TeessimConfig.FILE_NAME}") ?: return null
        return TeessimConfig.parse(text)
    }

    /**
     * Points every profile of the module's config at [fileName].
     *
     * Returns false when there is no config to change or it cannot be written;
     * the caller has already confirmed the "every profile" part with the user.
     */
    fun setTeessimKeybox(fileName: String): Boolean {
        val path = "$LIBRARY_DIR/${TeessimConfig.FILE_NAME}"
        val text = root.readText(path) ?: return false
        val updated = TeessimConfig.withKeybox(text, fileName) ?: return false
        return root.writeBytes(path, updated.toByteArray(Charsets.UTF_8))
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

        /** The folder the TEESimulator module serves keyboxes from. */
        const val LIBRARY_DIR = "/data/adb/teesim"

        /** Staging area for files root writes on the app's behalf. */
        const val SCRATCH_DIR_NAME = "root-tmp"
        const val EXPORT_DIR_NAME = "exports"

        /** A snapshot that has consulted nothing, for purely offline passes. */
        val OFFLINE_REVOCATION = RevocationSnapshot(emptyMap(), RevocationSource.NONE, 0L)
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
