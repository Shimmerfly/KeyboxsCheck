package dev.hcy917.keyboxchecker.keybox

import java.io.File

/**
 * Runs commands as root.
 *
 * The library lives in `/data/adb/teesim`, which belongs to the TEESimulator
 * module and is only readable by root, so every listing, read, write and delete
 * below goes through `su`. Two dialects exist in the wild: Magisk and KernelSU
 * take the whole command after `-c`, while the AOSP `su` on userdebug builds
 * takes a target uid followed by the command. Both are tried once and whichever
 * answers is remembered for the rest of the session.
 *
 * Nothing here is Android-specific: the shell is started with [ProcessBuilder]
 * and the scratch directory is supplied by the caller, so the command lines
 * themselves stay unit-testable.
 */
class RootShell(private val scratchDir: () -> File) {

    /** How this device's `su` accepts a command. */
    enum class Invocation(val label: String) {
        COMMAND("su -c"),
        UID_SHELL("su 0 sh -c"),
    }

    data class Outcome(val code: Int, val output: String) {
        val ok: Boolean get() = code == 0
    }

    /** One file in a root-only directory, as `ls`/`stat` describe it. */
    data class RemoteFile(val name: String, val sizeBytes: Long, val modifiedMillis: Long)

    /** The dialect that worked, or null while nothing has been tried yet. */
    var invocation: Invocation? = null
        private set

    /** The `su` that answered; Magisk and KernelSU ship one, AOSP another. */
    var binary: String = BINARIES.first()
        private set

    /** The argv for [command] under [invocation]; pure, so it can be tested. */
    fun argv(invocation: Invocation, command: String): List<String> =
        argv(binary, invocation, command)

    /** The argv for [command] run by [binary] with [invocation]. */
    fun argv(binary: String, invocation: Invocation, command: String): List<String> = when (invocation) {
        Invocation.COMMAND -> listOf(binary, "-c", command)
        Invocation.UID_SHELL -> listOf(binary, "0", "sh", "-c", command)
    }

    /**
     * Whether root can be obtained, asking the user the first time.
     *
     * The superuser app shows its prompt on the first call, which is exactly the
     * moment the user asked for something that needs it.
     */
    fun available(): Boolean = invocation != null || probe() != null

    /** Tries each `su` and dialect until one answers as uid 0. */
    @Synchronized
    fun probe(): Invocation? {
        invocation?.let { return it }
        for (candidate in BINARIES) {
            for (dialect in Invocation.entries) {
                val outcome = exec(candidate, dialect, "id") ?: continue
                if (outcome.ok && outcome.output.contains("uid=0")) {
                    binary = candidate
                    invocation = dialect
                    return dialect
                }
            }
        }
        return null
    }

    fun run(command: String): Outcome? {
        val invocation = invocation ?: probe() ?: return null
        return exec(binary, invocation, command)
    }

    private fun exec(binary: String, invocation: Invocation, command: String): Outcome? = runCatching {
        val process = ProcessBuilder(argv(binary, invocation, command))
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        Outcome(process.waitFor(), output)
    }.getOrNull()

    // -------------------------------------------------------------- file access

    /** True when the file or directory exists. */
    fun exists(remotePath: String): Boolean =
        run("[ -e ${quote(remotePath)} ] && echo yes")?.output?.contains("yes") == true

    fun makeDirectory(remotePath: String): Boolean =
        run("mkdir -p ${quote(remotePath)}")?.ok == true

    /**
     * The bytes of a root-only file.
     *
     * The file is copied into [scratchDir] first because the app cannot open a
     * path under `/data/adb` at all; the copy is `chmod 644` so the app — which
     * owns the directory but not the file — can read what root wrote.
     */
    fun readBytes(remotePath: String): ByteArray? {
        val scratch = scratchFile() ?: return null
        return try {
            val outcome = run(
                "cat ${quote(remotePath)} > ${quote(scratch.absolutePath)}" +
                    " && chmod 644 ${quote(scratch.absolutePath)}",
            )
            if (outcome?.ok != true) return null
            runCatching { scratch.readBytes() }.getOrNull()
        } finally {
            scratch.delete()
        }
    }

    fun readText(remotePath: String): String? =
        readBytes(remotePath)?.toString(Charsets.UTF_8)

    /** Writes [bytes] to [remotePath], creating the parent directory if needed. */
    fun writeBytes(remotePath: String, bytes: ByteArray): Boolean {
        val scratch = scratchFile() ?: return false
        return try {
            scratch.parentFile?.mkdirs()
            if (runCatching { scratch.writeBytes(bytes) }.isFailure) return false
            val parent = remotePath.substringBeforeLast('/', "")
            val prefix = if (parent.isEmpty()) "" else "mkdir -p ${quote(parent)} && "
            val outcome = run(
                prefix + "cp ${quote(scratch.absolutePath)} ${quote(remotePath)}" +
                    " && chmod 644 ${quote(remotePath)}",
            )
            outcome?.ok == true
        } finally {
            scratch.delete()
        }
    }

    /** `*.xml` files directly inside [remoteDir], or null when it cannot be read. */
    fun listXml(remoteDir: String): List<RemoteFile>? {
        val command = buildString {
            append("cd ").append(quote(remoteDir)).append(" 2>/dev/null || exit 1; ")
            append("for f in *.xml; do [ -f \"\$f\" ] || continue; ")
            append("printf '%s|%s|%s\\n' \"\$f\" ")
            append("\"\$(stat -c %s \"\$f\" 2>/dev/null)\" ")
            append("\"\$(stat -c %Y \"\$f\" 2>/dev/null)\"; done")
        }
        val outcome = run(command) ?: return null
        if (outcome.code == 1) return null
        return outcome.output.lineSequence()
            .mapNotNull { parseListing(it) }
            .toList()
    }

    /** Deletes one file, whether or not it was there. */
    fun delete(remotePath: String): Boolean = run("rm -f ${quote(remotePath)}")?.ok == true

    /** `name|size|mtime`; a missing `stat` leaves the numeric fields empty. */
    internal fun parseListing(line: String): RemoteFile? {
        val parts = line.trim().split('|')
        if (parts.size != 3) return null
        val name = parts[0].trim()
        if (name.isEmpty() || name.contains('/')) return null
        return RemoteFile(
            name = name,
            sizeBytes = parts[1].trim().toLongOrNull() ?: 0L,
            modifiedMillis = parts[2].trim().toLongOrNull()?.times(1000L) ?: 0L,
        )
    }

    /** A free name inside the scratch directory; also used for zip staging. */
    fun scratchFile(suffix: String = "tmp"): File? = runCatching {
        val directory = scratchDir().apply { mkdirs() }
        File.createTempFile("root-", ".$suffix", directory)
    }.getOrNull()

    /** Single-quoted for `sh`, so a file name can never break out of it. */
    internal fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    companion object {
        /**
         * Where `su` may live, in the order worth trying: most devices put it on
         * `PATH`, Magisk and KernelSU use `/system/bin`, and old userdebug images
         * only have `/system/xbin`.
         */
        private val BINARIES = listOf("su", "/system/bin/su", "/system/xbin/su")
    }
}
