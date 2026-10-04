package dev.hcy917.keyboxchecker.keybox

import org.json.JSONObject

/**
 * The TEESimulator configuration that lives next to the library.
 *
 * `/data/adb/teesim/config.json` maps every profile — the module's word for a
 * per-app configuration — to the keybox file it should use, so the file the
 * module is actually serving is a property of that document and not of the
 * folder listing. The app reads it to mark the keybox that is in use, and writes
 * it back when the user picks a different one.
 *
 * Parsing never throws: a config the app cannot make sense of simply selects
 * nothing, and the library keeps working as a folder.
 */
object TeessimConfig {

    const val FILE_NAME = "config.json"

    /** One entry of the `profiles` object. */
    data class Profile(val name: String, val keybox: String?)

    /** A parsed config: every profile, and the file names they select. */
    data class Document(val version: Int?, val profiles: List<Profile>) {
        /** The keybox file names the profiles point at, without any path. */
        val selected: Set<String>
            get() = profiles.mapNotNull { it.keybox?.let(::fileNameOf) }
                .filter { it.isNotEmpty() }
                .toSet()

        /** Profile names that point at [fileName]. */
        fun profilesUsing(fileName: String): List<String> =
            profiles.filter { it.keybox?.let(::fileNameOf) == fileName }.map { it.name }
    }

    /** Parses [json], or returns null when it is not a usable config. */
    fun parse(json: String): Document? {
        val root = runCatching { JSONObject(json) }.getOrNull() ?: return null
        val profiles = root.optJSONObject("profiles") ?: return null
        val out = ArrayList<Profile>()
        for (name in profiles.keys()) {
            val profile = profiles.optJSONObject(name)
            out += Profile(name = name, keybox = profile?.optString("keybox")?.takeIf { it.isNotBlank() })
        }
        val version = if (root.has("version")) root.optInt("version") else null
        return Document(version = version, profiles = out)
    }

    /**
     * [json] with every profile pointed at [fileName].
     *
     * The module has one keybox per profile and the app offers one choice, so
     * choosing a keybox means choosing it everywhere; the caller says so in its
     * confirmation before this runs. Returns null when [json] cannot be parsed
     * or holds no profiles at all, because then there is nothing to select.
     */
    fun withKeybox(json: String, fileName: String): String? {
        val root = runCatching { JSONObject(json) }.getOrNull() ?: return null
        val profiles = root.optJSONObject("profiles") ?: return null
        if (!profiles.keys().hasNext()) return null
        for (name in profiles.keys()) {
            val profile = profiles.optJSONObject(name) ?: continue
            runCatching { profile.put("keybox", fileName) }
        }
        runCatching { root.put("profiles", profiles) }
        return runCatching { root.toString(2) }.getOrNull()
    }

    /** `/data/adb/teesim/keybox.xml` and `keybox.xml` both name `keybox.xml`. */
    fun fileNameOf(path: String): String = path.substringAfterLast('/').trim()
}
