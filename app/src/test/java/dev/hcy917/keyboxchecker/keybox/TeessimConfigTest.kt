package dev.hcy917.keyboxchecker.keybox

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The module's config decides which keybox is in use, so which file the screen
 * marks as current — and what the app writes back when the user picks another —
 * is worth pinning down.
 */
class TeessimConfigTest {

    private val sample = """
        {
          "version": 1,
          "profiles": {
            "default": {
              "keybox": "keybox.xml",
              "mode": "patch"
            },
            "gms": {
              "keybox": "/data/adb/teesim/20261003N58052.xml",
              "mode": "patch"
            }
          }
        }
    """.trimIndent()

    @Test
    fun `every profile and its keybox is read back`() {
        val document = TeessimConfig.parse(sample)!!

        assertEquals(1, document.version)
        assertEquals(setOf("default", "gms"), document.profiles.map { it.name }.toSet())
        assertEquals(
            setOf("keybox.xml", "20261003N58052.xml"),
            document.selected,
        )
    }

    @Test
    fun `the profiles using a file are named, whatever path they wrote`() {
        val document = TeessimConfig.parse(sample)!!

        assertEquals(listOf("gms"), document.profilesUsing("20261003N58052.xml"))
        assertEquals(listOf("default"), document.profilesUsing("keybox.xml"))
        assertEquals(emptyList<String>(), document.profilesUsing("elsewhere.xml"))
    }

    @Test
    fun `a profile without a keybox selects nothing`() {
        val document = TeessimConfig.parse("""{"profiles":{"default":{}}}""")!!

        assertEquals(listOf(TeessimConfig.Profile("default", null)), document.profiles)
        assertTrue(document.selected.isEmpty())
    }

    @Test
    fun `a config the app cannot read selects nothing instead of failing`() {
        assertNull(TeessimConfig.parse("not json at all"))
        assertNull(TeessimConfig.parse("[]"))
        assertNull(TeessimConfig.parse("{}"))
        assertNull(TeessimConfig.parse("""{"version":1}"""))
    }

    @Test
    fun `choosing a keybox points every profile at it and keeps the rest`() {
        val written = TeessimConfig.withKeybox(sample, "20261004N00001.xml")!!
        val root = JSONObject(written)

        val profiles = root.getJSONObject("profiles")
        assertEquals("20261004N00001.xml", profiles.getJSONObject("default").getString("keybox"))
        assertEquals("20261004N00001.xml", profiles.getJSONObject("gms").getString("keybox"))
        // Everything the app does not own has to survive the round trip.
        assertEquals("patch", profiles.getJSONObject("default").getString("mode"))
        assertEquals(1, root.getInt("version"))

        val reread = TeessimConfig.parse(written)!!
        assertEquals(setOf("20261004N00001.xml"), reread.selected)
        assertEquals(listOf("default", "gms"), reread.profilesUsing("20261004N00001.xml").sorted())
    }

    @Test
    fun `a config with no profiles cannot be pointed anywhere`() {
        assertNull(TeessimConfig.withKeybox("""{"version":1,"profiles":{}}""", "a.xml"))
        assertNull(TeessimConfig.withKeybox("not json", "a.xml"))
        assertNull(TeessimConfig.withKeybox("""{"version":1}""", "a.xml"))
    }

    @Test
    fun `a bare name and a full path both name the same file`() {
        assertEquals("keybox.xml", TeessimConfig.fileNameOf("keybox.xml"))
        assertEquals("keybox.xml", TeessimConfig.fileNameOf("/data/adb/teesim/keybox.xml"))
        assertEquals("20261003N58052.xml", TeessimConfig.fileNameOf("  20261003N58052.xml  "))
    }

    @Test
    fun `the config file name is the one the module uses`() {
        assertEquals("config.json", TeessimConfig.FILE_NAME)
        assertFalse(TeessimConfig.FILE_NAME.startsWith("/"))
    }
}
