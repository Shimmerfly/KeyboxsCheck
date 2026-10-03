package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Saving is the one place where a mistake is permanent: a keybox written twice
 * is a key the user has to hunt down and delete by hand. These tests pin the
 * rule that decides it — the key material decides, never the bytes, and never
 * only the files of the current scan.
 */
class SavePlannerTest {

    @Test
    fun `the same key in two files is written once`() {
        val plan = SavePlanner.plan(
            keys = listOf(
                analyzed("a.xml", "KEY-1", deviceId = "ORIGINAL"),
                analyzed("b.xml", "KEY-1", deviceId = "CLONED"),
            ),
            availableDigests = setOf("SHA-a.xml", "SHA-b.xml"),
            libraryKeys = emptyMap(),
        )

        assertEquals(SavePlanner.Outcome.SAVED, plan[0].outcome)
        assertEquals(SavePlanner.Outcome.REPEATED_KEY, plan[1].outcome)
        assertEquals("a.xml", plan[1].detail)
        assertEquals(listOf(true, false), plan.map { it.saveable })
    }

    @Test
    fun `a key the library already holds is not written again`() {
        val plan = SavePlanner.plan(
            keys = listOf(analyzed("again.xml", "KEY-1")),
            availableDigests = setOf("SHA-again.xml"),
            libraryKeys = mapOf("KEY-1" to "localdev1/20261003N58052.xml"),
        )

        assertEquals(SavePlanner.Outcome.IN_LIBRARY, plan[0].outcome)
        assertEquals("localdev1/20261003N58052.xml", plan[0].detail)
        assertFalse(plan[0].saveable)
    }

    @Test
    fun `an expired keybox is refused even when it comes first`() {
        val plan = SavePlanner.plan(
            keys = listOf(
                analyzed("expired.xml", "KEY-1", expired = true),
                analyzed("fresh.xml", "KEY-1"),
            ),
            availableDigests = setOf("SHA-expired.xml", "SHA-fresh.xml"),
            libraryKeys = emptyMap(),
        )

        // The expired one never reserves the key, so the usable copy still lands.
        assertEquals(SavePlanner.Outcome.EXPIRED, plan[0].outcome)
        assertEquals(SavePlanner.Outcome.SAVED, plan[1].outcome)
    }

    @Test
    fun `byte identical content is flagged before the key is examined`() {
        val plan = SavePlanner.plan(
            keys = listOf(
                analyzed("first.xml", "KEY-1", contentSha256 = "SAME"),
                analyzed("second.xml", "KEY-1", contentSha256 = "SAME").copy(duplicateOf = "first.xml"),
            ),
            availableDigests = setOf("SAME"),
            libraryKeys = emptyMap(),
        )

        assertEquals(SavePlanner.Outcome.SAVED, plan[0].outcome)
        assertEquals(SavePlanner.Outcome.CONTENT_DUPLICATE, plan[1].outcome)
        assertEquals("first.xml", plan[1].detail)
    }

    @Test
    fun `content that is no longer cached cannot be written`() {
        val plan = SavePlanner.plan(
            keys = listOf(analyzed("gone.xml", "KEY-1")),
            availableDigests = emptySet(),
            libraryKeys = emptyMap(),
        )

        assertEquals(SavePlanner.Outcome.MISSING_CONTENT, plan[0].outcome)
    }

    @Test
    fun `a file that is not a confirmed keybox is skipped`() {
        val broken = analyzed("broken.xml", "KEY-1").copy(keys = emptyList(), parseError = "XML 解析失败")
        val plan = SavePlanner.plan(
            keys = listOf(broken),
            availableDigests = emptySet(),
            libraryKeys = emptyMap(),
        )

        assertEquals(SavePlanner.Outcome.NOT_KEYBOX, plan[0].outcome)
    }

    @Test
    fun `files that hold different keys are all written`() {
        val plan = SavePlanner.plan(
            keys = listOf(analyzed("a.xml", "KEY-1"), analyzed("b.xml", "KEY-2")),
            availableDigests = setOf("SHA-a.xml", "SHA-b.xml"),
            libraryKeys = emptyMap(),
        )

        assertEquals(listOf(SavePlanner.Outcome.SAVED, SavePlanner.Outcome.SAVED), plan.map { it.outcome })
    }

    @Test
    fun `every input file gets exactly one decision in order`() {
        val keys = listOf(
            analyzed("one.xml", "KEY-1"),
            analyzed("two.xml", "KEY-2", expired = true),
            analyzed("three.xml", "KEY-1"),
        )
        val plan = SavePlanner.plan(
            keys = keys,
            availableDigests = setOf("SHA-one.xml", "SHA-two.xml", "SHA-three.xml"),
            libraryKeys = emptyMap(),
        )

        assertEquals(keys.map { it.fileName }, plan.map { it.keybox.fileName })
        assertEquals(
            listOf(
                SavePlanner.Outcome.SAVED,
                SavePlanner.Outcome.EXPIRED,
                SavePlanner.Outcome.REPEATED_KEY,
            ),
            plan.map { it.outcome },
        )
        assertNull(plan[0].detail)
    }

    private fun analyzed(
        fileName: String,
        keyId: String,
        deviceId: String? = null,
        expired: Boolean = false,
        contentSha256: String = "SHA-$fileName",
    ): AnalyzedKeybox {
        val key = AnalyzedKey(
            index = 0,
            algorithm = "ecdsa",
            keyId = keyId,
            identitySource = IdentitySource.PRIVATE_KEY,
            status = RevocationStatus.VALID,
            chainValid = true,
            expired = expired,
        )
        return AnalyzedKeybox(
            fileName = fileName,
            contentSha256 = contentSha256,
            deviceId = deviceId,
            keys = listOf(key),
            chainFingerprint = "CHAIN-$fileName",
            source = KeyboxSource.LOCAL_PATH,
        )
    }
}
