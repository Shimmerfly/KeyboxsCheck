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

    @Test
    fun `a revoked key is never written`() {
        val plan = SavePlanner.plan(
            keys = listOf(analyzed("leaked.xml", "KEY-1", status = RevocationStatus.REVOKED, reason = "KEY_COMPROMISE")),
            availableDigests = setOf("SHA-leaked.xml"),
            libraryKeys = emptyMap(),
        )

        assertEquals(SavePlanner.Outcome.REVOKED, plan[0].outcome)
        assertEquals("KEY_COMPROMISE", plan[0].detail)
        assertFalse(plan[0].saveable)
    }

    @Test
    fun `a suspended key is never written`() {
        val plan = SavePlanner.plan(
            keys = listOf(analyzed("held.xml", "KEY-1", status = RevocationStatus.SUSPENDED)),
            availableDigests = setOf("SHA-held.xml"),
            libraryKeys = emptyMap(),
        )

        assertEquals(SavePlanner.Outcome.SUSPENDED, plan[0].outcome)
        assertFalse(plan[0].saveable)
    }

    @Test
    fun `a key nobody could check is never written`() {
        val plan = SavePlanner.plan(
            keys = listOf(analyzed("unknown.xml", "KEY-1", status = RevocationStatus.UNKNOWN)),
            availableDigests = setOf("SHA-unknown.xml"),
            libraryKeys = emptyMap(),
        )

        assertEquals(SavePlanner.Outcome.UNCHECKED, plan[0].outcome)
        assertFalse(plan[0].saveable)
    }

    @Test
    fun `the worst key of a file decides for the whole file`() {
        val plan = SavePlanner.plan(
            keys = listOf(
                analyzed(
                    "two-keys.xml",
                    "EC-1",
                    secondKeyId = "RSA-1",
                    secondStatus = RevocationStatus.REVOKED,
                ),
                analyzed("clean.xml", "EC-1"),
            ),
            availableDigests = setOf("SHA-two-keys.xml", "SHA-clean.xml"),
            libraryKeys = emptyMap(),
        )

        // A keybox hands out both keys, so one revoked key is enough to damn it —
        // and it must not reserve its keys and block the usable copy either.
        assertEquals(SavePlanner.Outcome.REVOKED, plan[0].outcome)
        assertEquals(SavePlanner.Outcome.SAVED, plan[1].outcome)
    }

    @Test
    fun `the second key of a file counts when the library is consulted`() {
        val plan = SavePlanner.plan(
            keys = listOf(analyzed("two-keys.xml", "EC-1", secondKeyId = "RSA-1")),
            availableDigests = setOf("SHA-two-keys.xml"),
            libraryKeys = mapOf("RSA-1" to "localdev1/20261003N58052.xml"),
        )

        assertEquals(SavePlanner.Outcome.IN_LIBRARY, plan[0].outcome)
        assertEquals("localdev1/20261003N58052.xml", plan[0].detail)
    }

    @Test
    fun `a file is a twin when any of its keys repeats`() {
        val plan = SavePlanner.plan(
            keys = listOf(
                analyzed("first.xml", "EC-1", secondKeyId = "RSA-1"),
                analyzed("second.xml", "EC-2", secondKeyId = "RSA-1"),
            ),
            availableDigests = setOf("SHA-first.xml", "SHA-second.xml"),
            libraryKeys = emptyMap(),
        )

        assertEquals(SavePlanner.Outcome.SAVED, plan[0].outcome)
        assertEquals(SavePlanner.Outcome.REPEATED_KEY, plan[1].outcome)
        assertEquals("first.xml", plan[1].detail)
    }

    private fun analyzed(
        fileName: String,
        keyId: String,
        deviceId: String? = null,
        expired: Boolean = false,
        contentSha256: String = "SHA-$fileName",
        status: RevocationStatus = RevocationStatus.VALID,
        reason: String? = null,
        secondKeyId: String? = null,
        secondStatus: RevocationStatus = RevocationStatus.VALID,
    ): AnalyzedKeybox {
        val keys = ArrayList<AnalyzedKey>()
        keys += key(0, "ecdsa", keyId, status, expired, reason)
        if (secondKeyId != null) keys += key(1, "rsa", secondKeyId, secondStatus, false, null)
        return AnalyzedKeybox(
            fileName = fileName,
            contentSha256 = contentSha256,
            deviceId = deviceId,
            keys = keys,
            chainFingerprint = "CHAIN-$fileName",
            source = KeyboxSource.LOCAL_PATH,
        )
    }

    private fun key(
        index: Int,
        algorithm: String,
        keyId: String,
        status: RevocationStatus,
        expired: Boolean,
        reason: String?,
    ) = AnalyzedKey(
        index = index,
        algorithm = algorithm,
        keyId = keyId,
        identitySource = IdentitySource.PRIVATE_KEY,
        status = status,
        matchedSerial = if (status == RevocationStatus.VALID) null else "SERIAL-$keyId",
        revocationReason = reason,
        chainValid = true,
        expired = expired,
    )
}
