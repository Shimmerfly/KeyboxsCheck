package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Grouping has to key on the key material alone. A keybox whose `DeviceID` was
 * edited must land in the same group as the untouched one — that is the whole
 * point of the comparison.
 */
class KeyboxClassifierTest {

    @Test
    fun `one key seen under two device ids is one group with a tampered label`() {
        val groups = KeyboxClassifier.classify(
            listOf(
                analyzed("a.xml", "KEY-1", deviceId = "ORIGINAL-SERIAL"),
                analyzed("b.xml", "KEY-1", deviceId = "CLONED-SERIAL"),
            ),
        )
        assertEquals(1, groups.size)
        assertEquals(2, groups[0].memberCount)
        // DeviceID is reported for context but never decides grouping.
        assertEquals(listOf("CLONED-SERIAL", "ORIGINAL-SERIAL"), groups[0].deviceIds.sorted())
    }

    @Test
    fun `the same key reissued on a different chain is one group with two variants`() {
        val groups = KeyboxClassifier.classify(
            listOf(
                analyzed("a.xml", "KEY-1", chainFingerprint = "CHAIN-A"),
                analyzed("b.xml", "KEY-1", chainFingerprint = "CHAIN-B"),
            ),
        )
        assertEquals(1, groups.size)
        assertEquals(2, groups[0].chainVariants)
        assertFalse(groups[0].identicalChains)
        assertEquals(listOf("CHAIN-A", "CHAIN-B"), groups[0].chainFingerprints)
    }

    @Test
    fun `identical chains collapse to one variant`() {
        val groups = KeyboxClassifier.classify(
            listOf(
                analyzed("a.xml", "KEY-1", deviceId = "A", chainFingerprint = "CHAIN"),
                analyzed("b.xml", "KEY-1", deviceId = "B", chainFingerprint = "CHAIN"),
            ),
        )
        assertEquals(1, groups[0].chainVariants)
        assertTrue(groups[0].identicalChains)
    }

    @Test
    fun `distinct keys become distinct groups ordered by severity`() {
        val groups = KeyboxClassifier.classify(
            listOf(
                analyzed("valid.xml", "KEY-VALID", status = RevocationStatus.VALID),
                analyzed("revoked.xml", "KEY-REVOKED", status = RevocationStatus.REVOKED),
                analyzed("suspended.xml", "KEY-SUSP", status = RevocationStatus.SUSPENDED),
            ),
        )
        assertEquals(3, groups.size)
        assertEquals("KEY-REVOKED", groups[0].keyId)
        assertEquals("KEY-SUSP", groups[1].keyId)
        assertEquals("KEY-VALID", groups[2].keyId)
    }

    @Test
    fun `a file without keys is never grouped`() {
        val empty = analyzed("broken.xml", "KEY-1").copy(keys = emptyList(), parseError = "XML 解析失败")
        assertNull(empty.primaryKeyId)
        assertTrue(KeyboxClassifier.classify(listOf(empty)).isEmpty())
    }

    @Test
    fun `duplicate content is flagged against its first occurrence`() {
        val marking = KeyboxClassifier.markDuplicates(
            listOf(
                analyzed("first.xml", "KEY-1", contentSha256 = "SAME"),
                analyzed("second.xml", "KEY-1", contentSha256 = "SAME"),
                analyzed("third.xml", "KEY-1", contentSha256 = "OTHER"),
            ),
        )
        assertEquals(1, marking.duplicateCount)
        assertNull(marking.keyboxes[0].duplicateOf)
        assertEquals("first.xml", marking.keyboxes[1].duplicateOf)
        assertNull(marking.keyboxes[2].duplicateOf)
    }

    @Test
    fun `files with no digest are left alone`() {
        val marking = KeyboxClassifier.markDuplicates(
            listOf(
                analyzed("a.xml", "KEY-1", contentSha256 = ""),
                analyzed("b.xml", "KEY-1", contentSha256 = ""),
            ),
        )
        assertEquals(0, marking.duplicateCount)
        assertNull(marking.keyboxes[0].duplicateOf)
        assertNull(marking.keyboxes[1].duplicateOf)
    }

    @Test
    fun `marking is idempotent so a reordered report keeps one survivor`() {
        // The report is rebuilt from a previous report, so the survivor arrives
        // already marked and in a different order. A stale flag on the survivor
        // used to make every copy point at another one, which left the whole
        // group unsaveable.
        val previouslyMarked = listOf(
            analyzed("b.xml", "KEY-1", contentSha256 = "SAME").copy(duplicateOf = "a.xml"),
            analyzed("a.xml", "KEY-1", contentSha256 = "SAME"),
        )

        val marking = KeyboxClassifier.markDuplicates(previouslyMarked)

        assertEquals(1, marking.duplicateCount)
        assertNull(marking.keyboxes[0].duplicateOf)
        assertEquals("b.xml", marking.keyboxes[1].duplicateOf)
        assertEquals(1, marking.keyboxes.count { it.duplicateOf == null })
    }

    @Test
    fun `remarking an already clean list changes nothing`() {
        val once = KeyboxClassifier.markDuplicates(
            listOf(
                analyzed("a.xml", "KEY-1", contentSha256 = "SAME"),
                analyzed("b.xml", "KEY-1", contentSha256 = "SAME"),
            ),
        ).keyboxes

        val twice = KeyboxClassifier.markDuplicates(once)

        assertEquals(1, twice.duplicateCount)
        assertNull(twice.keyboxes[0].duplicateOf)
        assertEquals("a.xml", twice.keyboxes[1].duplicateOf)
    }

    @Test
    fun `stats count only confirmed keyboxes`() {
        val stats = KeyboxClassifier.stats(
            filesScanned = 10,
            xmlFiles = 4,
            keyboxes = listOf(
                analyzed("a.xml", "KEY-1"),
                analyzed("broken.xml", "KEY-2").copy(keys = emptyList(), parseError = "bad"),
            ),
            notKeybox = 2,
            unreadable = 1,
            duplicateCount = 1,
        )
        assertEquals(10, stats.filesScanned)
        assertEquals(4, stats.xmlFiles)
        assertEquals(1, stats.confirmedKeyboxes)
        assertEquals(2, stats.notKeybox)
        assertEquals(1, stats.unreadable)
        assertEquals(1, stats.duplicates)
    }

    @Test
    fun `device id is an ignored identity field`() {
        assertTrue(IGNORED_IDENTITY_FIELDS.any { it.equals("DeviceID", ignoreCase = true) })
    }

    private fun analyzed(
        fileName: String,
        keyId: String,
        deviceId: String? = null,
        status: RevocationStatus = RevocationStatus.VALID,
        chainFingerprint: String = "CHAIN-$keyId",
        contentSha256: String = "SHA-$fileName",
    ): AnalyzedKeybox {
        val key = AnalyzedKey(
            index = 0,
            algorithm = "ecdsa",
            keyId = keyId,
            identitySource = IdentitySource.PRIVATE_KEY,
            status = status,
            chainValid = true,
        )
        return AnalyzedKeybox(
            fileName = fileName,
            contentSha256 = contentSha256,
            deviceId = deviceId,
            keys = listOf(key),
            chainFingerprint = chainFingerprint,
            source = KeyboxSource.LOCAL_PATH,
        )
    }
}
