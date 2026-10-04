package dev.hcy917.keyboxchecker.keybox

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The report lists one certificate per file, so the only thing the classifier
 * still has to work out is which files carry the same key. That comparison has
 * to key on the key material alone: a keybox whose `DeviceID` or chain was
 * edited still holds the same key and must be reported as a repeat.
 */
class KeyboxClassifierTest {

    @Test
    fun `one key seen in two files is one repeated key`() {
        val repeated = KeyboxClassifier.repeatedKeys(
            listOf(
                analyzed("b.xml", "KEY-1", deviceId = "CLONED-SERIAL"),
                analyzed("a.xml", "KEY-1", deviceId = "ORIGINAL-SERIAL"),
            ),
        )
        assertEquals(1, repeated.size)
        assertEquals("KEY-1", repeated[0].keyId)
        assertEquals(2, repeated[0].count)
        // DeviceID is reported for context but never decides identity.
        assertEquals(listOf("a.xml", "b.xml"), repeated[0].fileNames)
    }

    @Test
    fun `the same key reissued on a different chain is still the same key`() {
        val repeated = KeyboxClassifier.repeatedKeys(
            listOf(
                analyzed("a.xml", "KEY-1", chainFingerprint = "CHAIN-A"),
                analyzed("b.xml", "KEY-1", chainFingerprint = "CHAIN-B"),
            ),
        )
        assertEquals(1, repeated.size)
        assertEquals(listOf("a.xml", "b.xml"), repeated[0].fileNames)
    }

    @Test
    fun `a file that appears once is not a repeat`() {
        val repeated = KeyboxClassifier.repeatedKeys(
            listOf(
                analyzed("only.xml", "KEY-1"),
                analyzed("other.xml", "KEY-2"),
            ),
        )
        assertTrue(repeated.isEmpty())
    }

    @Test
    fun `repeats are ordered by how many files share the key`() {
        val repeated = KeyboxClassifier.repeatedKeys(
            listOf(
                analyzed("solo-a.xml", "KEY-SOLO-A"),
                analyzed("twin-a.xml", "KEY-TWIN"),
                analyzed("solo-b.xml", "KEY-SOLO-B"),
                analyzed("twin-b.xml", "KEY-TWIN"),
                analyzed("triple.xml", "KEY-TRIPLE"),
                analyzed("triple-b.xml", "KEY-TRIPLE"),
                analyzed("triple-c.xml", "KEY-TRIPLE"),
            ),
        )
        assertEquals(listOf("KEY-TRIPLE", "KEY-TWIN"), repeated.map { it.keyId })
    }

    @Test
    fun `a file without keys never counts as a repeat`() {
        val broken = analyzed("broken.xml", "KEY-1").copy(keys = emptyList(), parseError = "XML 解析失败")
        assertNull(broken.primaryKeyId)
        assertTrue(KeyboxClassifier.repeatedKeys(listOf(broken, broken)).isEmpty())
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

    @Test
    fun `a repeated second key makes the files twins`() {
        // A keybox carries an ECDSA and an RSA key. Comparing only the first key
        // would let the second copy of a key through unnoticed.
        val repeated = KeyboxClassifier.repeatedKeys(
            listOf(
                analyzed("a.xml", "EC-1", secondKeyId = "RSA-1"),
                analyzed("b.xml", "EC-2", secondKeyId = "RSA-1"),
            ),
        )

        assertEquals(1, repeated.size)
        assertEquals("RSA-1", repeated[0].keyId)
        assertEquals(listOf("a.xml", "b.xml"), repeated[0].fileNames)
    }

    @Test
    fun `both keys of a twin pair are reported`() {
        val repeated = KeyboxClassifier.repeatedKeys(
            listOf(
                analyzed("a.xml", "EC-1", secondKeyId = "RSA-1"),
                analyzed("b.xml", "EC-1", secondKeyId = "RSA-1"),
            ),
        )

        assertEquals(listOf("EC-1", "RSA-1"), repeated.map { it.keyId }.sorted())
        assertTrue(repeated.all { it.fileNames == listOf("a.xml", "b.xml") })
    }

    private fun analyzed(
        fileName: String,
        keyId: String,
        deviceId: String? = null,
        status: RevocationStatus = RevocationStatus.VALID,
        chainFingerprint: String = "CHAIN-$keyId",
        contentSha256: String = "SHA-$fileName",
        secondKeyId: String? = null,
    ): AnalyzedKeybox {
        val keys = ArrayList<AnalyzedKey>()
        keys += AnalyzedKey(
            index = 0,
            algorithm = "ecdsa",
            keyId = keyId,
            identitySource = IdentitySource.PRIVATE_KEY,
            status = status,
            chainValid = true,
        )
        if (secondKeyId != null) {
            keys += AnalyzedKey(
                index = 1,
                algorithm = "rsa",
                keyId = secondKeyId,
                identitySource = IdentitySource.PRIVATE_KEY,
                status = status,
                chainValid = true,
            )
        }
        return AnalyzedKeybox(
            fileName = fileName,
            contentSha256 = contentSha256,
            deviceId = deviceId,
            keys = keys,
            chainFingerprint = chainFingerprint,
            source = KeyboxSource.LOCAL_PATH,
        )
    }
}
