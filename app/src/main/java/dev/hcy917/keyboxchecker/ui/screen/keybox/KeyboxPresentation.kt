package dev.hcy917.keyboxchecker.ui.screen.keybox

import androidx.compose.ui.graphics.Color
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.keybox.RevocationSource
import dev.hcy917.keyboxchecker.keybox.RevocationStatus
import dev.hcy917.keyboxchecker.keybox.RootStatus
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Presentation helpers shared by the Material and the Miuix layouts, so both
 * design systems describe the same keybox state with the same words and colours.
 */

private const val COLOR_REVOKED = 0xFFD32F2FL
private const val COLOR_SUSPENDED = 0xFFEF6C00L
private const val COLOR_VALID = 0xFF2E7D32L
private const val COLOR_UNKNOWN = 0xFF757575L

internal fun keyboxStatusColor(status: RevocationStatus): Color = when (status) {
    RevocationStatus.REVOKED -> Color(COLOR_REVOKED)
    RevocationStatus.SUSPENDED -> Color(COLOR_SUSPENDED)
    RevocationStatus.VALID -> Color(COLOR_VALID)
    RevocationStatus.UNKNOWN -> Color(COLOR_UNKNOWN)
}

internal fun keyboxStatusLabelRes(status: RevocationStatus): Int = when (status) {
    RevocationStatus.REVOKED -> R.string.keybox_status_revoked
    RevocationStatus.SUSPENDED -> R.string.keybox_status_suspended
    RevocationStatus.VALID -> R.string.keybox_status_valid
    RevocationStatus.UNKNOWN -> R.string.keybox_status_unknown
}

/** [valid] is null when the chain could not be verified at all. */
internal fun keyboxChainLabelRes(valid: Boolean?): Int = when (valid) {
    true -> R.string.keybox_chain_valid
    false -> R.string.keybox_chain_invalid
    null -> R.string.keybox_chain_unknown
}

internal fun keyboxRevocationSourceLabelRes(source: RevocationSource): Int = when (source) {
    RevocationSource.NETWORK -> R.string.keybox_revocation_source_network
    RevocationSource.CACHE -> R.string.keybox_revocation_source_cache
    RevocationSource.NONE -> R.string.keybox_revocation_source_none
}

/** Which pinned root a chain terminates in, in the words of the reference projects. */
internal fun keyboxRootStatusRes(status: RootStatus): Int = when (status) {
    RootStatus.NULL -> R.string.keybox_root_status_none
    RootStatus.FAILED -> R.string.keybox_root_status_failed
    RootStatus.AOSP -> R.string.keybox_root_status_aosp
    RootStatus.GOOGLE -> R.string.keybox_root_status_google
    RootStatus.GOOGLE_RKP -> R.string.keybox_root_status_rkp
    RootStatus.KNOX -> R.string.keybox_root_status_knox
    RootStatus.UNKNOWN -> R.string.keybox_root_status_unknown
}

internal fun keyboxShortHex(value: String, length: Int = 16): String =
    if (value.length <= length) value else value.take(length)

internal fun keyboxFormatTime(millis: Long): String {
    if (millis <= 0L) return "—"
    return SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(millis))
}
