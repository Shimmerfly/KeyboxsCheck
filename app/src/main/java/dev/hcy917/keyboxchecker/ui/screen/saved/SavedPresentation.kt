package dev.hcy917.keyboxchecker.ui.screen.saved

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.res.stringResource
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.keybox.SavedKeybox
import dev.hcy917.keyboxchecker.keybox.SavedKind
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The name the library shows: "2026年10月3日本地58052" / "3 Oct 2026 Local 58052".
 *
 * Built from the day, the kind and the five digits of the file name, so the list
 * reads like a date instead of a bare `20261003N58052.xml`. The file on disk keeps
 * its original name — only the label changes.
 */
@Composable
internal fun savedDisplayName(keybox: SavedKeybox): String {
    if (!keybox.named) return keybox.fileName
    val pattern = stringResource(R.string.saved_date_pattern)
    val date = remember(keybox.savedAtMillis, pattern) {
        SimpleDateFormat(pattern, Locale.getDefault()).format(Date(keybox.savedAtMillis))
    }
    val kind = stringResource(
        if (keybox.kind == SavedKind.REMOTE) R.string.saved_kind_rkp else R.string.saved_kind_local,
    )
    return stringResource(R.string.saved_name_format, date, kind, keybox.serial)
}

/** `12.3 KB` — sizes here are single-digit KB, so one decimal is enough. */
internal fun savedFormatSize(bytes: Long): String = when {
    bytes >= 1024L * 1024L -> String.format(Locale.US, "%.1f MB", bytes / 1024.0 / 1024.0)
    bytes >= 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
    else -> "$bytes B"
}
