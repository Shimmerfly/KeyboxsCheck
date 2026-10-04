package dev.hcy917.keyboxchecker.ui.screen.saved

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.ui.LocalUiMode
import dev.hcy917.keyboxchecker.ui.UiMode

/**
 * The "saved" section: the keyboxes the app has already written, plus the two
 * collection-wide actions that only make sense from here — checking every one of
 * them against the revocation list in a single tap, and deleting the ones that
 * no longer work.
 *
 * The screen owns the two things a view model cannot: the save-file dialog and
 * the share sheet.
 */
@Composable
fun SavedPager(
    bottomInnerPadding: Dp,
    isCurrentPage: Boolean = true,
) {
    val viewModel = viewModel<SavedViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    // Resolved through the composition, not the context, so a configuration
    // change re-reads it (lint: LocalContextGetResourceValueCall).
    val chooserTitle = stringResource(R.string.saved_share_chooser)

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip"),
    ) { uri ->
        if (uri != null) viewModel.onExportTo(uri)
    }

    // Re-list whenever the section is shown again: keyboxes are saved from the
    // Keybox Check page, so the library can have grown while this page was off
    // screen.
    LaunchedEffect(isCurrentPage) {
        if (isCurrentPage) viewModel.refresh()
    }

    // A share request is answered by publishing the zip's uri; the chooser is
    // launched here because only the composition has the activity context.
    val pendingShare = state.pendingShare
    LaunchedEffect(pendingShare) {
        if (pendingShare != null) {
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "application/zip"
                putExtra(Intent.EXTRA_STREAM, pendingShare.uri)
                putExtra(Intent.EXTRA_SUBJECT, pendingShare.name)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            val chooser = Intent.createChooser(send, chooserTitle)
            runCatching { context.startActivity(chooser) }
            viewModel.onShareLaunched()
        }
    }

    val actions = remember(viewModel) {
        SavedActions(
            onRefresh = viewModel::refresh,
            onCheck = viewModel::onCheck,
            onCancel = viewModel::onCancel,
            onDeleteRevoked = viewModel::onDeleteRevoked,
            onExportZip = { exportLauncher.launch(viewModel.suggestedArchiveName()) },
            onShare = viewModel::onShare,
            onShareLaunched = viewModel::onShareLaunched,
            onDismissMessage = viewModel::onDismissMessage,
            onRequestRoot = viewModel::onRequestRoot,
            onMakeCurrent = viewModel::onMakeCurrent,
        )
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> SavedPagerMiuix(
            state = state,
            actions = actions,
            bottomInnerPadding = bottomInnerPadding,
        )

        UiMode.Material -> SavedPagerMaterial(
            state = state,
            actions = actions,
            bottomInnerPadding = bottomInnerPadding,
        )
    }
}
