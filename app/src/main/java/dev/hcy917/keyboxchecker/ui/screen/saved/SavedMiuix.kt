package dev.hcy917.keyboxchecker.ui.screen.saved

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.keybox.RevocationStatus
import dev.hcy917.keyboxchecker.ui.screen.keybox.keyboxFormatTime
import dev.hcy917.keyboxchecker.ui.screen.keybox.keyboxRevocationSourceLabelRes
import dev.hcy917.keyboxchecker.ui.screen.keybox.keyboxShortHex
import dev.hcy917.keyboxchecker.ui.screen.keybox.keyboxStatusColor
import dev.hcy917.keyboxchecker.ui.screen.keybox.keyboxStatusLabelRes
import top.yukonga.miuix.kmp.basic.Card as MiuixCard
import top.yukonga.miuix.kmp.basic.Icon as MiuixIcon
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold as MiuixScaffold
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.basic.TopAppBar as MiuixTopAppBar
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
internal fun SavedPagerMiuix(
    state: SavedUiState,
    actions: SavedActions,
    bottomInnerPadding: Dp,
) {
    val scrollBehavior = MiuixScrollBehavior()
    var confirmingDelete by remember { mutableStateOf(false) }
    var pendingCurrent by remember { mutableStateOf<String?>(null) }

    pendingCurrent?.let { fileName ->
        OverlayDialog(
            show = true,
            onDismissRequest = { pendingCurrent = null },
            insideMargin = DpSize(0.dp, 0.dp),
        ) {
            MiuixText(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 24.dp, bottom = 8.dp),
                text = stringResource(R.string.saved_make_current_title),
                fontSize = MiuixTheme.textStyles.title4.fontSize,
                fontWeight = FontWeight.Medium,
                textAlign = TextAlign.Center,
                color = MiuixTheme.colorScheme.onSurface,
            )
            MiuixText(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 8.dp),
                text = stringResource(R.string.saved_make_current_text, fileName),
                fontSize = MiuixTheme.textStyles.body2.fontSize,
                textAlign = TextAlign.Center,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                MiuixTextButton(
                    text = stringResource(R.string.saved_dismiss),
                    onClick = { pendingCurrent = null },
                    modifier = Modifier.weight(1f),
                )
                MiuixTextButton(
                    text = stringResource(R.string.saved_make_current_confirm),
                    onClick = {
                        pendingCurrent = null
                        actions.onMakeCurrent(fileName)
                    },
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }

    if (confirmingDelete) {
        OverlayDialog(
            show = true,
            onDismissRequest = { confirmingDelete = false },
            insideMargin = DpSize(0.dp, 0.dp),
        ) {
            MiuixText(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 24.dp, bottom = 8.dp),
                text = stringResource(R.string.saved_delete_confirm_title),
                fontSize = MiuixTheme.textStyles.title4.fontSize,
                fontWeight = FontWeight.Medium,
                textAlign = TextAlign.Center,
                color = MiuixTheme.colorScheme.onSurface,
            )
            MiuixText(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 8.dp),
                text = stringResource(R.string.saved_delete_confirm_text, state.revokedPaths.size),
                fontSize = MiuixTheme.textStyles.body2.fontSize,
                textAlign = TextAlign.Center,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                MiuixTextButton(
                    text = stringResource(R.string.saved_dismiss),
                    onClick = { confirmingDelete = false },
                    modifier = Modifier.weight(1f),
                )
                MiuixTextButton(
                    text = stringResource(R.string.saved_delete_confirm_ok),
                    onClick = {
                        confirmingDelete = false
                        actions.onDeleteRevoked()
                    },
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }

    MiuixScaffold(
        topBar = {
            MiuixTopAppBar(
                title = stringResource(R.string.saved_section),
                scrollBehavior = scrollBehavior,
            )
        },
        popupHost = { },
        contentWindowInsets =
            WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal),
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .padding(horizontal = 12.dp),
            contentPadding = innerPadding,
            verticalArrangement = Arrangement.spacedBy(12.dp),
            overscrollEffect = null,
        ) {
            item { SummaryCardMiuix(state) }

            if (state.rootChecked && !state.rootReady) {
                item { RootCardMiuix(state, actions) }
            }

            item {
                ActionsCardMiuix(
                    state = state,
                    actions = actions,
                    onDeleteClick = { confirmingDelete = true },
                )
            }

            if (state.isChecking || state.isBusy) {
                item { BusyCardMiuix(state) }
            }

            state.message?.let { message ->
                item { MessageCardMiuix(message, actions.onDismissMessage) }
            }

            item { SectionTitleMiuix(stringResource(R.string.saved_library_title)) }

            if (state.entries.isEmpty()) {
                item {
                    MiuixCard(modifier = Modifier.fillMaxWidth()) {
                        MiuixText(
                            text = stringResource(R.string.saved_empty),
                            fontSize = MiuixTheme.textStyles.body2.fontSize,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            modifier = Modifier.padding(16.dp),
                        )
                    }
                }
            }

            items(state.entries, key = { it.keybox.relativePath }) { entry ->
                EntryCardMiuix(
                    entry = entry,
                    configReady = state.configReady,
                    onMakeCurrent = { pendingCurrent = it },
                )
            }

            if (state.notes.isNotEmpty()) {
                item { NotesCardMiuix(state.notes) }
            }

            item { Spacer(Modifier.height(bottomInnerPadding)) }
        }
    }
}

@Composable
private fun SectionTitleMiuix(text: String) {
    MiuixText(
        text = text,
        fontSize = MiuixTheme.textStyles.title4.fontSize,
        fontWeight = FontWeight.Medium,
        color = MiuixTheme.colorScheme.onSurface,
        modifier = Modifier.padding(start = 4.dp, top = 4.dp),
    )
}

@Composable
private fun SummaryCardMiuix(state: SavedUiState) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            MiuixText(
                text = stringResource(R.string.saved_count, state.entries.size),
                fontSize = MiuixTheme.textStyles.title4.fontSize,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
            )
            if (state.entries.isNotEmpty()) {
                MiuixText(
                    text = stringResource(R.string.saved_total_size, savedFormatSize(state.totalBytes)),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            MiuixText(
                text = stringResource(R.string.saved_library_folder),
                fontSize = MiuixTheme.textStyles.footnote1.fontSize,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            MiuixText(
                text = state.libraryPath.ifBlank { "—" },
                fontSize = MiuixTheme.textStyles.body2.fontSize,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(2.dp))
            MiuixText(
                text = stringResource(
                    R.string.saved_last_check,
                    stringResource(keyboxRevocationSourceLabelRes(state.revocationSource)),
                    state.revocationEntries,
                    keyboxFormatTime(state.revocationFetchedAt),
                ),
                fontSize = MiuixTheme.textStyles.body2.fontSize,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            state.revocationError?.let { error ->
                MiuixText(
                    text = error,
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.error,
                )
            }
        }
    }
}

@Composable
private fun ActionsCardMiuix(
    state: SavedUiState,
    actions: SavedActions,
    onDeleteClick: () -> Unit,
) {
    val busy = state.isChecking || state.isBusy
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            MiuixText(
                text = stringResource(R.string.saved_actions_title),
                fontSize = MiuixTheme.textStyles.title4.fontSize,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (state.isChecking) {
                    MiuixTextButton(
                        text = stringResource(R.string.keybox_cancel),
                        onClick = actions.onCancel,
                        modifier = Modifier.weight(1f),
                    )
                } else {
                    MiuixTextButton(
                        text = stringResource(R.string.saved_check),
                        onClick = actions.onCheck,
                        enabled = !busy && state.entries.isNotEmpty(),
                        modifier = Modifier.weight(1f),
                    )
                }
                MiuixTextButton(
                    text = stringResource(R.string.saved_delete_revoked),
                    onClick = onDeleteClick,
                    // Nothing is ever deleted before a check has confirmed it.
                    enabled = !busy && state.revokedPaths.isNotEmpty(),
                    modifier = Modifier.weight(1f),
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                MiuixTextButton(
                    text = stringResource(R.string.saved_export),
                    onClick = actions.onExportZip,
                    enabled = !busy && state.entries.isNotEmpty(),
                    modifier = Modifier.weight(1f),
                )
                MiuixTextButton(
                    text = stringResource(R.string.saved_share),
                    onClick = actions.onShare,
                    enabled = !busy && state.entries.isNotEmpty(),
                    modifier = Modifier.weight(1f),
                )
            }

            if (state.checked && state.revokedPaths.isNotEmpty()) {
                MiuixText(
                    text = stringResource(R.string.saved_revoked_ready, state.revokedPaths.size),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
        }
    }
}

@Composable
private fun RootCardMiuix(state: SavedUiState, actions: SavedActions) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            MiuixText(
                text = stringResource(R.string.saved_root_title),
                fontSize = MiuixTheme.textStyles.title4.fontSize,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.error,
            )
            MiuixText(
                text = stringResource(R.string.saved_root_note, state.libraryPath),
                fontSize = MiuixTheme.textStyles.body2.fontSize,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            MiuixTextButton(
                text = stringResource(R.string.saved_root_request),
                onClick = actions.onRequestRoot,
                enabled = !state.isBusy,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun BusyCardMiuix(state: SavedUiState) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                InfiniteProgressIndicator()
                MiuixText(
                    text = stringResource(
                        if (state.isChecking) R.string.saved_checking else R.string.keybox_progress_working,
                    ),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.onSurface,
                )
            }
            state.progress?.let { progress ->
                MiuixText(
                    text = "${progress.processed} / ${progress.total} · ${progress.phase}",
                    fontSize = MiuixTheme.textStyles.footnote1.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                if (progress.currentName.isNotBlank()) {
                    MiuixText(
                        text = progress.currentName,
                        fontSize = MiuixTheme.textStyles.footnote1.fontSize,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
        }
    }
}

@Composable
private fun MessageCardMiuix(message: String, onDismiss: () -> Unit) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(start = 16.dp, top = 8.dp, bottom = 8.dp, end = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            MiuixText(
                text = message,
                fontSize = MiuixTheme.textStyles.body2.fontSize,
                color = MiuixTheme.colorScheme.onSurface,
                modifier = Modifier.weight(1f),
            )
            MiuixTextButton(
                text = stringResource(R.string.saved_dismiss),
                onClick = onDismiss,
            )
        }
    }
}

@Composable
private fun NotesCardMiuix(notes: List<String>) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            MiuixText(
                text = stringResource(R.string.keybox_notes),
                fontSize = MiuixTheme.textStyles.title4.fontSize,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
            )
            notes.forEach { note ->
                MiuixText(
                    text = note,
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
        }
    }
}

@Composable
private fun EntryCardMiuix(
    entry: SavedEntry,
    configReady: Boolean,
    onMakeCurrent: (String) -> Unit,
) {
    MiuixCard(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                // The keybox the module actually serves is worth pointing out at
                // a glance, so it gets a border on top of the inline badge.
                if (entry.selected) {
                    Modifier.border(
                        width = 2.dp,
                        color = MiuixTheme.colorScheme.primary,
                        shape = RoundedCornerShape(12.dp),
                    )
                } else {
                    Modifier
                },
            ),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    MiuixText(
                        text = savedDisplayName(entry.keybox),
                        fontSize = MiuixTheme.textStyles.title4.fontSize,
                        fontWeight = FontWeight.Medium,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                    MiuixText(
                        text = entry.keybox.relativePath,
                        fontSize = MiuixTheme.textStyles.body2.fontSize,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                StatusPillMiuix(entry.status)
            }

            if (entry.selected) {
                val profiles = entry.selectedBy.joinToString("、")
                MiuixText(
                    text = if (profiles.isBlank()) {
                        stringResource(R.string.saved_current_badge)
                    } else {
                        stringResource(R.string.saved_current_badge_profiles, profiles)
                    },
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    fontWeight = FontWeight.Medium,
                    color = MiuixTheme.colorScheme.primary,
                )
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                MiuixText(
                    text = savedFormatSize(entry.keybox.sizeBytes),
                    fontSize = MiuixTheme.textStyles.footnote1.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                if (entry.remoteProvisioned) {
                    MiuixText(
                        text = stringResource(R.string.saved_kind_rkp),
                        fontSize = MiuixTheme.textStyles.footnote1.fontSize,
                        color = MiuixTheme.colorScheme.primary,
                    )
                }
                if (!entry.keybox.named) {
                    MiuixText(
                        text = stringResource(R.string.saved_unnamed),
                        fontSize = MiuixTheme.textStyles.footnote1.fontSize,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
            }

            entry.keyId?.let { keyId ->
                MiuixText(
                    text = stringResource(R.string.keybox_group_identity, keyboxShortHex(keyId, 32)),
                    fontSize = MiuixTheme.textStyles.footnote1.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }

            entry.reason?.takeIf { entry.isRevoked }?.let { reason ->
                MiuixText(
                    text = reason,
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.error,
                )
            }

            if (configReady && !entry.selected) {
                MiuixTextButton(
                    text = stringResource(R.string.saved_make_current),
                    onClick = { onMakeCurrent(entry.keybox.fileName) },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun StatusPillMiuix(status: RevocationStatus?) {
    val label = status?.let { stringResource(keyboxStatusLabelRes(it)) }
        ?: stringResource(R.string.saved_status_not_checked)
    val color = status?.let { keyboxStatusColor(it) } ?: MiuixTheme.colorScheme.onSurfaceVariantSummary
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        MiuixIcon(
            imageVector = if (status == RevocationStatus.VALID) {
                Icons.Filled.CheckCircle
            } else {
                Icons.Filled.Warning
            },
            contentDescription = null,
            tint = color,
            modifier = Modifier.height(16.dp),
        )
        MiuixText(
            text = label,
            fontSize = MiuixTheme.textStyles.body2.fontSize,
            fontWeight = FontWeight.Medium,
            color = color,
        )
    }
}
