package dev.hcy917.keyboxchecker.ui.screen.saved

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.keybox.RevocationStatus
import dev.hcy917.keyboxchecker.ui.component.material.ExpressiveConfirmDialog
import dev.hcy917.keyboxchecker.ui.component.material.ExpressiveScaffold
import dev.hcy917.keyboxchecker.ui.component.material.SegmentedColumn
import dev.hcy917.keyboxchecker.ui.component.material.SegmentedItem
import dev.hcy917.keyboxchecker.ui.component.material.SegmentedItemContainer
import dev.hcy917.keyboxchecker.ui.component.material.SegmentedListItem
import dev.hcy917.keyboxchecker.ui.component.material.expressiveTopAppBarColors
import dev.hcy917.keyboxchecker.ui.screen.keybox.keyboxFormatTime
import dev.hcy917.keyboxchecker.ui.screen.keybox.keyboxRevocationSourceLabelRes
import dev.hcy917.keyboxchecker.ui.screen.keybox.keyboxShortHex
import dev.hcy917.keyboxchecker.ui.screen.keybox.keyboxStatusColor
import dev.hcy917.keyboxchecker.ui.screen.keybox.keyboxStatusLabelRes

/**
 * The "saved" section in the official manager's Material style: one
 * [ExpressiveScaffold] page, list-item groups instead of cards, and the progress
 * of a revocation check shown inline in the group it belongs to.
 */
@Composable
internal fun SavedPagerMaterial(
    state: SavedUiState,
    actions: SavedActions,
    bottomInnerPadding: Dp,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    var confirmingDelete by remember { mutableStateOf(false) }

    if (confirmingDelete) {
        ExpressiveConfirmDialog(
            title = stringResource(R.string.saved_delete_confirm_title),
            message = stringResource(R.string.saved_delete_confirm_text, state.revokedPaths.size),
            confirmText = stringResource(R.string.saved_delete_confirm_ok),
            dismissText = stringResource(R.string.saved_dismiss),
            onConfirm = {
                confirmingDelete = false
                actions.onDeleteRevoked()
            },
            onDismiss = { confirmingDelete = false },
        )
    }

    ExpressiveScaffold(
        topBar = {
            TopBar(
                title = stringResource(R.string.saved_section),
                scrollBehavior = scrollBehavior,
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .padding(innerPadding)
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                bottom = bottomInnerPadding + 16.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(13.dp),
        ) {
            item { SummaryGroup(state) }

            item {
                ActionsGroup(
                    state = state,
                    actions = actions,
                    onDeleteClick = { confirmingDelete = true },
                )
            }

            if (state.isChecking || state.isBusy) {
                item { BusyGroup(state) }
            }

            state.message?.let { message ->
                item { MessageGroup(message, actions.onDismissMessage) }
            }

            if (state.entries.isEmpty()) {
                item {
                    SegmentedColumn(modifier = Modifier.fillMaxWidth()) {
                        item {
                            SegmentedListItem(
                                headlineContent = { Text(stringResource(R.string.saved_empty)) },
                            )
                        }
                    }
                }
            } else {
                itemsIndexed(
                    items = state.entries,
                    key = { _, entry -> entry.keybox.relativePath },
                ) { index, entry ->
                    EntryGroup(
                        entry = entry,
                        index = index,
                        count = state.entries.size,
                    )
                }
            }

            if (state.notes.isNotEmpty()) {
                item { NotesGroup(state.notes) }
            }
        }
    }
}

@Composable
private fun TopBar(
    title: String,
    scrollBehavior: TopAppBarScrollBehavior? = null,
) {
    LargeFlexibleTopAppBar(
        title = { Text(title) },
        colors = expressiveTopAppBarColors(),
        windowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
        scrollBehavior = scrollBehavior,
    )
}

@Composable
private fun SummaryGroup(state: SavedUiState) {
    SegmentedColumn(modifier = Modifier.fillMaxWidth()) {
        item {
            SegmentedListItem(
                headlineContent = { Text(stringResource(R.string.saved_count, state.entries.size)) },
                supportingContent = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        if (state.entries.isNotEmpty()) {
                            Text(
                                text = stringResource(
                                    R.string.saved_total_size,
                                    savedFormatSize(state.totalBytes),
                                ),
                            )
                        }
                        Text(
                            text = stringResource(R.string.saved_library_folder),
                            style = MaterialTheme.typography.labelSmall,
                        )
                        Text(
                            text = state.outputDir.ifBlank { "—" },
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                        Text(
                            text = stringResource(
                                R.string.saved_last_check,
                                stringResource(keyboxRevocationSourceLabelRes(state.revocationSource)),
                                state.revocationEntries,
                                keyboxFormatTime(state.revocationFetchedAt),
                            ),
                        )
                        state.revocationError?.let { error ->
                            Text(
                                text = error,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                    }
                },
            )
        }
    }
}

@Composable
private fun ActionsGroup(
    state: SavedUiState,
    actions: SavedActions,
    onDeleteClick: () -> Unit,
) {
    val busy = state.isChecking || state.isBusy
    SegmentedColumn(modifier = Modifier.fillMaxWidth()) {
        item {
            SegmentedItemContainer {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        if (state.isChecking) {
                            OutlinedButton(
                                onClick = actions.onCancel,
                                modifier = Modifier.weight(1f),
                            ) {
                                Text(stringResource(R.string.keybox_cancel))
                            }
                        } else {
                            Button(
                                onClick = actions.onCheck,
                                enabled = !busy && state.entries.isNotEmpty(),
                                modifier = Modifier.weight(1f),
                            ) {
                                Text(stringResource(R.string.saved_check))
                            }
                        }
                        OutlinedButton(
                            onClick = onDeleteClick,
                            // Nothing is ever deleted before a check has confirmed it,
                            // so the button stays disabled until then.
                            enabled = !busy && state.revokedPaths.isNotEmpty(),
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(Icons.Filled.Delete, contentDescription = null)
                            Spacer(Modifier.size(8.dp))
                            Text(stringResource(R.string.saved_delete_revoked))
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedButton(
                            onClick = actions.onExportZip,
                            enabled = !busy && state.entries.isNotEmpty(),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(stringResource(R.string.saved_export))
                        }
                        OutlinedButton(
                            onClick = actions.onShare,
                            enabled = !busy && state.entries.isNotEmpty(),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(stringResource(R.string.saved_share))
                        }
                    }

                    if (state.checked && state.revokedPaths.isNotEmpty()) {
                        Text(
                            text = stringResource(R.string.saved_revoked_ready, state.revokedPaths.size),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun BusyGroup(state: SavedUiState) {
    SegmentedColumn(modifier = Modifier.fillMaxWidth()) {
        item {
            SegmentedItemContainer {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        Text(
                            text = stringResource(
                                if (state.isChecking) R.string.saved_checking else R.string.keybox_progress_working,
                            ),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                    state.progress?.let { progress ->
                        if (progress.total > 0) {
                            LinearProgressIndicator(
                                progress = { progress.fraction },
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        Text(
                            text = "${progress.processed} / ${progress.total} · ${progress.phase}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        if (progress.currentName.isNotBlank()) {
                            Text(
                                text = progress.currentName,
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MessageGroup(message: String, onDismiss: () -> Unit) {
    SegmentedColumn(modifier = Modifier.fillMaxWidth()) {
        item {
            SegmentedListItem(
                colors = ListItemDefaults.segmentedColors(
                    containerColor = MaterialTheme.colorScheme.tertiaryContainer,
                    contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
                ),
                headlineContent = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = message,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onTertiaryContainer,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(onClick = onDismiss) {
                            Text(stringResource(R.string.saved_dismiss))
                        }
                    }
                },
            )
        }
    }
}

@Composable
private fun NotesGroup(notes: List<String>) {
    SegmentedColumn(
        modifier = Modifier.fillMaxWidth(),
        title = stringResource(R.string.keybox_notes),
    ) {
        notes.forEachIndexed { index, note ->
            item(key = index) {
                SegmentedListItem(headlineContent = { Text(note) })
            }
        }
    }
}

@Composable
private fun EntryGroup(entry: SavedEntry, index: Int, count: Int) {
    val status = entry.status
    SegmentedItem(index = index, count = count) {
        SegmentedListItem(
            headlineContent = {
                Column {
                    Text(savedDisplayName(entry.keybox))
                    Text(
                        text = entry.keybox.relativePath,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            supportingContent = {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Text(
                            text = savedFormatSize(entry.keybox.sizeBytes),
                            style = MaterialTheme.typography.labelSmall,
                        )
                        if (entry.remoteProvisioned) {
                            Text(
                                text = stringResource(R.string.saved_kind_rkp),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                        if (!entry.keybox.named) {
                            Text(
                                text = stringResource(R.string.saved_unnamed),
                                style = MaterialTheme.typography.labelSmall,
                            )
                        }
                    }
                    entry.keyId?.let { keyId ->
                        Text(
                            text = stringResource(R.string.keybox_group_identity, keyboxShortHex(keyId, 32)),
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                    entry.reason?.takeIf { entry.isRevoked }?.let { reason ->
                        Text(
                            text = reason,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            },
            trailingContent = { StatusPill(status) },
        )
    }
}

@Composable
private fun StatusPill(status: RevocationStatus?) {
    val label = status?.let { stringResource(keyboxStatusLabelRes(it)) }
        ?: stringResource(R.string.saved_status_not_checked)
    val color = status?.let { keyboxStatusColor(it) } ?: MaterialTheme.colorScheme.onSurfaceVariant
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Icon(
            imageVector = if (status == RevocationStatus.VALID) {
                Icons.Rounded.CheckCircle
            } else {
                Icons.Filled.Warning
            },
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(16.dp),
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = color,
        )
    }
}
