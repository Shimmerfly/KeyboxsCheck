package dev.hcy917.keyboxchecker.ui.screen.keybox

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.keybox.AnalyzedKeybox
import dev.hcy917.keyboxchecker.keybox.RepeatedKey
import dev.hcy917.keyboxchecker.keybox.RevocationSource
import dev.hcy917.keyboxchecker.keybox.RevocationStatus
import dev.hcy917.keyboxchecker.keybox.RootStatus
import dev.hcy917.keyboxchecker.ui.component.material.ExpressiveScaffold
import dev.hcy917.keyboxchecker.ui.component.material.SegmentedColumn
import dev.hcy917.keyboxchecker.ui.component.material.SegmentedItem
import dev.hcy917.keyboxchecker.ui.component.material.SegmentedItemContainer
import dev.hcy917.keyboxchecker.ui.component.material.SegmentedListItem
import dev.hcy917.keyboxchecker.ui.component.material.TopBarBackButton
import dev.hcy917.keyboxchecker.ui.component.material.expressiveTopAppBarColors

/**
 * The keybox checker in the official manager's Material style: one
 * [ExpressiveScaffold] page, the input form in a single segmented group, and one
 * list item per scanned file instead of a card each.
 */
@Composable
internal fun KeyboxScreenMaterial(
    state: KeyboxUiState,
    actions: KeyboxActions,
    onBack: () -> Unit,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                title = { Text(stringResource(R.string.keybox_section)) },
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                colors = expressiveTopAppBarColors(),
                windowInsets = WindowInsets.safeDrawing.only(
                    WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
                ),
                scrollBehavior = scrollBehavior,
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Top + WindowInsetsSides.Horizontal,
        ),
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(13.dp),
        ) {
            item { InputGroup(state, actions) }

            if (state.isScanning) {
                item { BusyGroup(state) }
            }

            state.message?.let { message ->
                item { MessageGroup(message) }
            }

            item { RevocationGroup(state, actions) }

            if (state.repeatedKeys.isNotEmpty()) {
                item { RepeatedGroup(state.repeatedKeys) }
            }

            if (state.certificates.isEmpty()) {
                item {
                    SegmentedColumn(modifier = Modifier.fillMaxWidth()) {
                        item {
                            SegmentedListItem(
                                headlineContent = { Text(stringResource(R.string.keybox_no_results)) },
                            )
                        }
                    }
                }
            } else {
                itemsIndexed(state.certificates, key = { _, item -> item.fileName }) { index, keybox ->
                    SegmentedItem(index = index, count = state.certificates.size) {
                        CertificateItem(
                            keybox = keybox,
                            twins = state.twinNames(keybox),
                            expanded = state.expandedFiles.contains(keybox.fileName),
                            onToggle = actions.onToggleFile,
                        )
                    }
                }
            }

            item { SaveGroup(state, actions) }

            if (state.notes.isNotEmpty()) {
                item { NotesGroup(state.notes) }
            }
        }
    }
}

@Composable
private fun InputGroup(state: KeyboxUiState, actions: KeyboxActions) {
    SegmentedColumn(
        modifier = Modifier.fillMaxWidth(),
        title = stringResource(R.string.keybox_input_title),
    ) {
        item {
            SegmentedItemContainer {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    OutlinedTextField(
                        value = state.path,
                        onValueChange = actions.onPathChanged,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(stringResource(R.string.keybox_path_label)) },
                        placeholder = { Text(stringResource(R.string.keybox_path_hint)) },
                        singleLine = true,
                    )
                    state.pickedTreeLabel?.let { label ->
                        Text(
                            text = stringResource(R.string.keybox_picked, label),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    if (state.pickedFileNames.isNotEmpty()) {
                        Text(
                            text = stringResource(
                                R.string.keybox_picked_files,
                                state.pickedFileNames.size,
                                state.pickedFileNames.joinToString("、"),
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    OutlinedTextField(
                        value = state.localDeviceId,
                        onValueChange = actions.onLocalDeviceIdChanged,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(stringResource(R.string.keybox_local_id_label)) },
                        placeholder = { Text(stringResource(R.string.keybox_local_id_hint)) },
                        supportingText = { Text(stringResource(R.string.keybox_local_id_note)) },
                        singleLine = true,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = actions.onPickDirectory) {
                            Text(stringResource(R.string.keybox_pick_directory))
                        }
                        OutlinedButton(onClick = actions.onPickFiles) {
                            Text(stringResource(R.string.keybox_pick_files))
                        }
                    }
                    if (state.isScanning) {
                        OutlinedButton(
                            onClick = actions.onCancel,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(stringResource(R.string.keybox_cancel))
                        }
                    } else {
                        Button(
                            onClick = actions.onScan,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Icon(Icons.Filled.Upload, contentDescription = null)
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.keybox_scan))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun BusyGroup(state: KeyboxUiState) {
    SegmentedColumn(modifier = Modifier.fillMaxWidth()) {
        item {
            SegmentedItemContainer {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            text = state.progress?.phase?.ifBlank { null }
                                ?: stringResource(R.string.keybox_progress_working),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        state.progress?.let { progress ->
                            val detail = buildString {
                                if (progress.total > 0) append("${progress.processed} / ${progress.total}")
                                if (progress.currentName.isNotBlank()) {
                                    if (isNotEmpty()) append(" · ")
                                    append(progress.currentName)
                                }
                            }
                            if (detail.isNotEmpty()) {
                                Text(
                                    text = detail,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MessageGroup(message: String) {
    SegmentedColumn(modifier = Modifier.fillMaxWidth()) {
        item {
            SegmentedListItem(
                colors = ListItemDefaults.segmentedColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                ),
                headlineContent = {
                    Text(
                        text = message,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                    )
                },
            )
        }
    }
}

@Composable
private fun RevocationGroup(state: KeyboxUiState, actions: KeyboxActions) {
    val sourceColor = keyboxStatusColor(
        if (state.revocationSource == RevocationSource.NONE) {
            RevocationStatus.UNKNOWN
        } else {
            RevocationStatus.VALID
        },
    )
    SegmentedColumn(
        modifier = Modifier.fillMaxWidth(),
        title = stringResource(R.string.keybox_revocation_title),
    ) {
        item {
            SegmentedListItem(
                headlineContent = {
                    Text(
                        text = stringResource(keyboxRevocationSourceLabelRes(state.revocationSource)),
                        color = sourceColor,
                    )
                },
                supportingContent = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        if (state.revocationEntries > 0) {
                            Text(stringResource(R.string.keybox_revocation_entries, state.revocationEntries))
                        }
                        if (state.revocationFetchedAt > 0L) {
                            Text(keyboxFormatTime(state.revocationFetchedAt))
                        }
                        state.revocationError?.let { error ->
                            Text(
                                text = error,
                                color = keyboxStatusColor(RevocationStatus.SUSPENDED),
                            )
                        }
                    }
                },
                trailingContent = {
                    TextButton(onClick = actions.onRefreshRevocation) {
                        Text(stringResource(R.string.keybox_revocation_refresh))
                    }
                },
            )
        }
    }
}

@Composable
private fun RepeatedGroup(repeated: List<RepeatedKey>) {
    SegmentedColumn(
        modifier = Modifier.fillMaxWidth(),
        title = stringResource(R.string.keybox_repeated_title),
    ) {
        item {
            SegmentedListItem(
                headlineContent = {
                    Text(
                        text = stringResource(R.string.keybox_repeated_note),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                },
            )
        }
        repeated.forEach { key ->
            item {
                SegmentedListItem(
                    headlineContent = {
                        Text(
                            text = key.fileNames.joinToString("、"),
                            color = MaterialTheme.colorScheme.error,
                        )
                    },
                )
            }
        }
    }
}

@Composable
private fun CertificateItem(
    keybox: AnalyzedKeybox,
    twins: List<String>,
    expanded: Boolean,
    onToggle: (String) -> Unit,
) {
    val color = keyboxStatusColor(keybox.status)
    SegmentedListItem(
        onClick = { onToggle(keybox.fileName) },
        leadingContent = {
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(color),
            )
        },
        headlineContent = {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = stringResource(keyboxStatusLabelRes(keybox.status)),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = color,
                    )
                    if (twins.isNotEmpty()) {
                        Icon(
                            imageVector = Icons.Rounded.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(16.dp),
                        )
                    }
                }
                Text(
                    text = keybox.fileName,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        },
        supportingContent = {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = keyboxShortHex(keybox.primaryKeyId ?: keybox.contentSha256),
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                )
                if (twins.isNotEmpty()) {
                    Text(
                        text = stringResource(R.string.keybox_repeated_key, twins.joinToString("、")),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                if (expanded) {
                    Text(
                        text = stringResource(R.string.keybox_group_identity, keybox.primaryKeyId ?: "-"),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                    Text(
                        text = stringResource(R.string.keybox_group_ignored),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    MemberDetails(keybox)
                }
            }
        },
        trailingContent = {
            Icon(
                imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
        },
    )
}

@Composable
private fun MemberDetails(member: AnalyzedKeybox) {
    val key = member.keys.firstOrNull()
    val sourceLabel = stringResource(R.string.keybox_source_local)
    val chainLabel = stringResource(keyboxChainLabelRes(key?.chainValid))
    val meta = buildString {
        append(sourceLabel)
        append(" · ")
        append(chainLabel)
        if (member.duplicateOf != null) append(" · duplicate")
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = member.fileName,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
        )
        Text(
            text = meta,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (key != null) {
            key.matchedSerial?.let { serial ->
                Text(
                    text = "serial $serial",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
            key.identityError?.let { error ->
                Text(
                    text = error,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            key.chainError?.let { error ->
                Text(
                    text = error,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            key.revocationReason?.let { reason ->
                Text(
                    text = reason,
                    style = MaterialTheme.typography.bodySmall,
                    color = keyboxStatusColor(key.status),
                )
            }
            Text(
                text = stringResource(keyboxRootStatusRes(key.rootStatus)),
                style = MaterialTheme.typography.bodySmall,
                color = if (key.rootStatus == RootStatus.UNKNOWN) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
            key.chainRoot?.let { root ->
                Text(
                    text = stringResource(R.string.keybox_root_recognized, root),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (key.remoteProvisioned) {
                Text(
                    text = stringResource(R.string.keybox_rkp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            if (key.privateKeyMatchesLeaf == false) {
                Text(
                    text = stringResource(R.string.keybox_private_key_mismatch),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            if (key.tooManyCertificates) {
                Text(
                    text = stringResource(R.string.keybox_too_many_certificates),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (member.expired) {
            Text(
                text = stringResource(R.string.keybox_expired),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}

@Composable
private fun SaveGroup(state: KeyboxUiState, actions: KeyboxActions) {
    SegmentedColumn(
        modifier = Modifier.fillMaxWidth(),
        title = stringResource(R.string.keybox_output_title),
    ) {
        item {
            SegmentedItemContainer {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        text = "${stringResource(R.string.keybox_output_dir)}: ${state.outputDir}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Button(
                        onClick = actions.onSaveConfirmed,
                        enabled = state.report != null && !state.isScanning,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.keybox_save))
                    }
                }
            }
        }
    }
}

@Composable
private fun NotesGroup(notes: List<String>) {
    SegmentedColumn(
        modifier = Modifier.fillMaxWidth(),
        title = stringResource(R.string.keybox_notes),
    ) {
        notes.forEach { note ->
            item {
                SegmentedListItem(headlineContent = { Text(note) })
            }
        }
    }
}
