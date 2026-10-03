package dev.hcy917.keyboxchecker.ui.screen.keybox

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.keybox.AnalyzedKeybox
import dev.hcy917.keyboxchecker.keybox.KeyGroup
import dev.hcy917.keyboxchecker.keybox.RevocationSource
import dev.hcy917.keyboxchecker.keybox.RevocationStatus
import dev.hcy917.keyboxchecker.keybox.RootStatus
import dev.hcy917.keyboxchecker.ui.component.material.TonalCard

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun KeyboxScreenMaterial(
    state: KeyboxUiState,
    actions: KeyboxActions,
    onBack: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.keybox_section)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
            )
        },
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { InputCard(state, actions) }

            if (state.isScanning) {
                item { BusyCard(state) }
            }

            state.message?.let { message ->
                item { MessageCard(message) }
            }

            item { RevocationCard(state, actions) }

            item {
                Text(
                    text = stringResource(R.string.keybox_results_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }

            if (state.groups.isEmpty()) {
                item {
                    TonalCard {
                        Text(
                            text = stringResource(R.string.keybox_no_results),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(16.dp),
                        )
                    }
                }
            }

            items(state.groups, key = { it.keyId }) { group ->
                GroupCard(
                    group = group,
                    expanded = state.expandedGroups.contains(group.keyId),
                    onToggle = actions.onToggleGroup,
                )
            }

            item { SaveCard(state, actions) }

            if (state.notes.isNotEmpty()) {
                item { NotesCard(state.notes) }
            }
        }
    }
}

@Composable
private fun InputCard(state: KeyboxUiState, actions: KeyboxActions) {
    TonalCard {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.keybox_input_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
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
                if (state.isScanning) {
                    OutlinedButton(onClick = actions.onCancel) {
                        Text(stringResource(R.string.keybox_cancel))
                    }
                } else {
                    Button(onClick = actions.onScan) {
                        Text(stringResource(R.string.keybox_scan))
                    }
                }
            }
        }
    }
}


@Composable
private fun BusyCard(state: KeyboxUiState) {
    TonalCard {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp))
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
                        Text(text = detail, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun MessageCard(message: String) {
    TonalCard(containerColor = MaterialTheme.colorScheme.secondaryContainer) {
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(16.dp),
        )
    }
}

@Composable
private fun RevocationCard(state: KeyboxUiState, actions: KeyboxActions) {
    TonalCard {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = stringResource(R.string.keybox_revocation_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = stringResource(keyboxRevocationSourceLabelRes(state.revocationSource)),
                style = MaterialTheme.typography.bodyMedium,
                color = keyboxStatusColor(
                    if (state.revocationSource == RevocationSource.NONE) {
                        RevocationStatus.UNKNOWN
                    } else {
                        RevocationStatus.VALID
                    },
                ),
            )
            if (state.revocationEntries > 0) {
                Text(
                    text = stringResource(R.string.keybox_revocation_entries, state.revocationEntries),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (state.revocationFetchedAt > 0L) {
                Text(
                    text = keyboxFormatTime(state.revocationFetchedAt),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            state.revocationError?.let { error ->
                Text(
                    text = error,
                    style = MaterialTheme.typography.bodySmall,
                    color = keyboxStatusColor(RevocationStatus.SUSPENDED),
                )
            }
            TextButton(onClick = actions.onRefreshRevocation) {
                Text(stringResource(R.string.keybox_revocation_refresh))
            }
        }
    }
}

@Composable
private fun GroupCard(group: KeyGroup, expanded: Boolean, onToggle: (String) -> Unit) {
    val color = keyboxStatusColor(group.status)
    TonalCard(onClick = { onToggle(group.keyId) }) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(color),
                )
                Text(
                    text = stringResource(keyboxStatusLabelRes(group.status)),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = color,
                )
                Spacer(Modifier.weight(1f))
                Text(
                    text = keyboxShortHex(group.keyId),
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                )
            }

            Text(
                text = stringResource(R.string.keybox_group_members, group.memberCount),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (group.chainVariants > 1) {
                Text(
                    text = stringResource(R.string.keybox_group_variants, group.chainVariants),
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            if (expanded) {
                group.deviceIds.take(6).forEach { deviceId ->
                    Text(
                        text = stringResource(R.string.keybox_group_devices, deviceId),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Text(
                    text = stringResource(R.string.keybox_group_identity, group.keyId),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
                Text(
                    text = stringResource(R.string.keybox_group_ignored),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(2.dp))
                group.members.take(12).forEach { member -> MemberRow(member) }
            }
        }
    }
}

@Composable
private fun MemberRow(member: AnalyzedKeybox) {
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
            .padding(vertical = 4.dp),
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
private fun SaveCard(state: KeyboxUiState, actions: KeyboxActions) {
    TonalCard {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.keybox_output_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = "${stringResource(R.string.keybox_output_dir)}: ${state.outputDir}",
                style = MaterialTheme.typography.bodySmall,
            )
            Button(
                onClick = actions.onSaveConfirmed,
                enabled = state.report != null && !state.isScanning,
            ) {
                Text(stringResource(R.string.keybox_save))
            }
        }
    }
}

@Composable
private fun NotesCard(notes: List<String>) {
    TonalCard {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = stringResource(R.string.keybox_notes),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            notes.forEach { note ->
                Text(text = note, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
