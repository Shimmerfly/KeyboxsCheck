package dev.hcy917.keyboxchecker.ui.screen.keybox

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.keybox.AnalyzedKeybox
import dev.hcy917.keyboxchecker.keybox.KeyGroup
import dev.hcy917.keyboxchecker.keybox.KeyboxSource
import dev.hcy917.keyboxchecker.keybox.RevocationSource
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Card as MiuixCard
import top.yukonga.miuix.kmp.basic.Icon as MiuixIcon
import top.yukonga.miuix.kmp.basic.IconButton as MiuixIconButton
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold as MiuixScaffold
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.basic.TextField as MiuixTextField
import top.yukonga.miuix.kmp.basic.TopAppBar as MiuixTopAppBar
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
internal fun KeyboxScreenMiuix(
    state: KeyboxUiState,
    actions: KeyboxActions,
    onBack: () -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior()
    MiuixScaffold(
        topBar = {
            MiuixTopAppBar(
                title = stringResource(R.string.keybox_section),
                navigationIcon = {
                    MiuixIconButton(onClick = onBack) {
                        MiuixIcon(MiuixIcons.Back, contentDescription = null)
                    }
                },
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
            item { Spacer(Modifier.height(0.dp)) }
            item { InputCardMiuix(state, actions) }
            item { TelegramCardMiuix(state, actions) }

            if (state.isScanning || state.isImporting) {
                item { BusyCardMiuix(state) }
            }

            state.message?.let { message ->
                item { MessageCardMiuix(message) }
            }

            item { RevocationCardMiuix(state, actions) }
            item { SectionTitleMiuix(stringResource(R.string.keybox_results_title)) }

            if (state.groups.isEmpty()) {
                item {
                    MiuixCard(modifier = Modifier.fillMaxWidth()) {
                        MiuixText(
                            text = stringResource(R.string.keybox_no_results),
                            fontSize = MiuixTheme.textStyles.body2.fontSize,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            modifier = Modifier.padding(16.dp),
                        )
                    }
                }
            }

            items(state.groups, key = { it.keyId }) { group ->
                GroupCardMiuix(
                    group = group,
                    expanded = state.expandedGroups.contains(group.keyId),
                    onToggle = actions.onToggleGroup,
                )
            }

            item { SaveCardMiuix(state, actions) }

            if (state.notes.isNotEmpty()) {
                item { NotesCardMiuix(state.notes) }
            }
        }
    }
}

@Composable
private fun SectionTitleMiuix(text: String) {
    MiuixText(
        text = text,
        fontSize = MiuixTheme.textStyles.headline1.fontSize,
        fontWeight = FontWeight.Medium,
        color = MiuixTheme.colorScheme.onSurface,
        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp),
    )
}

@Composable
private fun InputCardMiuix(state: KeyboxUiState, actions: KeyboxActions) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            MiuixText(
                text = stringResource(R.string.keybox_input_title),
                fontSize = MiuixTheme.textStyles.headline1.fontSize,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
            )
            MiuixTextField(
                value = state.path,
                onValueChange = actions.onPathChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.keybox_path_label),
                singleLine = true,
            )
            state.pickedTreeLabel?.let { label ->
                MiuixText(
                    text = stringResource(R.string.keybox_picked, label),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.primary,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MiuixTextButton(
                    text = stringResource(R.string.keybox_pick_directory),
                    onClick = actions.onPickDirectory,
                )
                if (state.isScanning || state.isImporting) {
                    MiuixTextButton(
                        text = stringResource(R.string.keybox_cancel),
                        onClick = actions.onCancel,
                    )
                } else {
                    MiuixTextButton(
                        text = stringResource(R.string.keybox_scan),
                        onClick = actions.onScan,
                    )
                }
            }
        }
    }
}

@Composable
private fun TelegramCardMiuix(state: KeyboxUiState, actions: KeyboxActions) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            MiuixText(
                text = stringResource(R.string.keybox_telegram_title),
                fontSize = MiuixTheme.textStyles.headline1.fontSize,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
            )
            MiuixText(
                text = stringResource(R.string.keybox_telegram_note),
                fontSize = MiuixTheme.textStyles.body2.fontSize,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            MiuixTextField(
                value = state.tgBotToken,
                onValueChange = actions.onBotTokenChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.keybox_bot_token),
                singleLine = true,
            )
            MiuixTextField(
                value = state.tgChannel,
                onValueChange = actions.onChannelChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.keybox_channel),
                singleLine = true,
            )
            MiuixTextButton(
                text = stringResource(R.string.keybox_import),
                onClick = actions.onImportFromTelegram,
                enabled = !state.isImporting && !state.isScanning,
            )
            MiuixText(
                text = stringResource(R.string.keybox_privacy_note),
                fontSize = MiuixTheme.textStyles.body2.fontSize,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

@Composable
private fun BusyCardMiuix(state: KeyboxUiState) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            InfiniteProgressIndicator()
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                MiuixText(
                    text = state.progress?.phase?.ifBlank { null }
                        ?: stringResource(R.string.keybox_progress_working),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.onSurface,
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
                        MiuixText(
                            text = detail,
                            fontSize = MiuixTheme.textStyles.body2.fontSize,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun MessageCardMiuix(message: String) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        MiuixText(
            text = message,
            fontSize = MiuixTheme.textStyles.body2.fontSize,
            color = MiuixTheme.colorScheme.onSurface,
            modifier = Modifier.padding(16.dp),
        )
    }
}

@Composable
private fun RevocationCardMiuix(state: KeyboxUiState, actions: KeyboxActions) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            MiuixText(
                text = stringResource(R.string.keybox_revocation_title),
                fontSize = MiuixTheme.textStyles.headline1.fontSize,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
            )
            MiuixText(
                text = stringResource(keyboxRevocationSourceLabelRes(state.revocationSource)),
                fontSize = MiuixTheme.textStyles.body2.fontSize,
                color = if (state.revocationSource == RevocationSource.NONE) {
                    MiuixTheme.colorScheme.error
                } else {
                    MiuixTheme.colorScheme.onSurfaceVariantSummary
                },
            )
            if (state.revocationEntries > 0) {
                MiuixText(
                    text = stringResource(R.string.keybox_revocation_entries, state.revocationEntries),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            if (state.revocationFetchedAt > 0L) {
                MiuixText(
                    text = keyboxFormatTime(state.revocationFetchedAt),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            state.revocationError?.let { error ->
                MiuixText(
                    text = error,
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.error,
                )
            }
            MiuixTextButton(
                text = stringResource(R.string.keybox_revocation_refresh),
                onClick = actions.onRefreshRevocation,
            )
        }
    }
}

@Composable
private fun GroupCardMiuix(group: KeyGroup, expanded: Boolean, onToggle: (String) -> Unit) {
    val color = keyboxStatusColor(group.status)
    val summary = buildString {
        append(stringResource(R.string.keybox_group_members, group.memberCount))
        if (group.chainVariants > 1) {
            append(" · ")
            append(stringResource(R.string.keybox_group_variants, group.chainVariants))
        }
    }

    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        BasicComponent(
            title = stringResource(keyboxStatusLabelRes(group.status)),
            summary = summary,
            startAction = {
                Box(
                    modifier = Modifier
                        .padding(end = 8.dp)
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(color),
                )
            },
            endActions = {
                MiuixIcon(
                    imageVector = if (group.status.severity >= 2) {
                        Icons.Default.Warning
                    } else {
                        Icons.Default.CheckCircle
                    },
                    tint = color,
                    contentDescription = null,
                )
            },
            onClick = { onToggle(group.keyId) },
        )
        if (expanded) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                group.deviceIds.take(6).forEach { deviceId ->
                    MiuixText(
                        text = stringResource(R.string.keybox_group_devices, deviceId),
                        fontSize = MiuixTheme.textStyles.body2.fontSize,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                MiuixText(
                    text = stringResource(R.string.keybox_group_identity, group.keyId),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                MiuixText(
                    text = stringResource(R.string.keybox_group_ignored),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                group.members.take(12).forEach { member -> MemberRowsMiuix(member) }
            }
        }
    }
}

@Composable
private fun MemberRowsMiuix(member: AnalyzedKeybox) {
    val key = member.keys.firstOrNull()
    val sourceLabel = stringResource(
        if (member.source == KeyboxSource.TELEGRAM) {
            R.string.keybox_source_telegram
        } else {
            R.string.keybox_source_local
        },
    )
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
            .padding(top = 8.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        MiuixText(
            text = member.fileName,
            fontSize = MiuixTheme.textStyles.body2.fontSize,
            fontWeight = FontWeight.Medium,
            color = MiuixTheme.colorScheme.onSurface,
        )
        MiuixText(
            text = meta,
            fontSize = MiuixTheme.textStyles.body2.fontSize,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        if (key != null) {
            key.matchedSerial?.let { serial ->
                MiuixText(
                    text = "serial $serial",
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            key.revocationReason?.let { reason ->
                MiuixText(
                    text = reason,
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = keyboxStatusColor(key.status),
                )
            }
        }
    }
}

@Composable
private fun SaveCardMiuix(state: KeyboxUiState, actions: KeyboxActions) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            MiuixText(
                text = stringResource(R.string.keybox_output_title),
                fontSize = MiuixTheme.textStyles.headline1.fontSize,
                fontWeight = FontWeight.Medium,
                color = MiuixTheme.colorScheme.onSurface,
            )
            MiuixText(
                text = "${stringResource(R.string.keybox_output_dir)}: ${state.outputDir}",
                fontSize = MiuixTheme.textStyles.body2.fontSize,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            MiuixTextButton(
                text = stringResource(R.string.keybox_save),
                onClick = actions.onSaveConfirmed,
                enabled = state.report != null && !state.isScanning && !state.isImporting,
            )
        }
    }
}

@Composable
private fun NotesCardMiuix(notes: List<String>) {
    MiuixCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            MiuixText(
                text = stringResource(R.string.keybox_notes),
                fontSize = MiuixTheme.textStyles.headline1.fontSize,
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
