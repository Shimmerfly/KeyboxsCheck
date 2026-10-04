package dev.hcy917.keyboxchecker.ui.screen.home

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.TopAppBarScrollBehavior
import androidx.compose.material3.contentColorFor
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import dev.hcy917.keyboxchecker.R
import dev.hcy917.keyboxchecker.permission.PermissionState
import dev.hcy917.keyboxchecker.ui.component.WarningLevel
import dev.hcy917.keyboxchecker.ui.component.dialog.rememberConfirmDialog
import dev.hcy917.keyboxchecker.ui.component.material.ExpressiveScaffold
import dev.hcy917.keyboxchecker.ui.component.material.SegmentedColumn
import dev.hcy917.keyboxchecker.ui.component.material.SegmentedListItem
import dev.hcy917.keyboxchecker.ui.component.material.expressiveTopAppBarColors

/**
 * Material 3 Expressive home page, laid out the way the official KernelSU
 * manager does it: a large flexible top bar over `surfaceContainer`, then
 * segmented groups of list items instead of free-floating cards.
 */
@Composable
fun HomePagerMaterial(
    state: HomeUiState,
    permissionState: PermissionState,
    actions: HomeActions,
    bottomInnerPadding: Dp,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = { TopBar(scrollBehavior = scrollBehavior) },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(13.dp)
        ) {
            UpdateCard(state)

            PermissionCard(
                state = permissionState,
                onClick = actions.onPermissionsClick,
            )

            InfoCard(systemInfo = state.systemInfo)

            SegmentedColumn(modifier = Modifier.fillMaxWidth()) {
                item {
                    SegmentedListItem(
                        onClick = actions.onKeyboxClick,
                        headlineContent = { Text(stringResource(R.string.keybox_section)) },
                        supportingContent = { Text(stringResource(R.string.keybox_home_summary)) },
                        leadingContent = {
                            Icon(Icons.Filled.Search, stringResource(R.string.keybox_section))
                        },
                        trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null) },
                    )
                }
            }

            Spacer(Modifier.height(bottomInnerPadding))
        }
    }
}

@Composable
private fun UpdateCard(state: HomeUiState) {
    val newVersion = state.latestVersionInfo
    val hasUpdate = state.checkUpdateEnabled && newVersion.versionCode > state.currentAppVersionCode

    AnimatedVisibility(
        visible = hasUpdate,
        enter = fadeIn() + expandVertically(),
        exit = shrinkVertically() + fadeOut(),
    ) {
        val uriHandler = LocalUriHandler.current
        val updateText = stringResource(R.string.home_update)
        val updateDialog = rememberConfirmDialog(
            onConfirm = { uriHandler.openUri(newVersion.downloadUrl) }
        )

        WarningCard(
            message = stringResource(R.string.home_new_version_available, newVersion.versionCode),
            level = WarningLevel.Notice,
        ) {
            TextButton(
                onClick = {
                    if (newVersion.changelog.isEmpty()) {
                        uriHandler.openUri(newVersion.downloadUrl)
                    } else {
                        updateDialog.showConfirm(
                            title = updateText,
                            content = newVersion.changelog,
                            markdown = false,
                            confirm = updateText,
                        )
                    }
                }
            ) {
                Text(updateText)
            }
        }
    }
}

@Composable
private fun TopBar(
    scrollBehavior: TopAppBarScrollBehavior? = null
) {
    LargeFlexibleTopAppBar(
        title = { Text(stringResource(R.string.app_name)) },
        colors = expressiveTopAppBarColors(),
        windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
        scrollBehavior = scrollBehavior
    )
}

@Composable
private fun PermissionCard(
    state: PermissionState,
    onClick: () -> Unit,
) {
    val granted = state.requiredGranted
    val containerColor = if (granted) {
        MaterialTheme.colorScheme.secondaryContainer
    } else {
        MaterialTheme.colorScheme.errorContainer
    }
    val contentColor = contentColorFor(containerColor)
    val title = stringResource(
        if (granted) R.string.permission_status_ready_title else R.string.permission_status_missing_title
    )

    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = containerColor,
        contentColor = contentColor,
        shape = MaterialTheme.shapes.large,
        onClick = onClick,
    ) {
        ListItem(
            leadingContent = { Icon(Icons.Rounded.CheckCircle, contentDescription = title) },
            trailingContent = {
                Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
            },
            supportingContent = {
                Text(
                    text = stringResource(
                        if (granted) R.string.permission_ready else R.string.permission_missing
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            verticalAlignment = Alignment.CenterVertically,
            colors = ListItemDefaults.colors(
                containerColor = Color.Transparent,
                contentColor = contentColor,
                leadingContentColor = contentColor,
                trailingContentColor = contentColor,
                supportingContentColor = contentColor.copy(alpha = 0.7f),
            ),
            elevation = ListItemDefaults.elevation(),
            content = {
                Text(text = title, style = MaterialTheme.typography.titleMedium)
            },
        )
    }
}

@Composable
private fun InfoCard(
    systemInfo: SystemInfo,
    modifier: Modifier = Modifier,
) {
    @Composable
    fun InfoItem(icon: ImageVector, label: String, content: String) {
        SegmentedListItem(
            headlineContent = { Text(text = label, style = MaterialTheme.typography.bodyLarge) },
            leadingContent = { Icon(imageVector = icon, contentDescription = label) },
            supportingContent = {
                Text(
                    text = content,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            },
        )
    }

    val appVersion = stringResource(R.string.home_app_version)
    SegmentedColumn(modifier = modifier.fillMaxWidth()) {
        item {
            InfoItem(
                icon = Icons.Filled.Tag,
                label = appVersion,
                content = systemInfo.appVersion,
            )
        }
    }
}

/** A segmented list item that is also a warning, coloured by severity. */
@Composable
private fun WarningCard(
    message: String,
    level: WarningLevel = WarningLevel.Error,
    onClick: (() -> Unit)? = null,
    content: @Composable () -> Unit = {},
) {
    val containerColor = when (level) {
        WarningLevel.Error -> MaterialTheme.colorScheme.errorContainer
        WarningLevel.Notice -> MaterialTheme.colorScheme.tertiaryContainer
    }
    val contentColor = contentColorFor(containerColor)

    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = containerColor,
        contentColor = contentColor,
        shape = MaterialTheme.shapes.large,
        onClick = onClick ?: {},
        enabled = onClick != null,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(
                imageVector = Icons.Rounded.Warning,
                contentDescription = null,
            )
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            content()
        }
    }
}
