package dev.hcy917.keyboxchecker.ui.screen.home

import androidx.compose.runtime.Immutable
import dev.hcy917.keyboxchecker.ui.util.LatestVersionInfo

@Immutable
data class HomeUiState(
    val checkUpdateEnabled: Boolean,
    val latestVersionInfo: LatestVersionInfo,
    val currentAppVersionCode: Long,
    val systemInfo: SystemInfo,
)

@Immutable
data class HomeActions(
    val onPermissionsClick: () -> Unit,
    val onKeyboxClick: () -> Unit,
    val onOpenUrl: (String) -> Unit,
)
