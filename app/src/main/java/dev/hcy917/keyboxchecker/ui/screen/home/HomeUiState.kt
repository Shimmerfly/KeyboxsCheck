package dev.hcy917.keyboxchecker.ui.screen.home

import androidx.compose.runtime.Immutable
import dev.hcy917.keyboxchecker.ui.util.LatestVersionInfo

@Immutable
data class HomeUiState(
    val checkUpdateEnabled: Boolean,
    val latestVersionInfo: LatestVersionInfo,
    val currentAppVersionCode: Long,
    val systemInfo: SystemInfo,
    /** The module folder the keyboxes live in, named by the root card. */
    val libraryPath: String = "",
    /** True once root answers. The card is the only thing that ever asks. */
    val rootReady: Boolean = false,
)

@Immutable
data class HomeActions(
    /** Asks for root, which every keybox read and write goes through. */
    val onRequestRoot: () -> Unit,
    val onKeyboxClick: () -> Unit,
)
