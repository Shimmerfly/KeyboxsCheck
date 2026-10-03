package dev.hcy917.keyboxchecker.ui.viewmodel

import androidx.compose.runtime.Immutable
import dev.hcy917.keyboxchecker.ui.UiMode
import dev.hcy917.keyboxchecker.ui.theme.AppSettings

@Immutable
data class MainActivityUiState(
    val appSettings: AppSettings,
    val pageScale: Float,
    val enableBlur: Boolean,
    val enableFloatingBottomBar: Boolean,
    val enableFloatingBottomBarBlur: Boolean,
    val uiMode: UiMode,
)
