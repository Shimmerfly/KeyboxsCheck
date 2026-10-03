package dev.hcy917.keyboxchecker.ui.screen.home

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.unit.Dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.hcy917.keyboxchecker.permission.PermissionManager
import dev.hcy917.keyboxchecker.ui.LocalUiMode
import dev.hcy917.keyboxchecker.ui.UiMode
import dev.hcy917.keyboxchecker.ui.navigation3.Navigator
import dev.hcy917.keyboxchecker.ui.navigation3.Route
import dev.hcy917.keyboxchecker.ui.viewmodel.HomeViewModel

@Composable
fun HomePager(
    navigator: Navigator,
    bottomInnerPadding: Dp,
    isCurrentPage: Boolean = true
) {
    val viewModel = viewModel<HomeViewModel>()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val context = androidx.compose.ui.platform.LocalContext.current
    val permissionManager = remember(context) { PermissionManager(context) }
    val permissionState by permissionManager.state.collectAsStateWithLifecycle()

    var hasActivated by remember { mutableStateOf(false) }
    if (isCurrentPage) hasActivated = true

    if (hasActivated) {
        LaunchedEffect(Unit) {
            viewModel.refresh()
        }
    }
    LifecycleResumeEffect(permissionManager) {
        permissionManager.refresh()
        onPauseOrDispose { }
    }

    val actions = HomeActions(
        onPermissionsClick = { navigator.push(Route.Permissions) },
        onKeyboxClick = { navigator.push(Route.Keybox) },
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> HomePagerMiuix(
            state = uiState,
            permissionState = permissionState,
            actions = actions,
            bottomInnerPadding = bottomInnerPadding,
        )

        UiMode.Material -> HomePagerMaterial(
            state = uiState,
            permissionState = permissionState,
            actions = actions,
            bottomInnerPadding = bottomInnerPadding,
        )
    }
}
