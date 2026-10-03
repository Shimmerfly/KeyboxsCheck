package dev.hcy917.keyboxchecker.ui.screen.keybox

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.hcy917.keyboxchecker.ui.LocalUiMode
import dev.hcy917.keyboxchecker.ui.UiMode
import dev.hcy917.keyboxchecker.ui.navigation3.LocalNavigator

/**
 * Entry point of the keybox screen.
 *
 * The screen renders through whichever design system is active: the KernelSU
 * style (Miuix) or Material 3. Both layouts share one [KeyboxViewModel].
 */
@Composable
fun KeyboxScreen() {
    val navigator = LocalNavigator.current
    val viewModel = viewModel<KeyboxViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    val pickDirectory = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree(),
    ) { uri -> if (uri != null) viewModel.onTreePicked(uri) }

    // A single keybox is as valid an input as a whole tree, so files can be
    // picked one by one — possibly several at once — without granting access to
    // the folder that holds them.
    val pickFiles = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments(),
    ) { uris -> viewModel.onFilesPicked(uris) }

    val actions = KeyboxActions(
        onPathChanged = viewModel::onPathChanged,
        onPickDirectory = { pickDirectory.launch(null) },
        onPickFiles = { pickFiles.launch(arrayOf("*/*")) },
        onLocalDeviceIdChanged = viewModel::onLocalDeviceIdChanged,
        onScan = viewModel::onScan,
        onCancel = viewModel::onCancelScan,
        onRefreshRevocation = viewModel::onRefreshRevocation,
        onSaveConfirmed = viewModel::onSaveConfirmed,
        onToggleFile = viewModel::onToggleFile,
    )

    val onBack = dropUnlessResumed { navigator.pop() }

    when (LocalUiMode.current) {
        UiMode.Miuix -> KeyboxScreenMiuix(state, actions, onBack)
        UiMode.Material -> KeyboxScreenMaterial(state, actions, onBack)
    }
}
