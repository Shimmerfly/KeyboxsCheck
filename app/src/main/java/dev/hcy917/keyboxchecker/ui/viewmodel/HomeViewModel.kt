package dev.hcy917.keyboxchecker.ui.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import dev.hcy917.keyboxchecker.keybox.KeyboxRepository
import dev.hcy917.keyboxchecker.templateApp
import dev.hcy917.keyboxchecker.ui.screen.home.HomeUiState
import dev.hcy917.keyboxchecker.ui.screen.home.SystemInfo
import dev.hcy917.keyboxchecker.ui.screen.home.getAppVersion
import dev.hcy917.keyboxchecker.ui.util.LatestVersionInfo
import dev.hcy917.keyboxchecker.ui.util.checkNewVersion

class HomeViewModel : ViewModel() {

    private val repository = KeyboxRepository(templateApp, templateApp.okhttpClient)

    private val _uiState = MutableStateFlow(buildState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    init {
        // Entering the app is reason enough to ask. Nothing on the keybox side
        // works without root, the superuser app answers from memory once it has
        // been told yes, and the grant itself only lives in this process - so
        // without this the card read "not granted" on every cold start until it
        // was tapped again.
        refreshRoot()
    }

    fun refresh() {
        viewModelScope.launch {
            val baseState = withContext(Dispatchers.IO) { buildState() }
            _uiState.update { baseState.copy(latestVersionInfo = it.latestVersionInfo) }
            if (baseState.checkUpdateEnabled) {
                val latestVersionInfo = withContext(Dispatchers.IO) { checkNewVersion() }
                _uiState.update { it.copy(latestVersionInfo = latestVersionInfo) }
            }
        }
    }

    /**
     * Re-reads root, asking only while this process has no verdict yet.
     *
     * [KeyboxRepository.rootAvailable] answers from the verdict it already has,
     * so a page rebuild is not a reason to prompt again; the first call in a
     * process is the one that talks to the superuser app.
     */
    fun refreshRoot() {
        viewModelScope.launch {
            val granted = withContext(Dispatchers.IO) { repository.rootAvailable() }
            _uiState.update { it.copy(rootReady = granted) }
        }
    }

    /** The card's tap: asks again even after a refusal. */
    fun requestRoot() {
        viewModelScope.launch {
            val granted = withContext(Dispatchers.IO) { repository.requestRoot() }
            _uiState.update { it.copy(rootReady = granted) }
        }
    }

    private fun buildState(): HomeUiState {
        val prefs = templateApp.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val appVersion = getAppVersion(templateApp)

        return HomeUiState(
            checkUpdateEnabled = prefs.getBoolean("check_update", true),
            latestVersionInfo = LatestVersionInfo(),
            currentAppVersionCode = appVersion.versionCode,
            systemInfo = SystemInfo(
                appVersion = "${appVersion.versionName} (${appVersion.versionCode})",
            ),
            libraryPath = repository.libraryPath(),
            rootReady = repository.rootGranted(),
        )
    }
}
