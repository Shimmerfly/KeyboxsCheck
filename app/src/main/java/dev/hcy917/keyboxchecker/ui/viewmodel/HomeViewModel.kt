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
     * Re-reads the answer root already gave. Every page rebuilds on resume, and
     * root may have been granted from somewhere else in the meantime, but this
     * must never prompt: only the card's tap may do that.
     */
    fun refreshRoot() {
        _uiState.update { it.copy(rootReady = repository.rootGranted()) }
    }

    /** Asks for root; this is what makes the superuser app show its prompt. */
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
