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
import dev.hcy917.keyboxchecker.templateApp
import dev.hcy917.keyboxchecker.ui.screen.home.HomeUiState
import dev.hcy917.keyboxchecker.ui.screen.home.SystemInfo
import dev.hcy917.keyboxchecker.ui.screen.home.getAppVersion
import dev.hcy917.keyboxchecker.ui.util.LatestVersionInfo
import dev.hcy917.keyboxchecker.ui.util.checkNewVersion

class HomeViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(buildState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    fun updateTgBotToken(token: String) {
        _uiState.update { it.copy(tgBotToken = token) }
        templateApp.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().putString("tg_bot_token", token).apply()
    }

    fun updateTgChannelId(id: String) {
        _uiState.update { it.copy(tgChannelId = id) }
        templateApp.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().putString("tg_channel_id", id).apply()
    }

    fun refresh() {
        viewModelScope.launch {
            val baseState = withContext(Dispatchers.IO) { buildState() }
            _uiState.update { baseState }
            if (baseState.checkUpdateEnabled) {
                val latestVersionInfo = withContext(Dispatchers.IO) { checkNewVersion() }
                _uiState.update { it.copy(latestVersionInfo = latestVersionInfo) }
            }
        }
    }

    private fun buildState(): HomeUiState {
        val prefs = templateApp.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val appVersion = getAppVersion(templateApp)

        return HomeUiState(
            tgBotToken = prefs.getString("tg_bot_token", "") ?: "",
            tgChannelId = prefs.getString("tg_channel_id", "") ?: "",
            checkUpdateEnabled = templateApp.getSharedPreferences("settings", Context.MODE_PRIVATE)
                .getBoolean("check_update", true),
            latestVersionInfo = LatestVersionInfo(),
            currentAppVersionCode = appVersion.versionCode,
            systemInfo = SystemInfo(
                appVersion = "${appVersion.versionName} (${appVersion.versionCode})",
            ),
        )
    }
}
