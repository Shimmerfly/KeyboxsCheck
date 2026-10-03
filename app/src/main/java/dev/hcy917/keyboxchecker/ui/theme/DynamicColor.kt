package dev.hcy917.keyboxchecker.ui.theme

import android.content.Context
import android.os.Build
import androidx.annotation.ChecksSdkIntAtLeast
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.ui.graphics.Color

/**
 * Wallpaper based colours (Material You) were introduced in Android 12, and the
 * platform entry points below that throw. Every call site therefore has to check
 * first and fall back to a fixed seed.
 */
@ChecksSdkIntAtLeast(api = Build.VERSION_CODES.S)
fun supportsDynamicColor(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

/** The wallpaper colour scheme, or null on platforms that cannot provide one. */
fun dynamicColorSchemeOrNull(context: Context, isDark: Boolean): ColorScheme? =
    // The comparison is inlined so the API checker can see the platform guard.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        if (isDark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
    } else {
        null
    }

/** Seed used when the wallpaper palette was requested but the platform has none. */
val MaterialYouFallbackSeed: Color = Color(0xFF6750A4)
