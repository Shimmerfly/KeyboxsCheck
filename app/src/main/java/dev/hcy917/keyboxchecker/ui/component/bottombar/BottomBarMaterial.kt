package dev.hcy917.keyboxchecker.ui.component.bottombar

import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.union
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Bookmark
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ShortNavigationBar
import androidx.compose.material3.ShortNavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import dev.hcy917.keyboxchecker.ui.LocalMainPagerState

/**
 * Filled / outlined icon pair for one destination, so the selected item can be
 * drawn the way the official manager does.
 */
private data class NavIcon(val selected: ImageVector, val unselected: ImageVector)

private val materialNavIcons = listOf(
    NavIcon(Icons.Filled.Home, Icons.Outlined.Home),
    NavIcon(Icons.Filled.Bookmark, Icons.Outlined.Bookmark),
    NavIcon(Icons.Filled.Settings, Icons.Outlined.Settings),
)

/**
 * The Material 3 Expressive bottom bar, mirroring the official KernelSU manager:
 * a [ShortNavigationBar] on `surfaceContainer`, one item per main page.
 */
@Composable
fun BottomBarMaterial() {
    val mainPagerState = LocalMainPagerState.current

    ShortNavigationBar(
        containerColor = MaterialTheme.colorScheme.surfaceContainer,
        windowInsets = WindowInsets.systemBars.union(WindowInsets.displayCutout).only(
            WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom
        )
    ) {
        BottomBarDestination.entries.forEachIndexed { index, destination ->
            val selected = mainPagerState.selectedPage == index
            val label = stringResource(destination.label)
            val icon = materialNavIcons.getOrNull(index)
            ShortNavigationBarItem(
                selected = selected,
                onClick = {
                    if (!selected) {
                        mainPagerState.animateToPage(index)
                    }
                },
                icon = {
                    icon?.let {
                        Icon(
                            imageVector = if (selected) it.selected else it.unselected,
                            contentDescription = label,
                        )
                    }
                },
                label = {
                    Text(
                        label,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            )
        }
    }
}
