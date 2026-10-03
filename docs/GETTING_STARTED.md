# Start A New Project From This Template

English | [简体中文](GETTING_STARTED.zh-CN.md)

This checklist helps you migrate KernelSU Style UI Kit into your own Android project. Follow it in order and run a build after major steps so package, resource, or naming issues show up early.

## 1. Create Your Project

The recommended path is to click `Use this template` on GitHub and create your own repository. You can also clone it and point the remote to your repository:

```bash
git clone https://github.com/chenaizhang/KernelSU-Style-UI-Kit.git
cd KernelSU-Style-UI-Kit
git remote set-url origin https://github.com/<owner>/<repo>.git
```

If you want to keep the original template as an upstream remote:

```bash
git remote add upstream https://github.com/chenaizhang/KernelSU-Style-UI-Kit.git
```

## 2. Run It Once

Open the project with Android Studio, wait for Gradle sync to finish, then verify the template builds before changing it:

```bash
./gradlew :app:assembleDebug
```

Once it runs cleanly, start renaming and replacing template content.

## 3. Update Project Identity

Update the Gradle project name:

```kotlin
// settings.gradle.kts
rootProject.name = "YourProjectName"
```

Update the app package and version information:

```kotlin
// app/build.gradle.kts
android {
    namespace = "com.yourcompany.yourapp"

    defaultConfig {
        applicationId = "com.yourcompany.yourapp"
        versionCode = 1
        versionName = "1.0.0"
    }
}
```

Update the APK archive prefix:

```kotlin
// app/build.gradle.kts
base {
    archivesName.set("YourProjectName_${managerVersionName}_${managerVersionCode}")
}
```

Update the app name:

```xml
<!-- app/src/main/res/values/strings.xml -->
<string name="app_name" translatable="false">Your App Name</string>
```

## 4. Rename The Source Package

The current source package is:

```text
com.example.kernelsustyleuikit
```

If your package is `com.yourcompany.yourapp`, move the source directory to:

```text
app/src/main/java/com/yourcompany/yourapp
```

Then replace package and import references in Kotlin/Java files:

```text
com.example.kernelsustyleuikit -> com.yourcompany.yourapp
```

Build again:

```bash
./gradlew :app:assembleDebug
```

## 5. Replace Branding Assets

At minimum, replace these assets:

```text
app/src/main/res/drawable/ic_logo.xml
app/src/main/res/drawable/ic_launcher_foreground.xml
app/src/main/res/drawable/ic_launcher_monochrome.xml
app/src/main/res/mipmap-*/ic_launcher.png
app/src/main/res/raw/logo.svg
docs/assets/screenshots/*.webp
```

If you change the home screen layout, also update the theme settings preview so the preview stays aligned with the real home screen.

## 6. Update Links And Update Checking

Replace template repository links with your own project links:

```text
docs/README.md
docs/README.zh-CN.md
app/src/main/res/values/strings.xml
app/src/main/java/.../ui/screen/about/AboutScreen.kt
app/src/main/java/.../ui/util/Downloader.kt
```

Update checking currently reads GitHub Releases latest API:

```kotlin
https://api.github.com/repos/<owner>/<repo>/releases/latest
```

If your project does not use GitHub Releases, replace the implementation in `Downloader.kt`.

## 7. Pick The Default UI Style

The template includes both Miuix and Material UI styles. The default UI style is controlled by `UiMode.DEFAULT_VALUE`:

```text
app/src/main/java/.../ui/UiMode.kt
```

Miuix defaults such as blur, floating bottom bar, and glass effect live here:

```text
app/src/main/java/.../ui/screen/settings/SettingsUiState.kt
app/src/main/java/.../data/repository/SettingsRepositoryImpl.kt
```

## 8. Replace Example Content

The template includes a sample notification, sample link, and permission page. Most projects should start by replacing these files:

```text
app/src/main/java/.../ui/screen/home
app/src/main/java/.../ui/screen/permission
app/src/main/java/.../ui/screen/settings
app/src/main/res/values/strings.xml
```

If your project does not need the permission page, remove its route, screen, permission manager, and manifest permissions.

## 9. Add Product Features

New screens usually touch these areas:

```text
app/src/main/java/.../ui/navigation3/Routes.kt
app/src/main/java/.../ui/MainActivity.kt
app/src/main/java/.../ui/screen/<feature>
app/src/main/java/.../ui/viewmodel
```

Follow the existing structure:

```text
screen/<feature>/<Feature>Screen.kt
screen/<feature>/<Feature>UiState.kt
viewmodel/<Feature>ViewModel.kt
```

## 10. Pre-Release Checklist

Before release, verify:

- `applicationId` is your final unique package name
- `namespace` matches the source package
- app name, icons, About link, and update-check URL are correct
- README screenshots have been replaced with your app screenshots
- unused example screens, strings, and permissions have been removed
- release signing files and passwords are not committed

Build the release APK:

```bash
./gradlew :app:assembleRelease
```

For signed releases, create a local signing configuration based on `sign.example.properties` and make sure real keystore files stay ignored by `.gitignore`.
