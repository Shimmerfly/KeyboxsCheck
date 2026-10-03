# 从模板开始新项目

[English](GETTING_STARTED.md) | 简体中文

这份清单用于帮助你把 KernelSU Style UI Kit 迁移成自己的 Android 项目。建议按顺序完成，每一步完成后都跑一次构建，能更早发现命名或资源遗漏。

## 1. 创建项目

推荐在 GitHub 上点击 `Use this template` 创建自己的仓库。也可以直接克隆后重新绑定远端：

```bash
git clone https://github.com/chenaizhang/KernelSU-Style-UI-Kit.git
cd KernelSU-Style-UI-Kit
git remote set-url origin https://github.com/<owner>/<repo>.git
```

如果你要保留模板上游，建议额外添加 upstream：

```bash
git remote add upstream https://github.com/chenaizhang/KernelSU-Style-UI-Kit.git
```

## 2. 第一次运行

用 Android Studio 打开项目，等待 Gradle 同步完成，然后先确认模板本身可以构建：

```bash
./gradlew :app:assembleDebug
```

确认运行正常后，再开始重命名和业务开发。

## 3. 修改项目身份

修改 Gradle 项目名：

```kotlin
// settings.gradle.kts
rootProject.name = "YourProjectName"
```

修改应用包名和版本信息：

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

修改 APK 产物名前缀：

```kotlin
// app/build.gradle.kts
base {
    archivesName.set("YourProjectName_${managerVersionName}_${managerVersionCode}")
}
```

修改应用名称：

```xml
<!-- app/src/main/res/values/strings.xml -->
<string name="app_name" translatable="false">Your App Name</string>
```

## 4. 迁移包名目录

当前源码包名是：

```text
com.example.kernelsustyleuikit
```

如果你的包名是 `com.yourcompany.yourapp`，需要把源码目录移动为：

```text
app/src/main/java/com/yourcompany/yourapp
```

同时全局替换 Kotlin/Java 文件中的 package 和 import：

```text
com.example.kernelsustyleuikit -> com.yourcompany.yourapp
```

完成后构建验证：

```bash
./gradlew :app:assembleDebug
```

## 5. 替换品牌资源

至少替换这些资源：

```text
app/src/main/res/drawable/ic_logo.xml
app/src/main/res/drawable/ic_launcher_foreground.xml
app/src/main/res/drawable/ic_launcher_monochrome.xml
app/src/main/res/mipmap-*/ic_launcher.png
app/src/main/res/raw/logo.svg
docs/assets/screenshots/*.webp
```

如果你调整了主页布局，请同步更新主题设置页里的预览图，避免预览与真实首页不一致。

## 6. 更新链接和检查更新

把模板仓库链接替换成你的项目链接：

```text
docs/README.md
docs/README.zh-CN.md
app/src/main/res/values/strings.xml
app/src/main/java/.../ui/screen/about/AboutScreen.kt
app/src/main/java/.../ui/util/Downloader.kt
```

更新检查默认读取 GitHub Releases latest API：

```kotlin
https://api.github.com/repos/<owner>/<repo>/releases/latest
```

如果你的项目不使用 GitHub Releases，可以替换 `Downloader.kt` 里的实现。

## 7. 选择默认界面风格

模板保留了 Miuix 和 Material 两套界面。默认界面风格由 `UiMode.DEFAULT_VALUE` 控制：

```text
app/src/main/java/.../ui/UiMode.kt
```

Miuix 的模糊、悬浮底栏、液态玻璃等默认值在这里：

```text
app/src/main/java/.../ui/screen/settings/SettingsUiState.kt
app/src/main/java/.../data/repository/SettingsRepositoryImpl.kt
```

## 8. 替换示例内容

模板内置了示例通知、示例链接和权限页。开始业务开发时，通常先替换这些位置：

```text
app/src/main/java/.../ui/screen/home
app/src/main/java/.../ui/screen/permission
app/src/main/java/.../ui/screen/settings
app/src/main/res/values/strings.xml
```

如果你的项目不需要权限页，可以删除相关 route、screen、permission manager 和 manifest permission。

## 9. 新增业务页面

新增页面通常需要改这些文件：

```text
app/src/main/java/.../ui/navigation3/Routes.kt
app/src/main/java/.../ui/MainActivity.kt
app/src/main/java/.../ui/screen/<feature>
app/src/main/java/.../ui/viewmodel
```

建议按当前结构组织：

```text
screen/<feature>/<Feature>Screen.kt
screen/<feature>/<Feature>UiState.kt
viewmodel/<Feature>ViewModel.kt
```

## 10. 发布前检查

发布前至少确认：

- `applicationId` 是唯一的正式包名
- `namespace` 与源码包名一致
- app 名称、图标、关于页链接、更新检查链接正确
- README 截图已替换为你的应用截图
- 不需要的示例页面、字符串、权限已经删除
- release 签名配置没有提交真实密码或 keystore

构建 release 包：

```bash
./gradlew :app:assembleRelease
```

如果需要签名发布，请基于 `sign.example.properties` 创建本地签名配置文件，并确保真实签名文件被 `.gitignore` 忽略。
