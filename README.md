# KeyboxsCheck

An Android app that audits Android key attestation **keyboxes**: it finds every
keybox it can reach, checks each key against Google's attestation revocation
list, and groups the keys by *key identity* so that cloned keyboxes which only
differ in tamperable fields are shown together.

Built on the [KernelSU Style UI Kit](https://github.com/chenaizhang/KernelSU-Style-UI-Kit)
template and modelled after [KeyAttestation](https://github.com/VisionR1/KeyAttestation).

## What it does

1. **Scan** an absolute directory path or a directory granted through the
   Storage Access Framework, recursively, for `*.xml` files.
2. **Parse** every XML that looks like a keybox and classify it as *confirmed*
   (parseable XML + at least one `<Key>` + an X.509-parseable certificate chain)
   or *not a keybox*.
3. **Check revocation** of every certificate in the chain against
   `https://android.googleapis.com/attestation/status`, reporting the worst
   status found: `REVOKED`, `SUSPENDED`, `VALID` or `UNKNOWN`.
4. **Import from Telegram**: poll a channel through a bot you configure and pull
   every `.xml` document it contains, then compare those against the local ones
   in a single result set.
5. **Group by key identity**: keys are identified by the SHA-256 of the
   SubjectPublicKeyInfo derived from the private key (falling back to the leaf
   certificate, then to the raw PEM bytes). `DeviceID` and other attestation
   properties that a cloner can freely edit **never** take part in matching —
   they are only reported as *differing fields*.
6. **Save** every confirmed keybox to
   `<output>/<device-id-or-unknown>/<original-name>.xml`, next to a generated
   `classification.json` and `report.md`.

## Requirements

- Android 8.0 (API 26) or newer.
- No root. Reading arbitrary absolute paths is optional and uses
  `MANAGE_EXTERNAL_STORAGE`; the default path is the Storage Access Framework.
- A network connection for the revocation list. Without one the app uses the
  24-hour cache and, if there is no cache at all, reports every key as
  `UNKNOWN` rather than pretending it is valid.

## Telegram setup

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy its token.
2. **Add the bot to the channel.** Telegram only delivers `channel_post`
   updates for channels the bot is a member of — making it an administrator is
   the reliable option.
3. For a private channel use the numeric id (`-100…`), because usernames are not
   available. Public channels accept `@name` as well.
4. Put the token and the channel id in the app's keybox screen. The token is
   stored in private `SharedPreferences` only; it is never written to a report,
   a log or version control.

## Build

```bash
./gradlew :app:assembleDebug          # debug APK
./gradlew :app:testDebugUnitTest      # JVM unit tests (engine only)
./gradlew :app:assembleRelease        # release APK, needs the signing secrets
```

The engine package `dev.hcy917.keyboxchecker.keybox` is pure JDK (plus OkHttp
and `org.json`), which is why the unit tests run on a plain JVM with no Android
runtime. `KeyboxRepository` is the only file in that package that touches the
Android SDK, and the Compose screens live in `ui/screen/keybox`.

## Signing a release

`app/build.gradle.kts` uses the [apksign](https://github.com/LSPosed/LSPlant)
Gradle plugin. It reads four *project properties*:

| Property | Meaning |
| --- | --- |
| `KEYSTORE_FILE` | Path to the keystore file |
| `KEYSTORE_PASSWORD` | Keystore password |
| `KEY_ALIAS` | Key alias |
| `KEY_PASSWORD` | Key password |

Provide them through environment variables rather than a file in the repository:

```bash
export ORG_GRADLE_PROJECT_KEYSTORE_FILE=/secure/release.jks
export ORG_GRADLE_PROJECT_KEYSTORE_PASSWORD=…
export ORG_GRADLE_PROJECT_KEY_ALIAS=…
export ORG_GRADLE_PROJECT_KEY_PASSWORD=…
./gradlew :app:assembleRelease
```

Without them the plugin falls back to the debug signature and the build still
succeeds, so an unconfigured checkout is never broken.

## Continuous integration

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `.github/workflows/build.yml` | push / PR to `main` | runs `:app:testDebugUnitTest`, then `:app:assembleDebug` and `:app:lintDebug`, uploading the APK, test report and lint report as artifacts |
| `.github/workflows/release.yml` | push of a `v*` tag | builds a signed `:app:assembleRelease` and publishes it as a GitHub release |
| `.github/workflows/sync-upstream.yml` | daily at 03:00 UTC | merges new commits from the upstream UI kit template and opens a pull request |

The release workflow expects four repository secrets: `KEYSTORE_FILE` (the
keystore, base64-encoded), `KEYSTORE_PASSWORD`, `KEY_ALIAS` and `KEY_PASSWORD`.
Release signing is best-effort: with no secrets the workflow still produces a
debug-signed APK and prints a warning.

## Privacy and scope

- Telegram credentials stay on the device in private app storage.
- No telemetry. The only network calls are the Telegram API (with the token you
  supply) and Google's public revocation list.
- This project is not affiliated with or endorsed by Google. Use it on keyboxes
  you own or are authorised to inspect; a keybox is a secret that identifies a
  device's attestation identity.

## License

GPL-3.0, inherited from the upstream UI kit template. See `LICENSE`.
