# KeyboxsCheck

An Android app that audits Android key attestation **keyboxes**: it finds every
keybox it can reach, checks each one the way the reference checkers do, and
groups keys by *key identity* so that cloned keyboxes are shown together.

Built on the [KernelSU Style UI Kit](https://github.com/chenaizhang/KernelSU-Style-UI-Kit)
template. The checks follow [KimmyXYC/KeyboxChecker](https://github.com/KimmyXYC/KeyboxChecker),
and chain roots are recognised with the pinned public keys of
[VisionR1/KeyAttestation](https://github.com/VisionR1/KeyAttestation), including
its remote-provisioning (RKP) detection.

## What it does

1. **Scan** an absolute directory path or a directory granted through the
   Storage Access Framework, recursively, for `*.xml` files.
2. **Parse** every XML that looks like a keybox and classify it as *confirmed*
   (parseable XML + at least one `<Key>` + an X.509-parseable certificate chain)
   or *not a keybox*.
3. **Check** every confirmed keybox with six rules taken from KeyboxChecker:

   | Check | Rule |
   | --- | --- |
   | Validity period | every certificate must be inside its `notBefore`/`notAfter` window |
   | Private key ↔ leaf | the public key derived from the private key must equal the leaf certificate's public key |
   | Chain links | each certificate's issuer must be the next certificate's subject, and each signature must verify |
   | Chain root | the last certificate must match one of the pinned roots |
   | Certificate count | more than three certificates is flagged |
   | Revocation | every certificate's serial is looked up in Google's published list |

4. **Recognise the root** by pinning the SubjectPublicKeyInfo of the known
   roots, exactly as KeyAttestation does: the Google hardware attestation root
   (RSA 4096), the **Google RKP root** (`CN=Key Attestation CA1`, P-384), the
   AOSP software roots (EC and RSA), and Samsung Knox SAK v1 / v2 / SAK-M v1.
   Anything else is reported as an unknown root, so a locally generated
   self-signed chain can never masquerade as a Google one.
5. **Detect RKP** per either signal: the chain terminates in the pinned RKP root,
   or the leaf certificate carries the `ProvisioningInfo` extension
   (`1.3.6.1.4.1.11129.2.1.30`).
6. **Check revocation** of every certificate in the chain against
   `https://android.googleapis.com/attestation/status`, reporting the worst
   status found: `REVOKED`, `SUSPENDED`, `VALID` or `UNKNOWN`. The published list
   mixes decimal and hex serials, so both readings are indexed. Without a usable
   list every key is reported as `UNKNOWN` rather than pretending to be valid.
7. **Group by key identity**: keys are identified by the SHA-256 of the
   SubjectPublicKeyInfo derived from the private key (falling back to the leaf
   certificate, then to the raw PEM bytes). `DeviceID` and other attestation
   properties a cloner can freely edit **never** take part in matching.
8. **Save** the confirmed keyboxes that are still valid:

   - expired keyboxes (any certificate outside its validity window) are not
     saved and are listed as skipped instead;
   - `DeviceID` is rewritten to **your own device id**, which you type into the
     keybox screen, so a saved keybox carries your identity rather than the
     seller's;
   - each file is named `yyyyMMdd` + `R`/`N` + five random digits, e.g.
     `20261003R12345.xml` — `R` for an RKP keybox, `N` for anything else, with
     the random part re-drawn until it does not collide with a file already
     saved that day;
   - next to them the app writes `classification.json` and `report.md`.

## Requirements

- Android 8.0 (API 26) or newer.
- No root. Reading arbitrary absolute paths is optional and uses
  `MANAGE_EXTERNAL_STORAGE`; the default path is the Storage Access Framework.
- A network connection for the revocation list. Without one the app uses the
  24-hour cache and, if there is no cache at all, reports every key as
  `UNKNOWN` rather than pretending it is valid.
- Your device id, typed into the keybox screen. It is needed only when saving.

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
| `.github/workflows/lint-baseline.yml` | manual | regenerates `app/lint-baseline.xml` after the upstream template changes |

The release workflow expects four repository secrets: `KEYSTORE_FILE` (the
keystore, base64-encoded), `KEYSTORE_PASSWORD`, `KEY_ALIAS` and `KEY_PASSWORD`.
Release signing is best-effort: with no secrets the workflow still produces a
debug-signed APK and prints a warning.

## Privacy and scope

- No telemetry and no accounts. The only network calls are Google's public
  revocation list and the upstream template sync, which runs in CI.
- Nothing about your keyboxes leaves the device: saved files, the classification
  JSON and the report are written to the output directory you choose.
- This project is not affiliated with or endorsed by Google. Use it on keyboxes
  you own or are authorised to inspect; a keybox is a secret that identifies a
  device's attestation identity.

## License

GPL-3.0, inherited from the upstream UI kit template. See `LICENSE`.
