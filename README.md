# KeyboxsCheck

An Android app that audits Android key attestation **keyboxes**: it finds every
keybox it can reach, checks each one the way the reference checkers do, and
lists the results *one file at a time* — files that carry the same key are
flagged as repeats instead of being quietly merged into one entry.

Built on the [KernelSU Style UI Kit](https://github.com/chenaizhang/KernelSU-Style-UI-Kit)
template. The checks follow [KimmyXYC/KeyboxChecker](https://github.com/KimmyXYC/KeyboxChecker),
and chain roots are recognised with the pinned public keys of
[VisionR1/KeyAttestation](https://github.com/VisionR1/KeyAttestation), including
its remote-provisioning (RKP) detection.

## What it does

1. **Scan** an absolute directory path or a directory granted through the
   Storage Access Framework, recursively, for `*.xml` files — or pick one or
   more individual keyboxes with "Select files", without granting access to the
   folder that holds them.
2. **Parse** every XML that looks like a keybox and classify it as *confirmed*
   (parseable XML + at least one `<Key>` + an X.509-parseable certificate chain)
   or *not a keybox*.
3. **Check** every confirmed keybox with six rules taken from KeyboxChecker:

   | Check | Rule |
   | --- | --- |
   | Validity period | every certificate must be inside its `notBefore`/`notAfter` window — **a keybox with any expired certificate is reported as `REVOKED`** |
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
   list every key is reported as `UNKNOWN` rather than pretending to be valid,
   and saving is refused until a check has cleared the key.
   An expired certificate is `REVOKED` on its own — that verdict is reached
   locally, so it holds even when the list cannot be fetched.
7. **Compare by key, list by file**: keys are identified by the SHA-256 of the
   SubjectPublicKeyInfo derived from the private key (falling back to the leaf
   certificate, then to the raw PEM bytes). `DeviceID` and other attestation
   properties a cloner can freely edit **never** take part in matching. The
   result does *not* merge a key seen more than once: every file gets its own
   entry, and the files that share a key are flagged as repeats — so a second
   copy that differs only in its `DeviceID` cannot hide.
8. **Save** the confirmed keyboxes that are still valid — *only* the ones a
   revocation check has cleared:

   - **nothing is written without the revocation list.** A keybox is a secret; if
     the list cannot be reached, every key reads as `UNKNOWN` and saving is
     refused (the screen says so) rather than writing a key that may be revoked.
     `REVOKED`, `SUSPENDED`, `UNKNOWN` and expired keyboxes are never saved, and
     every skipped file says why;
   - every candidate is compared against the other files of this scan *and*
     against the library already on disk: a key is written once, a key the
     library already holds is never written again, and each skipped file says
     which file it repeats or which saved key it matches;
   - a keybox carries two keys (an ECDSA and an RSA one), so **every** key of a
     file takes part in that comparison — two files are the same certificate as
     soon as one of their keys matches;
   - expired keyboxes (any certificate outside its validity window) are reported
     as `REVOKED` and are not saved — they are listed as skipped instead;
   - `DeviceID` is rewritten to **your own device id**, which you type into the
     keybox screen, so a saved keybox carries your identity rather than the
     seller's;
   - each file is named `yyyyMMdd` + `R`/`N` + five random digits, e.g.
     `20261003R12345.xml` — `R` for an RKP keybox, `N` for anything else, with
     the random part re-drawn until it does not collide with a file already
     saved that day;
   - the file goes straight into `/data/adb/teesim`, the folder the TEESimulator
     module serves its keyboxes from: no subfolder, and nothing else is written
     beside it, because the module reads that folder and no other file belongs in
     it. Writing there needs root, so the app asks for it the first time it needs
     it; without root nothing at all is saved and the screen says so.
9. **Browse what you saved** in the *Saved* section of the bottom bar
   (`Home → Saved → Settings`), which lists that same module folder. Each entry
   is labelled by date, kind and serial — `3 Oct 2026 Local 58052` — where the
   stored `R`/`N` marker decides whether it reads *RKP* or *Local*; the file on
   disk keeps its original name. The keybox the module's `config.json` points at
   is highlighted in the list and named as the current one, and **Use this
   keybox** points every profile in that file at the keybox you pick, behind a
   confirmation — the keybox itself is never modified. The section carries four
   collection-wide actions:

   - **Check revocation** treats the whole library as one scan and writes the
     verdict of every file back into the list, so revoked ones turn red;
   - **Delete all revoked** removes only the files a check has confirmed as
     `REVOKED` or `SUSPENDED`, behind a confirmation dialog — nothing is deleted
     before a check has run;
   - **Use this keybox** switches the module over to the keybox you pick;
   - **Export** packs every keybox into one zip, either to a location you choose
     or straight into the system share sheet.

## Requirements

- Android 8.0 (API 26) or newer.
- **Root**, for saving and for the *Saved* section: the keyboxes live in
  `/data/adb/teesim`, the folder the TEESimulator module owns and only root
  can read or write. Scanning and checking need no root, and neither does
  reading arbitrary absolute paths, which is optional and uses
  `MANAGE_EXTERNAL_STORAGE`; the default is the Storage Access Framework.
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
- Nothing about your keyboxes leaves the device: they are written into the
  module's folder on your own device and nowhere else. No report file is
  written beside them any more.
- This project is not affiliated with or endorsed by Google. Use it on keyboxes
  you own or are authorised to inspect; a keybox is a secret that identifies a
  device's attestation identity.

## License

GPL-3.0, inherited from the upstream UI kit template. See `LICENSE`.
