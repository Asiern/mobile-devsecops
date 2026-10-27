# Vulnerable — MASTG demo catalog (iOS)

> ⚠️ **Educational use only.** This app intentionally implements the insecure
> patterns from the [OWASP MASTG](https://mas.owasp.org/MASTG/) demos so they
> can be practised against with static (radare2 / rabin2) and dynamic (Frida)
> tooling. **Do not ship any of this code.**

Launch the app and browse the catalog (`ContentView.swift`). Each row is one
MASTG-DEMO; tapping it runs or shows the vulnerable pattern. Each implementation
is tagged in-source with its `MASTG-DEMO-xxxx` / `MASTG-TEST-xxxx` ids.

## Where each demo lives

| Demo | Title | File |
|------|-------|------|
| 0011 | Insufficient RSA key size (`SecKeyCreateRandomKey`, 512-bit) | `CryptoDemos.swift` |
| 0013 | Hardcoded RSA private key (`SecKeyCreateWithData`) | `CryptoDemos.swift` |
| 0014 | Hardcoded ECDSA private key (CryptoKit) | `CryptoDemos.swift` |
| 0015 | Broken hashing — CommonCrypto (MD5/SHA1) | `CryptoDemos.swift` |
| 0016 | Broken hashing — CryptoKit (`Insecure.MD5/SHA1`) | `CryptoDemos.swift` |
| 0018 | Broken encryption algorithm — DES | `CryptoDemos.swift` |
| 0080 | Broken encryption mode — AES-ECB | `CryptoDemos.swift` |
| 0117 | Sensitive data through `CCCrypt` (Frida target) | `CryptoDemos.swift` |
| 0024 / 0026 | `LAContext.canEvaluatePolicy` | `KeychainBiometricsDemos.swift` |
| 0041 / 0042 | `LAContext.evaluatePolicy` | `KeychainBiometricsDemos.swift` |
| 0043 / 0044 | `kSecAccessControlUserPresence` | `KeychainBiometricsDemos.swift` |
| 0045 / 0046 | `kSecAccessControlBiometryCurrentSet` | `KeychainBiometricsDemos.swift` |
| 0047 | Keychain not requiring user presence | `KeychainBiometricsDemos.swift` |
| 0065 / 0066 | Logging sensitive data (Logger/NSLog/print) | `LoggingStorageDemos.swift` |
| 0124 / 0125 | Logging implementation details | `LoggingStorageDemos.swift` |
| 0019 | `isExcludedFromBackupKey = false` | `LoggingStorageDemos.swift` |
| 0067 | File eligible for backup (`.noFileProtection`) | `LoggingStorageDemos.swift` |
| 0150 | Storage without integrity check (UserDefaults) | `LoggingStorageDemos.swift` |
| 0073 / 0074 | Insecure random (`arc4random`/`drand48`/LCG) | `LoggingStorageDemos.swift` |
| 0084 | Hardcoded HTTP URLs | `NetworkingDemos.swift` |
| 0085 | Network.framework bypassing ATS (plain TCP) | `NetworkingDemos.swift` |
| 0086 | BSD sockets bypassing ATS | `NetworkingDemos.swift` |
| 0110 | URLSession minimum TLS lowered to 1.0 | `NetworkingDemos.swift` |
| 0111 | Network.framework TLS minimum lowered | `NetworkingDemos.swift` |
| 0154 | URLSessionDelegate accepts any certificate | `NetworkingDemos.swift` |
| 0094 | Deprecated `UIWebView` reference | `WebViewDemos.swift` |
| 0095 | Attacker-controlled WebView URL | `WebViewDemos.swift` |
| 0096 | HTML injection → local file access | `WebViewDemos.swift` |
| 0098 / 0099 | File access in WebView (`loadFileURL`, file-URL prefs) | `WebViewDemos.swift` |
| 0142 | Sensitive data via WKWebView native bridge | `WebViewDemos.swift` |
| 0143 | Secret returned to page JS via `evaluateJavaScript` | `WebViewDemos.swift` |
| 0144 | Password field in WebView DOM, no native overlay | `WebViewDemos.swift` |
| 0145 | DOM inspection without content-world isolation | `WebViewDemos.swift` |
| 0146 | Secret written into WebView DOM | `WebViewDemos.swift` |
| 0134 | Custom URL scheme handler without validation | `PlatformDemos.swift` / `ContentView.swift` |
| 0135 | Custom URL scheme handler with source validation | `PlatformDemos.swift` |
| 0149 | Insecure deserialization of URL scheme payload | `PlatformDemos.swift` |
| 0153 | Universal link handler without validation | `PlatformDemos.swift` / `ContentView.swift` |
| 0126 | Deceptive location purpose string | `PlatformDemos.swift` + `Info.plist` |
| 0021 | Jailbreak detection | `PlatformDemos.swift` |
| 0131 | Virtual device (simulator) detection | `PlatformDemos.swift` |
| 0118 | Detect Frida modules before crypto | `PlatformDemos.swift` |
| 0119 | Detect Frida D-Bus port (27042) | `PlatformDemos.swift` |
| 0076 / 0077 | Keyboard caching not prevented | `TextInputDemos.swift` |
| 0112 / 0113 | Sensitive data not hidden (plain `TextField`) | `TextInputDemos.swift` |

### Configuration-based demos (`Info.plist` / `Vulnerable.entitlements`)

| Demo | Title | Where |
|------|-------|-------|
| 0083 | Insecure ATS (`NSAllowsArbitraryLoads`) | `Info.plist` |
| 0109 | ATS TLS policy exceptions (`NSExceptionDomains`) | `Info.plist` |
| 0148 | Missing certificate pinning (no `NSPinnedDomains`) | `Info.plist` (by omission) |
| 0036 | Debuggable entitlement (`get-task-allow`) | `Vulnerable.entitlements` |
| 0127 | Excessive / unjustified entitlements | `Vulnerable.entitlements` |

## Notes

- **Runtime-only demos** (Frida / frida-trace / idevicesyslog captures, e.g.
  0026, 0042, 0044, 0046, 0067, 0074, 0077, 0099, 0113) share the same code as
  their static counterparts — the vulnerable surface is what the dynamic tool
  attaches to. They are noted alongside the corresponding static demo.
- **Tooling-only demos** from the full MASTG list that have no in-app code
  surface (0052/0053 SwiftPM SBOM scanning) are out of scope for this app,
  which has no package dependencies.
- The deployment target is iOS 27.0. To run on an older simulator, lower
  `IPHONEOS_DEPLOYMENT_TARGET` (the build was validated with an override to 26.0).

## Try the deep-link demos

```sh
xcrun simctl openurl booted "vulnerable://transfer?to=attacker&amount=9999"   # 0134
xcrun simctl openurl booted "vulnerable://load?data=<base64-archive>"         # 0149
```
