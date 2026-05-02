# Mobile Applications: Android, iOS, Cordova, and Flutter

This guide explains how to use Joern for mobile application review. Joern can help a lot with source code and bytecode, but it does not fully replace mobile-specific tooling. Use these queries to find code patterns, then review platform configuration files manually.

## What Joern Can Cover

- Android Java source with the Java frontend.
- Android Kotlin source with the Kotlin frontend.
- Android JVM bytecode with the JVM bytecode frontend. APKs may need conversion or extraction first.
- Cordova JavaScript with the JavaScript frontend.
- iOS Swift source with the Swift frontend.
- Native C/C++ code used by mobile apps with the C/C++ frontend.

## What Needs Extra Review

- Dart and Flutter app logic are not covered by an official Joern frontend.
- Objective-C is not listed as an official Joern frontend. C-like code may be partially visible, but Objective-C-specific calls need other tooling.
- Android `AndroidManifest.xml`, iOS `Info.plist`, Cordova `config.xml`, entitlements, and signing settings should be reviewed with XML/plist tooling.

## Android: WebView Risky Settings

Look for WebView settings that make file access, JavaScript, or cross-origin file access more dangerous.

```scala
cpg.call
  .name("(?i)(setJavaScriptEnabled|setAllowFileAccess|setAllowContentAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs)")
  .where(_.argument.code("true"))
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Android: JavaScript Bridge Exposure

`addJavascriptInterface` can expose native methods to JavaScript loaded inside a WebView. This is especially dangerous with untrusted content.

```scala
cpg.call
  .name("addJavascriptInterface")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Android: External Input to WebView Loading

Trace intent or URL input into WebView loading methods.

```scala
def source = cpg.call.name("(?i)(getStringExtra|getData|getDataString|getExtras|getQueryParameter)").argument
def sink = cpg.call.name("(?i)(loadUrl|loadData|loadDataWithBaseURL)").argument

sink.reachableByFlows(source).p
```

## Android: Insecure Local Storage

Find storage APIs that may hold secrets or sensitive user data.

```scala
cpg.call
  .name("(?i)(getSharedPreferences|openFileOutput|getExternalFilesDir|getExternalStorageDirectory)")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

Also search for world-readable or world-writable modes in older Android code.

```scala
cpg.call
  .code("(?i).*(MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE).*")
  .l
```

## Android: Logs With Sensitive Data

```scala
cpg.call
  .methodFullName("(?i).*android\\.util\\.Log\\.(d|e|i|v|w|wtf).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Android: Weak Crypto

```scala
cpg.call
  .name("getInstance")
  .where(_.argument.isLiteral.code("(?i).*(MD5|SHA1|DES|RC4|AES/ECB|ECB/PKCS5Padding).*"))
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Android: Manifest Items to Review Outside Joern

Review `AndroidManifest.xml` with XML tooling for:

- `android:exported="true"` on activities, services, receivers, and providers.
- Missing or weak permissions on exported components.
- `android:debuggable="true"`.
- `android:allowBackup="true"` when sensitive local data exists.
- `android:usesCleartextTraffic="true"`.
- Custom schemes and deep links with broad intent filters.

## iOS Swift: Hardcoded HTTP URLs

```scala
cpg.literal
  .code("(?i).*http://.*")
  .map(l => (l.method.fullName, l.lineNumber, l.code))
  .l
```

## iOS Swift: Web Content Loading

Review dynamic input reaching WebView or HTML-loading APIs.

```scala
def source = cpg.call.name("(?i)(URL|URLComponents|queryItems|absoluteString)").argument
def sink = cpg.call.name("(?i)(load|loadHTMLString|evaluateJavaScript)").argument

sink.reachableByFlows(source).p
```

## iOS Swift: Weak TLS Handling

Look for certificate challenge handlers that create credentials without strong validation.

```scala
cpg.call
  .name("(?i)(didReceive|useCredential|serverTrust|credential)")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## iOS Swift: Sensitive Storage Candidates

```scala
cpg.call
  .code("(?i).*(UserDefaults|NSUbiquitousKeyValueStore|UIPasteboard|FileManager).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

Prefer Keychain for secrets. When Keychain APIs are used, review access control flags.

```scala
cpg.call
  .name("(?i)(SecItemAdd|SecItemUpdate|SecItemCopyMatching)")
  .l
```

## iOS Files to Review Outside Joern

Review `Info.plist`, entitlements, and project settings for:

- `NSAppTransportSecurity` exceptions.
- `NSAllowsArbitraryLoads`.
- URL schemes and universal links.
- Keychain access groups.
- Debug flags or test endpoints.
- Sensitive permissions and privacy descriptions.

## Cordova: JavaScript Sinks

Cordova apps often expose native capabilities to JavaScript. Start with dangerous JavaScript sinks.

```scala
cpg.call
  .name("(?i)(eval|Function|setTimeout|setInterval|document.write)")
  .whereNot(_.argument.isLiteral)
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Cordova: DOM XSS Candidates

```scala
cpg.call
  .code("(?i).*(innerHTML|outerHTML|insertAdjacentHTML|\\.html\\().*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Cordova: Native Bridge Calls

```scala
cpg.call
  .code("(?i).*cordova\\.exec.*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Cordova: InAppBrowser and External URLs

```scala
def source = cpg.call.name("(?i)(getParameterByName|URLSearchParams|getItem)").argument
def sink = cpg.call.code("(?i).*(cordova\\.InAppBrowser\\.open|window\\.open).*").argument

sink.reachableByFlows(source).p
```

## Cordova Config Items to Review Outside Joern

Review `config.xml` and plugin configuration for:

- `<access origin="*">`.
- Broad `<allow-navigation>` or `<allow-intent>` rules.
- Dangerous plugins such as file, camera, geolocation, contacts, media, and custom native bridges.
- Remote content loaded inside the app WebView.
- Weak Content Security Policy.

## Flutter: What Joern Can and Cannot Do

Joern does not have an official Dart frontend, so it is not the right tool for analyzing most Flutter business logic. Still, Flutter projects usually include native wrapper code that Joern can help review:

- `android/app/src/...` Java or Kotlin.
- `ios/Runner/...` Swift.
- Native plugins written in Java, Kotlin, Swift, C, or C++.

## Flutter: Native Bridge Review

For Android Flutter plugins, look for `MethodChannel` handlers and data flowing into sensitive APIs.

```scala
cpg.call
  .code("(?i).*(MethodChannel|setMethodCallHandler|invokeMethod).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

For iOS Flutter plugins, look for method call handlers.

```scala
cpg.call
  .code("(?i).*(FlutterMethodChannel|setMethodCallHandler|FlutterMethodCall).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## What to Check Manually

- Whether attacker-controlled data reaches native bridge calls.
- Whether WebView content is local, trusted, or remote.
- Whether exported Android components are protected by permissions.
- Whether iOS ATS exceptions are limited and justified.
- Whether secrets are stored in platform-safe storage.
- Whether logs include tokens, passwords, session IDs, or PII.
