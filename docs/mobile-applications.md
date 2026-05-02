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

Prioritize bridges in classes that also load remote or intent-controlled URLs.

```scala
cpg.method
  .where(_.ast.isCall.name("addJavascriptInterface"))
  .where(_.ast.isCall.name("(?i)(loadUrl|loadData|loadDataWithBaseURL)"))
  .map(m => (m.fullName, m.filename, m.lineNumber))
  .l
```

## Android: External Input to WebView Loading

Trace intent or URL input into WebView loading methods.

```scala
def source = cpg.call.name("(?i)(getStringExtra|getData|getDataString|getExtras|getQueryParameter)").argument
def sink = cpg.call.name("(?i)(loadUrl|loadData|loadDataWithBaseURL)").argument

sink.reachableByFlows(source).p
```

## Android: Intent or Deep Link Input to Sensitive APIs

Trace Activity intent data into command, file, WebView, or network sinks.

```scala
def source = cpg.call.name("(?i)(getIntent|getData|getDataString|getStringExtra|getExtras|getQueryParameter)").argument
def sink = cpg.call.name("(?i)(loadUrl|openFileOutput|File|Uri.parse|startActivity|sendBroadcast|exec|Runtime.getRuntime)").argument

sink.reachableByFlows(source).p
```

Check whether the receiving component is exported, whether the deep link host/path are allowlisted, and whether the sink performs authorization.

## Android: Insecure Local Storage

Find storage APIs that may hold secrets or sensitive user data.

```scala
cpg.call
  .name("(?i)(getSharedPreferences|openFileOutput|getExternalFilesDir|getExternalStorageDirectory)")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

Trace sensitive-looking variables into storage APIs.

```scala
def source = cpg.identifier.code("(?i).*(token|secret|password|passwd|jwt|session|apiKey|apikey|credential).*")
def sink = cpg.call.name("(?i)(putString|putBytes|openFileOutput|write|insert|execSQL)").argument

sink.reachableByFlows(source).p
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

Prioritize log calls that include secret-like names or values.

```scala
cpg.call
  .methodFullName("(?i).*android\\.util\\.Log\\.(d|e|i|v|w|wtf).*")
  .where(_.argument.code("(?i).*(token|secret|password|passwd|jwt|session|apiKey|apikey|credential).*"))
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

Find hardcoded keys, IVs, salts, or passwords used near crypto APIs.

```scala
cpg.call
  .name("(?i)(SecretKeySpec|IvParameterSpec|PBEKeySpec|setSeed|getBytes)")
  .where(_.argument.isLiteral)
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Android: Weak TLS and Certificate Pinning Bypass

Search for trust-all certificate managers, permissive hostname verifiers, and disabled SSL verification.

```scala
cpg.call
  .code("(?i).*(X509TrustManager|checkServerTrusted|HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAll|SSL_set_verify|SSL_VERIFY_NONE).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

```scala
cpg.method
  .name("(?i)(checkServerTrusted|verify)")
  .whereNot(_.ast.isCall.name("(?i)(throw|checkValidity|verify|CertificatePinner|pin)"))
  .map(m => (m.fullName, m.filename, m.lineNumber))
  .l
```

## Android: Cleartext Traffic and Hardcoded Endpoints

Find hardcoded HTTP URLs and internal network endpoints in supported source code.

```scala
cpg.literal
  .code("(?i).*http://.*")
  .map(l => (l.method.fullName, l.lineNumber, l.code))
  .l
```

```scala
cpg.literal
  .code("(?i).*(localhost|127\\.0\\.0\\.1|10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|169\\.254\\.169\\.254).*")
  .map(l => (l.method.fullName, l.lineNumber, l.code))
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

Prioritize challenge handlers that call completion with `.useCredential` or create credentials from `serverTrust`.

```scala
cpg.method
  .code("(?s).*(didReceive|serverTrust|URLAuthenticationChallenge).*")
  .where(_.ast.isCall.code("(?i).*(useCredential|URLCredential|serverTrust).*"))
  .map(m => (m.fullName, m.filename, m.lineNumber))
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

## iOS Swift: Weak Crypto and Randomness

```scala
cpg.call
  .code("(?i).*(MD5|SHA1|DES|RC4|ECB|arc4random|random\\(|srand|CC_MD5|CC_SHA1).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## iOS Swift: Pasteboard and Clipboard Exposure

```scala
cpg.call
  .code("(?i).*(UIPasteboard|generalPasteboard|setString|setValue).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
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

Trace URL, local storage, or DOM-controlled input into native bridge calls.

```scala
def source = cpg.call.name("(?i)(URLSearchParams|getItem|querySelector|getElementById|val|text|html)").argument
def sink = cpg.call.code("(?i).*cordova\\.exec.*").argument

sink.reachableByFlows(source).p
```

## Cordova: InAppBrowser and External URLs

```scala
def source = cpg.call.name("(?i)(getParameterByName|URLSearchParams|getItem)").argument
def sink = cpg.call.code("(?i).*(cordova\\.InAppBrowser\\.open|window\\.open).*").argument

sink.reachableByFlows(source).p
```

## Cordova: Insecure Client Storage

```scala
cpg.call
  .code("(?i).*(localStorage|sessionStorage|IndexedDB|openDatabase|sqlitePlugin).*")
  .where(_.argument.code("(?i).*(token|secret|password|jwt|session|apiKey|credential).*"))
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
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

Trace method-call arguments into native Android sinks inside Flutter plugins.

```scala
def source = cpg.call.code("(?i).*call\\.argument.*").argument
def sink = cpg.call.name("(?i)(loadUrl|openFileOutput|startActivity|sendBroadcast|exec|Runtime.getRuntime)").argument

sink.reachableByFlows(source).p
```

For iOS Flutter plugins, look for method call handlers.

```scala
cpg.call
  .code("(?i).*(FlutterMethodChannel|setMethodCallHandler|FlutterMethodCall).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

Trace Flutter call arguments into iOS sinks.

```scala
def source = cpg.call.code("(?i).*(FlutterMethodCall|arguments|argument).*").argument
def sink = cpg.call.name("(?i)(evaluateJavaScript|loadHTMLString|open|write|URL|URLRequest)").argument

sink.reachableByFlows(source).p
```

## What to Check Manually

- Whether attacker-controlled data reaches native bridge calls.
- Whether WebView content is local, trusted, or remote.
- Whether exported Android components are protected by permissions.
- Whether iOS ATS exceptions are limited and justified.
- Whether secrets are stored in platform-safe storage.
- Whether logs include tokens, passwords, session IDs, or PII.
