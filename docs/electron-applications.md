# Electron Applications

Electron apps are usually JavaScript or TypeScript applications with a privileged main process, preload scripts, and renderer code. Joern can analyze JavaScript code with the JavaScript frontend. TypeScript may need to be compiled or converted depending on your workflow.

The main security goal is to find places where untrusted renderer content can reach Node.js, OS commands, files, or unsafe Electron APIs.

## Files to Prioritize

Start with:

- `main.js`, `main.ts`, or files that create `BrowserWindow`.
- `preload.js` or `preload.ts`.
- IPC handlers in the main process.
- Renderer code that sends IPC messages.
- Custom protocol handlers.
- Auto-update code.

## BrowserWindow With Dangerous WebPreferences

These settings are common root causes for Electron vulnerabilities.

```scala
cpg.call
  .code("(?s).*new\\s+BrowserWindow\\s*\\(.*")
  .where(_.code("(?s).*(nodeIntegration\\s*:\\s*true|contextIsolation\\s*:\\s*false|webSecurity\\s*:\\s*false|allowRunningInsecureContent\\s*:\\s*true|enableRemoteModule\\s*:\\s*true).*"))
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Node Integration Enabled

```scala
cpg.call
  .code("(?s).*nodeIntegration\\s*:\\s*true.*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Context Isolation Disabled

```scala
cpg.call
  .code("(?s).*contextIsolation\\s*:\\s*false.*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Web Security Disabled

```scala
cpg.call
  .code("(?s).*webSecurity\\s*:\\s*false.*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Remote Content Loaded Into a Window

```scala
cpg.call
  .name("(?i)(loadURL|loadFile)")
  .where(_.argument.code("(?i).*http://.*|.*https://.*"))
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

If remote content is loaded, review the related `webPreferences` very carefully.

## IPC Handlers

IPC is the bridge between renderer code and privileged main process code. Treat each handler as an attack surface.

```scala
cpg.call
  .code("(?i).*(ipcMain\\.handle|ipcMain\\.on|ipcRenderer\\.invoke|ipcRenderer\\.send).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## IPC Input to Command Execution

```scala
def source = cpg.call.code("(?i).*(ipcMain\\.handle|ipcMain\\.on).*").argument
def sink = cpg.call.name("(?i)(exec|execFile|spawn|fork)").argument

sink.reachableByFlows(source).p
```

## IPC Input to File Access

```scala
def source = cpg.call.code("(?i).*(ipcMain\\.handle|ipcMain\\.on).*").argument
def sink = cpg.call
  .name("(?i)(readFile|readFileSync|writeFile|writeFileSync|appendFile|unlink|rm|mkdir|createReadStream|createWriteStream)")
  .argument

sink.reachableByFlows(source).p
```

## Dangerous Shell and OS APIs

```scala
cpg.call
  .name("(?i)(exec|execFile|spawn|fork|openExternal|showOpenDialog|showSaveDialog)")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## `shell.openExternal` With Dynamic Input

```scala
cpg.call
  .code("(?i).*shell\\.openExternal.*")
  .whereNot(_.argument.isLiteral)
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Preload Exposes Too Much Power

Look for APIs exposed from preload scripts to the renderer.

```scala
cpg.call
  .code("(?i).*(contextBridge\\.exposeInMainWorld|window\\.[a-zA-Z0-9_]+\\s*=).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

Then check whether exposed methods call `fs`, `child_process`, `shell`, `clipboard`, `nativeImage`, `dialog`, or custom native modules.

## Insecure Navigation and Window Open Handling

```scala
cpg.call
  .code("(?i).*(setWindowOpenHandler|will-navigate|new-window|webContents\\.on).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

Review whether navigation is restricted to an allowlist.

## Dangerous Dynamic JavaScript

```scala
cpg.call
  .name("(?i)(eval|Function|setTimeout|setInterval|executeJavaScript)")
  .whereNot(_.argument.isLiteral)
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Weak Update or Download Flows

```scala
cpg.call
  .code("(?i).*(autoUpdater|downloadURL|setFeedURL|downloadFile|createWriteStream).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

Review whether updates and downloads are authenticated, integrity-checked, and restricted to trusted hosts.

## Package and Config Items to Review Outside Joern

Review `package.json`, build configs, and Electron security settings for:

- Outdated Electron versions.
- `nodeIntegration: true`.
- `contextIsolation: false`.
- `sandbox: false`.
- `webSecurity: false`.
- Missing Content Security Policy.
- Remote content loaded with privileged APIs enabled.
- Native modules that expose filesystem, command execution, or credential access.

## What to Check Manually

- Whether renderer-controlled IPC input reaches privileged APIs.
- Whether every IPC channel validates arguments and enforces authorization.
- Whether navigation and new windows are allowlisted.
- Whether preload exposes small, specific APIs instead of raw Node.js access.
- Whether remote content is isolated from Node.js and native capabilities.
- Whether command execution uses fixed commands and safe argument arrays.
