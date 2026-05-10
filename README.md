# Joern Vulnerability Hunting Cheatsheet

This repository collects Joern queries for bug hunting and source code review. The goal is to start with simple patterns, define clear sources and sinks, and then reduce false positives with data-flow, control-flow, and context filters.

 GitHub Pages
 https://p4b3l1t0.github.io/joern-cheatsheet/

Joern represents code as a Code Property Graph (CPG). A practical hunting workflow is:

1. Find dangerous calls or suspicious patterns.
2. Define attacker-controlled sources and sensitive sinks.
3. Use `reachableBy` to check if data can flow from a source to a sink.
4. Use `reachableByFlows(...).p` to print the full path and review it manually.
5. Reduce noise with filters such as `where`, `whereNot`, `controlledBy`, `notControlledBy`, `argumentIndex`, `method`, `callIn`, `caller`, and `callee`.

## Vulnerability Guides

- [Command Injection](docs/command-injection.md)
- [Buffer Overflow and Memory Corruption](docs/buffer-overflow-memory-corruption.md)
- [Use After Free and Double Free](docs/use-after-free.md)
- [Input Validation and Return Values](docs/input-validation.md)
- [Memory Leaks](docs/memory-leaks.md)
- [Directory Traversal, Filesystem, and Race Conditions](docs/filesystem-path-traversal.md)
- [TLS, Certificates, and Insecure Network Traffic](docs/tls-network.md)
- [SQL Injection and XSS](docs/web-injection.md)
- [Web Application Vulnerabilities](docs/web-app-vulnerabilities.md)
- [Integer Overflow, Truncation, and Allocation Bugs](docs/integer-overflow.md)

## Platform-Specific Guides

- [Mobile Applications: Android, iOS, Cordova, and Flutter](docs/mobile-applications.md)
- [Electron Applications](docs/electron-applications.md)

## Language and Platform Coverage

Joern works best when the target language has an official frontend. According to the official Joern documentation, strong or available coverage exists for C/C++, Java, JavaScript, JVM bytecode, Kotlin, Swift, PHP, Python, Go, Ruby, and C#.

Short disclaimer: these rules are Joern CPGQL hunting patterns for supported languages. Dart/Flutter app logic and Objective-C-specific semantics need extra tooling, although native wrappers and supported language components can still be reviewed.

For mobile and desktop apps, this means:

- Android Java/Kotlin code can be analyzed with Joern.
- Android APKs may require bytecode conversion or JVM bytecode analysis before importing.
- iOS Swift code can be analyzed with Joern.
- Cordova JavaScript code can be analyzed with Joern, while `config.xml` should be reviewed with XML tooling.
- Electron main/preload/renderer JavaScript can be analyzed with Joern.
- Flutter Dart code is not covered by an official Joern frontend, but the Android and iOS native wrapper code can still be reviewed.
- Objective-C is not listed as an official Joern frontend. C/C++ portions may be partially useful, but Objective-C-specific semantics should be reviewed with other tooling.

## Base Snippets

### Common Sources

```scala
def cliArgs = cpg.method.name("main").parameter.name("argv")

def cInputs = cpg.call
  .name("(?i)(getenv|gets|fgets|scanf|sscanf|read|recv|recvfrom)")
  .argument

def javaHttpInput = cpg.call
  .methodFullName(".*HttpServletRequest\\.(getParameter|getHeader|getCookies|getQueryString).*")
```

### Sinks and Data-flow

```scala
def source = cliArgs ++ cInputs
def sink = cpg.call.name("(?i)(system|popen|exec.*)").argument

sink.reachableBy(source).l
sink.reachableByFlows(source).p
```

### Quick Inspection

```scala
cpg.call.name("(?i)(strcpy|strcat|sprintf|gets|scanf)").code.l

cpg.method
  .filter(_.numberOfLines >= 500)
  .map(m => (m.name, m.filename, m.lineNumber))
  .l

cpg.call.name(".*")
  .map(c => (c.name, c.method.name, c.lineNumber, c.code))
  .take(20)
  .l
```

## Usage Notes

- `reachableBy` returns the sources that can reach a sink. `reachableByFlows` prints the paths and is usually better for explaining a finding.
- `callIn` is useful when you start from a method definition and want to list its call sites.
- `whereNot(_.argument(...).isLiteral)` helps prioritize dynamic data over hardcoded constants.
- To reduce noise, filter by file, method, or attack surface when possible: endpoints, parsers, handlers, CLI commands, network input, or exposed code.
- These queries are heuristics. A match is not a confirmed vulnerability until you review sanitization, bounds checks, memory ownership, and runtime context.

## References

- [Joern Documentation](https://docs.joern.io/)
- [Data-Flow Steps](https://docs.joern.io/cpgql/data-flow-steps/)
- [CPGQL Reference Card](https://docs.joern.io/cpgql/reference-card/)
- [Joern Query Database](http://queries.joern.io/)
- [Interprocedural Data-flow in Joern](https://joern.io/blog/interproc-dataflow-2024/)
- [AppThreat joern-lib](https://github.com/AppThreat/joern-lib)
