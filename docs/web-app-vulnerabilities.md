# Web Application Vulnerabilities

These rules are starter Joern CPGQL patterns for common web application bugs. They are designed for Joern-compatible codebases such as Java, JavaScript, JVM bytecode, Kotlin, Swift, PHP, Python, Go, Ruby, C#, and native helper code. Treat every match as a lead: confirm the framework behavior, sanitization, authorization, and runtime configuration before reporting.

## NoSQL Injection

Find request-controlled values reaching document database query APIs.

```scala
def source = cpg.call.name("(?i)(body|query|param|params|getParameter|JSON.parse)").argument
def sink = cpg.call.name("(?i)(find|findOne|findById|aggregate|updateOne|updateMany|deleteOne|where)").argument

sink.reachableByFlows(source).p
```

Check whether users can control object keys or operators such as `$ne`, `$gt`, `$regex`, or `$where`.

## Server-Side Request Forgery

Trace attacker-controlled URLs into server-side HTTP clients.

```scala
def source = cpg.call.name("(?i)(getParameter|param|query|body|getHeader)").argument
def sink = cpg.call.name("(?i)(fetch|axios|get|post|request|openConnection|HttpClient|OkHttpClient|URL)").argument

sink.reachableByFlows(source).p
```

Check allowlists after parsing, redirects, DNS resolution, private IP ranges, and cloud metadata endpoints.

## Open Redirect

Find request-controlled redirect targets.

```scala
def source = cpg.call.name("(?i)(getParameter|param|query|body)").argument
def sink = cpg.call.name("(?i)(redirect|sendRedirect|setHeader|location|redirectTo)").argument

sink.reachableByFlows(source).p
```

Check protocol-relative URLs, CRLF injection into `Location`, OAuth callback flows, and strict host allowlists.

## CSRF and State-Changing Routes

Find handlers that modify server-side state.

```scala
cpg.call
  .code("(?i).*(post|put|patch|delete|router\\.|app\\.).*")
  .where(_.method.ast.isCall.name("(?i)(save|update|delete|insert|create|write|transfer|changePassword)"))
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

Check CSRF tokens, SameSite cookies, Origin/Referer validation, and whether cookie-authenticated users can trigger the action cross-site.

## CORS Misconfiguration

Find permissive CORS code and reflected origins.

```scala
cpg.call
  .code("(?i).*(Access-Control-Allow-Origin|cors\\(|allowedOrigins|allowCredentials|Access-Control-Allow-Credentials).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

Check wildcard origins, reflected `Origin`, credentialed requests, and sensitive API routes sharing broad CORS policies.

## File Upload Issues

Trace uploaded file metadata and content into filesystem writes or parsers.

```scala
def source = cpg.call.name("(?i)(file|files|multipart|filename|originalname|buffer|stream)").argument
def sink = cpg.call.name("(?i)(writeFile|writeFileSync|createWriteStream|move|mv|copyFile|unzip|extract)").argument

sink.reachableByFlows(source).p
```

Check server-generated filenames, extension allowlists, content inspection, archive extraction, and whether uploaded files can be served or executed.

## Server-Side Template Injection

Find request-controlled input reaching template rendering or compilation.

```scala
def source = cpg.call.name("(?i)(getParameter|param|query|body|getHeader)").argument
def sink = cpg.call.name("(?i)(render|renderString|compile|template|parse|processTemplate)").argument

sink.reachableByFlows(source).p
```

Check whether the user controls the template source or path, not just template variables.

## IDOR and Broken Access Control

Trace user-controlled IDs into object lookup, update, delete, download, or export APIs.

```scala
def source = cpg.call.name("(?i)(param|params|getParameter|query|body)").argument.code("(?i).*(id|user|account|org|tenant).*")
def sink = cpg.call.name("(?i)(findById|findOne|getById|update|delete|download|export)").argument

sink.reachableByFlows(source).p
```

Check whether objects are scoped to the authenticated user, organization, or tenant before use.

## JWT and Session Issues

Search for token verification, signing, decoding, and cookie handling.

```scala
cpg.call
  .code("(?i).*(jwt|jsonwebtoken|sign\\(|verify\\(|decode\\(|setCookie|cookie|SameSite|httpOnly|secure).*")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

Check whether tokens are verified instead of only decoded, secrets are not hardcoded, and cookies use `HttpOnly`, `Secure`, and `SameSite` where appropriate.

## Unsafe Deserialization

Find structured user input reaching object deserializers and parsers.

```scala
def source = cpg.call.name("(?i)(body|read|readFile|upload|message|getInputStream)").argument
def sink = cpg.call.name("(?i)(deserialize|readObject|ObjectInputStream|pickle|load|loadAll|fromXML|readValue|parse)").argument

sink.reachableByFlows(source).p
```

Check type restrictions, XML external entities, unsafe YAML loaders, gadget exposure, and file/message queue ingestion paths.
