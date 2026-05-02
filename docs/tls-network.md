# TLS, Certificates, and Insecure Network Traffic

These queries cover disabled or ineffective certificate validation, insecure protocols, and weak cryptographic APIs.

## OpenSSL Without Verification

```scala
cpg.call
  .name("(?i)SSL_set_verify")
  .where(_.argument(2).code(".*SSL_VERIFY_NONE.*|0"))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Verification Callback That Always Accepts

```scala
cpg.method
  .name("(?i).*(verify|check.*trusted).*")
  .where(_.methodReturn)
  .where(_.ast.isReturn.code(".*(true|1).*"))
  .whereNot(_.ast.isReturn.code(".*(false|0).*"))
  .map(m => (m.fullName, m.filename, m.lineNumber))
  .l
```

## Permissive Java `HostnameVerifier` / `TrustManager`

Pattern inspired by `ineffective-certificate-check` from the Joern Query Database.

```scala
val validators = Map(
  "verify" -> "boolean(java.lang.String,javax.net.ssl.SSLSession)",
  "checkClientTrusted" -> "void(java.security.cert.X509Certificate[],java.lang.String,java.net.Socket)",
  "checkServerTrusted" -> "void(java.security.cert.X509Certificate[],java.lang.String,java.net.Socket)"
)

cpg.method
  .nameExact(validators.keys.toSeq: _*)
  .signatureExact(validators.values.toSeq: _*)
  .where(_.ast.isReturn.code(".*(true|1).*"))
  .l
```

## Hardcoded HTTP Protocol

```scala
cpg.call
  .where(_.argument.isLiteral.code("(?i).*http://.*"))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Java/Kotlin `URL("http://...")`

```scala
cpg.call
  .methodFullNameExact("java.net.URL.<init>:void(java.lang.String)")
  .where(_.argument.isLiteral.code("^[^h]*http:.*"))
  .l
```

## Weak Algorithms

```scala
cpg.call
  .where(_.argument.isLiteral.code("(?i).*(MD5|SHA1|DES|RC4|SSLv3|TLSv1\\.0).*"))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## What to Check Manually

- Whether verification is disabled only in tests or debug builds.
- Whether real pinning or external verification exists.
- Whether HTTP is used for non-sensitive resources or can affect integrity.
- Whether the weak algorithm protects real security data or only non-security fingerprints.
