# TLS, Certificados y Trafico Inseguro

Estas queries cubren validacion de certificados deshabilitada o inefectiva, protocolos inseguros y APIs criptograficas debiles.

## OpenSSL sin verificacion

```scala
cpg.call
  .name("(?i)SSL_set_verify")
  .where(_.argument(2).code(".*SSL_VERIFY_NONE.*|0"))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Callback de verificacion que siempre acepta

```scala
cpg.method
  .name("(?i).*(verify|check.*trusted).*")
  .where(_.methodReturn)
  .where(_.ast.isReturn.code(".*(true|1).*"))
  .whereNot(_.ast.isReturn.code(".*(false|0).*"))
  .map(m => (m.fullName, m.filename, m.lineNumber))
  .l
```

## Java `HostnameVerifier` / `TrustManager` permisivo

Patron inspirado en `ineffective-certificate-check` de Joern Query Database.

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

## Protocolo HTTP hardcodeado

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

## Algoritmos debiles

```scala
cpg.call
  .where(_.argument.isLiteral.code("(?i).*(MD5|SHA1|DES|RC4|SSLv3|TLSv1\\.0).*"))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Que validar manualmente

- Si la verificacion esta deshabilitada solo en tests o debug.
- Si hay pinning o verificacion externa real.
- Si HTTP se usa para recursos no sensibles o puede afectar integridad.
- Si el algoritmo debil protege seguridad real o solo fingerprints no criptograficos.
