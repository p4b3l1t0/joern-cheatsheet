# Directory Traversal, Filesystem y Race Conditions

Busca paths construidos con entrada externa, operaciones repetidas sobre el mismo path y uso de APIs donde un atacante podria cambiar el archivo entre checks y uso.

## File operations no constantes

```scala
cpg.call
  .name("(?i)(fopen|open|openat|creat|stat|lstat|access|chmod|chown|unlink|rename|mkdir|rmdir)")
  .whereNot(_.argument(1).isLiteral)
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Path traversal desde entrada externa

```scala
def source = cpg.call.name("(?i)(getenv|gets|fgets|scanf|read|recv|recvfrom)").argument
def pathSink = cpg.call.name("(?i)(fopen|open|openat|stat|lstat|access|unlink|rename)").argument

pathSink.reachableByFlows(source).p
```

## Paths construidos por concatenacion

```scala
def builders = cpg.call.name("(?i)(strcat|strncat|sprintf|snprintf|asprintf)")
def pathSink = cpg.call.name("(?i)(fopen|open|openat|stat|lstat|access|unlink|rename)").argument

pathSink.reachableByFlows(builders).p
```

## Filtro para `../` literal o separadores sospechosos

```scala
cpg.call
  .name("(?i)(fopen|open|openat|stat|lstat|access|unlink|rename)")
  .argument
  .code(".*(\\.\\./|\\.\\.\\\\|/tmp/|\\\\tmp\\\\).*")
  .l
```

## Race condition por operaciones sobre el mismo path

Adaptado de `file-operation-race` de Joern Query Database.

```scala
val operations: Map[String, Seq[Int]] = Map(
  "access" -> Seq(1),
  "chmod" -> Seq(1),
  "chown" -> Seq(1),
  "creat" -> Seq(1),
  "fopen" -> Seq(1),
  "lstat" -> Seq(1),
  "mkdir" -> Seq(1),
  "open" -> Seq(1),
  "rename" -> Seq(1, 2),
  "stat" -> Seq(1),
  "unlink" -> Seq(1)
)

def fileCalls(calls: Traversal[Call]) =
  calls.nameExact(operations.keys.toSeq: _*)

def fileArgs(c: Call) =
  c.argument.whereNot(_.isLiteral).argumentIndex(operations(c.name): _*)

fileCalls(cpg.call).filter { call =>
  val otherCalls = fileCalls(call.method.ast.isCall).filter(_ != call)
  val otherArgs = otherCalls.flatMap(c => fileArgs(c)).code.toSet
  fileArgs(call).code.exists(arg => otherArgs.contains(arg))
}.l
```

## Que validar manualmente

- Si el path se canonicaliza antes del uso.
- Si hay allowlist de directorios o nombres.
- Si se usan file descriptors en lugar de repetir operaciones por path.
- Si el directorio base es controlable o writable por atacante.
