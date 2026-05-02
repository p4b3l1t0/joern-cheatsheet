# Directory Traversal, Filesystem, and Race Conditions

Look for paths built from external input, repeated operations on the same path, and APIs where an attacker may change the target file between a check and a use.

## Non-constant File Operations

```scala
cpg.call
  .name("(?i)(fopen|open|openat|creat|stat|lstat|access|chmod|chown|unlink|rename|mkdir|rmdir)")
  .whereNot(_.argument(1).isLiteral)
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Path Traversal From External Input

```scala
def source = cpg.call.name("(?i)(getenv|gets|fgets|scanf|read|recv|recvfrom)").argument
def pathSink = cpg.call.name("(?i)(fopen|open|openat|stat|lstat|access|unlink|rename)").argument

pathSink.reachableByFlows(source).p
```

## Paths Built by Concatenation

```scala
def builders = cpg.call.name("(?i)(strcat|strncat|sprintf|snprintf|asprintf)")
def pathSink = cpg.call.name("(?i)(fopen|open|openat|stat|lstat|access|unlink|rename)").argument

pathSink.reachableByFlows(builders).p
```

## Filter for Literal `../` or Suspicious Separators

```scala
cpg.call
  .name("(?i)(fopen|open|openat|stat|lstat|access|unlink|rename)")
  .argument
  .code(".*(\\.\\./|\\.\\.\\\\|/tmp/|\\\\tmp\\\\).*")
  .l
```

## Race Condition From Operations on the Same Path

Adapted from `file-operation-race` in the Joern Query Database.

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

## What to Check Manually

- Whether the path is canonicalized before use.
- Whether there is an allowlist for directories or file names.
- Whether the code uses file descriptors instead of repeating path-based operations.
- Whether the base directory is attacker-controlled or attacker-writable.
