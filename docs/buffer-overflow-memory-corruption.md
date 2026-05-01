# Buffer Overflow y Memory Corruption

Estas queries priorizan copias inseguras, formatos no constantes, buffers con tamanos dinamicos y operaciones de memoria donde el tamano copiado no coincide con el tamano reservado.

## Funciones peligrosas

```scala
cpg.call
  .name("(?i)(gets|strcpy|strncpy|strcat|strncat|sprintf|vsprintf|memcpy|memmove|scanf|sscanf)")
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Copias con destino alcanzable desde allocation

```scala
def allocations = cpg.call.name("(?i)(malloc|calloc|realloc|alloca)").argument(1)

cpg.call
  .name("(?i)(memcpy|memmove|strncpy)")
  .where(_.argument(1).reachableBy(allocations))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## `malloc` con aritmetica y `memcpy` con tamano distinto

Basado en el patron `malloc-memcpy-int-overflow` de Joern Query Database.

```scala
val allocations = cpg.call
  .name("(?i)(malloc|calloc|realloc)")
  .where(_.argument(1).arithmetic)
  .l

cpg.call.name("(?i)memcpy").l.filter { memcpyCall =>
  memcpyCall
    .argument(1)
    .reachableBy(allocations)
    .where(_.inAssignment.target.codeExact(memcpyCall.argument(1).code))
    .whereNot(_.argument(1).codeExact(memcpyCall.argument(3).code))
    .hasNext
}
```

## Format string controlado

```scala
val printfFns = cpg.call
  .name("(?i)printf")
  .whereNot(_.argument(1).isLiteral)

val sprintfFns = cpg.call
  .name("(?i)(sprintf|vsprintf)")
  .whereNot(_.argument(2).isLiteral)

(printfFns ++ sprintfFns).l
```

## `strncpy` sin null termination cercana

```scala
val allocationSizes = cpg.call.name("(?i).*malloc$").argument(1).l

cpg.call.name("(?i)strncpy").map { c =>
  (c.method, c.argument(1), c.argument(3))
}.filter { case (method, dst, size) =>
  dst.reachableBy(allocationSizes).codeExact(size.code).nonEmpty &&
    method.assignment
      .where(_.target.arrayAccess.code(s"${dst.code}.*\\[.*"))
      .source
      .isLiteral
      .code(".*0.*")
      .isEmpty
}.map(_._2).l
```

## Input directo a copy sinks

```scala
def source = cpg.call.name("(?i)(getenv|gets|fgets|scanf|sscanf|read|recv)").argument
def sink = cpg.call.name("(?i)(strcpy|strcat|sprintf|memcpy|memmove)").argument

sink.reachableByFlows(source).p
```

## Que validar manualmente

- Si el tamano copiado esta ligado al tamano real del destino.
- Si hay terminacion nula garantizada.
- Si hay checks de longitud antes de la copia.
- Si el destino vive en stack, heap o estructura compartida.
