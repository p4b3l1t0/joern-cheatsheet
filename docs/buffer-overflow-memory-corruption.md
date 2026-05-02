# Buffer Overflow and Memory Corruption

These queries help find unsafe copies, non-constant format strings, dynamic buffer sizes, and memory operations where the copy size may not match the allocated size.

## Dangerous Functions

```scala
cpg.call
  .name("(?i)(gets|strcpy|strncpy|strcat|strncat|sprintf|vsprintf|memcpy|memmove|scanf|sscanf)")
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Copies Where the Destination Comes From an Allocation

```scala
def allocations = cpg.call.name("(?i)(malloc|calloc|realloc|alloca)").argument(1)

cpg.call
  .name("(?i)(memcpy|memmove|strncpy)")
  .where(_.argument(1).reachableBy(allocations))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## `malloc` With Arithmetic and `memcpy` With a Different Size

Based on the `malloc-memcpy-int-overflow` pattern from the Joern Query Database.

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

## Controlled Format String

```scala
val printfFns = cpg.call
  .name("(?i)printf")
  .whereNot(_.argument(1).isLiteral)

val sprintfFns = cpg.call
  .name("(?i)(sprintf|vsprintf)")
  .whereNot(_.argument(2).isLiteral)

(printfFns ++ sprintfFns).l
```

## `strncpy` Without Nearby Null Termination

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

## Direct Input to Copy Sinks

```scala
def source = cpg.call.name("(?i)(getenv|gets|fgets|scanf|sscanf|read|recv)").argument
def sink = cpg.call.name("(?i)(strcpy|strcat|sprintf|memcpy|memmove)").argument

sink.reachableByFlows(source).p
```

## What to Check Manually

- Whether the copied size is tied to the real destination size.
- Whether null termination is guaranteed.
- Whether length checks happen before the copy.
- Whether the destination lives on the stack, heap, or inside a shared structure.
