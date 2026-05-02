# Integer Overflow, Truncation, and Allocation Bugs

Integer bugs often appear when a size is calculated with arithmetic, truncated to a smaller type, or used with different formulas for allocation and copying.

## Allocation With Arithmetic

```scala
cpg.call
  .name("(?i)(malloc|calloc|realloc|alloca)")
  .where(_.argument.arithmetic)
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Multiplication in Allocation

```scala
cpg.call
  .name("(?i)(malloc|calloc|realloc)")
  .where(_.argument(1).isCallTo(Operators.multiplication))
  .l
```

## Calculated `malloc` and Different Copy Size

```scala
val allocations = cpg.call
  .name("(?i)(malloc|calloc|realloc)")
  .where(_.argument(1).arithmetic)
  .l

cpg.call.name("(?i)(memcpy|memmove)").l.filter { copyCall =>
  copyCall
    .argument(1)
    .reachableBy(allocations)
    .where(_.inAssignment.target.codeExact(copyCall.argument(1).code))
    .whereNot(_.argument(1).codeExact(copyCall.argument(3).code))
    .hasNext
}
```

## `strlen` Truncated to `int`

Based on `strlen-truncation` from the Joern Query Database.

```scala
cpg.call
  .name("(?i)strlen")
  .inAssignment
  .target
  .evalType("(g?)int")
  .l
```

## Signed Integer Shift

```scala
cpg.call
  .nameExact(Operators.shiftLeft)
  .where(_.argument(1).evalType(".*(int|long|short|char).*"))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Comparisons After Cast

```scala
cpg.call
  .name(".*<operator>\\.cast.*")
  .where(_.argument.evalType(".*(short|int|char).*"))
  .where(_.inCall.name(".*<operator>\\.(lessThan|greaterThan|equals).*"))
  .l
```

## What to Check Manually

- Whether arithmetic can wrap before allocation.
- Whether `calloc(n, size)` checks overflow for `n * size` on the target platform.
- Whether the destination type keeps the full range (`size_t` vs `int`).
- Whether the copy size uses the same expression as the allocation.
