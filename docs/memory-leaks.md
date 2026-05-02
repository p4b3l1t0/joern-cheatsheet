# Memory Leaks

Joern does not replace a full ownership analysis, but it can help find suspicious allocations, paths without cleanup, and large functions where cleanup is hard to review.

## Allocations

```scala
cpg.call
  .name("(?i)(malloc|calloc|realloc|strdup|strndup|new)")
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Allocation That Reaches a Return

```scala
def allocations = cpg.call.name("(?i)(malloc|calloc|realloc|strdup|strndup)").l

cpg.method.methodReturn
  .reachableByFlows(allocations)
  .p
```

## Allocation in a Method Without `free`

```scala
cpg.method
  .where(_.ast.isCall.name("(?i)(malloc|calloc|realloc|strdup|strndup)"))
  .whereNot(_.ast.isCall.name("(?i)(free|.*_free)"))
  .map(m => (m.fullName, m.filename, m.lineNumber))
  .l
```

## Allocation Assigned to a Local Variable and Not Freed in the Same Method

```scala
cpg.call
  .name("(?i)(malloc|calloc|realloc|strdup|strndup)")
  .inAssignment
  .target
  .isIdentifier
  .filter { id =>
    id.method.ast.isCall
      .name("(?i)(free|.*_free)")
      .argument(1)
      .codeExact(id.code)
      .isEmpty
  }
  .l
```

## Large Methods to Review Cleanup

```scala
cpg.method
  .filter(_.numberOfLines >= 300)
  .map(m => (m.name, m.numberOfLines, m.filename))
  .l
```

## What to Check Manually

- Whether memory ownership is transferred to the caller or to an owning structure.
- Whether cleanup happens in `goto` labels, `defer`, destructors, or external helpers.
- Whether `realloc` can lose the original pointer on failure.
- Whether error paths return before cleanup.
