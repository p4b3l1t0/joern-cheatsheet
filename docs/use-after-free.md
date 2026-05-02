# Use After Free and Double Free

The goal is to find values that are freed and later reused, returned, or freed again. These queries produce candidates; always review ownership and real execution paths before reporting.

## Calls a `free`

```scala
cpg.call
  .name("(?i)(free|.*_free|delete|kfree)")
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Reuse After `free`

Based on the `free-follows-value-reuse` pattern from the Joern Query Database.

```scala
cpg.method
  .name("(?i)(.*_)?free")
  .filter(_.parameter.size == 1)
  .callIn
  .where(_.argument(1).isIdentifier)
  .flatMap { f =>
    val freedIdentifier = f.argument(1).code
    val postDom = f.postDominatedBy.toSetImmutable

    val reassigned = postDom.isIdentifier
      .where(_.inAssignment)
      .codeExact(freedIdentifier)
      .flatMap(id => id ++ id.postDominatedBy)

    postDom
      .removedAll(reassigned)
      .isIdentifier
      .codeExact(freedIdentifier)
  }
  .l
```

## Simple Double Free by Identifier

```scala
cpg.call.name("(?i)(free|.*_free|kfree)").where(_.argument(1).isIdentifier).filter { f =>
  val freed = f.argument(1).code
  f.method.ast.isCall
    .name("(?i)(free|.*_free|kfree)")
    .filter(_ != f)
    .argument(1)
    .codeExact(freed)
    .nonEmpty
}.l
```

## Struct Field Freed Without Clear Reassignment

```scala
val freeOfStructField = cpg.call
  .name("(?i)(free|.*_free|kfree)")
  .where(
    _.argument(1)
      .isCallTo("<operator>.*[fF]ieldAccess.*")
      .filter(x => x.method.parameter.name.toSet.contains(x.argument(1).code))
  )
  .whereNot(_.argument(1).isCall.argument(1).filter { struct =>
    struct.method.ast.isCall
      .name("(?i)(.*free$|memset|bzero)")
      .argument(1)
      .codeExact(struct.code)
      .nonEmpty
  })
  .l

freeOfStructField.argument(1).filter { arg =>
  arg.method.methodReturn.reachableBy(arg).nonEmpty
}.l
```

## Values Returned After Free

```scala
def frees = cpg.call.name("(?i)(free|.*_free|kfree)").argument(1).isIdentifier
def returns = cpg.method.methodReturn

returns.reachableByFlows(frees).p
```

## What to Check Manually

- Whether the pointer is reassigned to `NULL` on every path.
- Whether the object remains reachable by callers or global structures.
- Whether there are aliases to the same pointer.
- Whether the second `free` only happens under mutually exclusive conditions.
