# Use After Free y Double Free

El objetivo es localizar valores liberados que vuelven a usarse, retornarse o liberarse. Estas queries generan candidatos; revisa ownership y paths reales antes de reportar.

## Calls a `free`

```scala
cpg.call
  .name("(?i)(free|.*_free|delete|kfree)")
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Reuso despues de `free`

Basado en el patron `free-follows-value-reuse` de Joern Query Database.

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

## Double free simple por identificador

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

## Campo de estructura liberado sin reasignacion clara

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

## Valores retornados despues de liberar

```scala
def frees = cpg.call.name("(?i)(free|.*_free|kfree)").argument(1).isIdentifier
def returns = cpg.method.methodReturn

returns.reachableByFlows(frees).p
```

## Que validar manualmente

- Si el puntero se reasigna a `NULL` en todos los paths.
- Si el objeto queda accesible a callers o estructuras globales.
- Si hay aliases del mismo puntero.
- Si el segundo `free` ocurre solo bajo condiciones mutuamente excluyentes.
