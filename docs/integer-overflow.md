# Enteros, Truncation y Allocation Bugs

Los bugs de enteros suelen aparecer cuando un tamano se calcula con aritmetica, se trunca a un tipo mas pequeno o se usa para reservar/copiar memoria con formulas distintas.

## Allocation con aritmetica

```scala
cpg.call
  .name("(?i)(malloc|calloc|realloc|alloca)")
  .where(_.argument.arithmetic)
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Multiplicacion en allocation

```scala
cpg.call
  .name("(?i)(malloc|calloc|realloc)")
  .where(_.argument(1).isCallTo(Operators.multiplication))
  .l
```

## `malloc` calculado y copy size distinto

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

## `strlen` truncado a `int`

Basado en `strlen-truncation` de Joern Query Database.

```scala
cpg.call
  .name("(?i)strlen")
  .inAssignment
  .target
  .evalType("(g?)int")
  .l
```

## Shift de signed integer

```scala
cpg.call
  .nameExact(Operators.shiftLeft)
  .where(_.argument(1).evalType(".*(int|long|short|char).*"))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Comparaciones despues de cast

```scala
cpg.call
  .name(".*<operator>\\.cast.*")
  .where(_.argument.evalType(".*(short|int|char).*"))
  .where(_.inCall.name(".*<operator>\\.(lessThan|greaterThan|equals).*"))
  .l
```

## Que validar manualmente

- Si la aritmetica puede wrappear antes de reservar.
- Si `calloc(n, size)` valida overflow de `n * size` en la plataforma objetivo.
- Si el tipo destino conserva todo el rango (`size_t` vs `int`).
- Si el copy size usa la misma expresion que la allocation.
