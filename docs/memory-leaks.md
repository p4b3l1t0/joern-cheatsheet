# Memory Leaks

Joern no reemplaza un analisis completo de ownership, pero permite encontrar allocations sospechosas, paths sin liberacion y funciones grandes donde el cleanup es dificil de revisar.

## Allocations

```scala
cpg.call
  .name("(?i)(malloc|calloc|realloc|strdup|strndup|new)")
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## Allocation que alcanza return

```scala
def allocations = cpg.call.name("(?i)(malloc|calloc|realloc|strdup|strndup)").l

cpg.method.methodReturn
  .reachableByFlows(allocations)
  .p
```

## Allocation en metodo sin `free`

```scala
cpg.method
  .where(_.ast.isCall.name("(?i)(malloc|calloc|realloc|strdup|strndup)"))
  .whereNot(_.ast.isCall.name("(?i)(free|.*_free)"))
  .map(m => (m.fullName, m.filename, m.lineNumber))
  .l
```

## Allocation asignada a local que no se libera en el mismo metodo

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

## Metodos grandes para revisar cleanup

```scala
cpg.method
  .filter(_.numberOfLines >= 300)
  .map(m => (m.name, m.numberOfLines, m.filename))
  .l
```

## Que validar manualmente

- Si la memoria se transfiere al caller o a una estructura owner.
- Si hay cleanup en labels `goto`, `defer`, destructores o helpers externos.
- Si `realloc` pierde el puntero original en fallo.
- Si existen paths de error que retornan antes del cleanup.
