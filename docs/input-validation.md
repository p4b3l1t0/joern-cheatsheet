# Input Validation y Return Values

Estas queries ayudan a encontrar entrada externa usada sin validacion suficiente y retornos de funciones criticas que no se comprueban.

## Fuentes comunes en C/C++

```scala
def source = cpg.method.name("main").parameter.name("argv") ++
  cpg.call.name("(?i)(getenv|gets|fgets|scanf|sscanf|read|recv|recvfrom)").argument
```

## Entrada que llega a sinks sensibles

```scala
def source = cpg.method.name("main").parameter.name("argv") ++
  cpg.call.name("(?i)(getenv|gets|fgets|scanf|sscanf|read|recv|recvfrom)").argument

def sink = cpg.call
  .name("(?i)(system|popen|exec.*|strcpy|strcat|sprintf|memcpy|fopen|open)")
  .argument

sink.reachableByFlows(source).p
```

## Flujo no protegido por condicion

`notControlledBy` es util para priorizar flows que no parecen estar bajo un check cercano. Ajusta el operador segun el caso.

```scala
def source = cpg.call.name("(?i)(read|recv|fgets|scanf)").argument
def sink = cpg.call.name("(?i)(memcpy|strncpy|open|fopen|system)").argument

sink
  .reachableByFlows(source)
  .notControlledBy(".*(<|>|<=|>=|==|!=).*")
  .p
```

## Return values no chequeados

Basado en `unchecked-read-recv-malloc` de Joern Query Database.

```scala
implicit val noResolve: NoResolve.type = NoResolve

cpg.call
  .name("(?i)(read|recv|malloc|calloc|realloc|fopen|open)")
  .returnValueNotChecked
  .l
```

## Metodos que reciben parametros y llaman sinks

```scala
cpg.method
  .where(_.parameter)
  .where(_.ast.isCall.name("(?i)(system|popen|exec.*|strcpy|memcpy|fopen|open)"))
  .map(m => (m.fullName, m.filename, m.lineNumber))
  .l
```

## Tag para superficie de ataque

```scala
cpg.method
  .name("(?i).*(parse|decode|handle|request|route|controller|endpoint).*")
  .newTagNode("attack-surface")
  .store
```

## Que validar manualmente

- Si hay allowlist, normalizacion o bounds check antes del sink.
- Si la validacion se aplica al mismo valor que llega al sink.
- Si el return value es usado indirectamente despues de una asignacion.
- Si el error path limpia recursos o corta ejecucion.
