# Command Injection

Busca datos controlables por atacante llegando a funciones que ejecutan comandos. Empieza con llamadas directas y luego confirma flujo de datos hacia argumentos sensibles.

## Llamadas peligrosas

```scala
cpg.call
  .name("(?i)(system|popen|execl|execlp|execle|execv|execvp|execve|posix_spawn|posix_spawnp)")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Flujo desde entrada a ejecucion

```scala
def source = cpg.method.name("main").parameter.name("argv") ++
  cpg.call.name("(?i)(getenv|gets|fgets|scanf|sscanf|read|recv|recvfrom)").argument

def sink = cpg.call
  .name("(?i)(system|popen|execl|execlp|execle|execv|execvp|execve|posix_spawn|posix_spawnp)")
  .argument

sink.reachableByFlows(source).p
```

## Priorizacion

### Comando no constante

```scala
cpg.call
  .name("(?i)(system|popen)")
  .whereNot(_.argument(1).isLiteral)
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

### Construccion de comando con concatenacion/formato

```scala
def builders = cpg.call.name("(?i)(strcat|strncat|sprintf|snprintf|asprintf)")
def execArgs = cpg.call.name("(?i)(system|popen|exec.*)").argument

execArgs.reachableByFlows(builders).p
```

### Exec con path dinamico

```scala
cpg.call
  .name("(?i)(execl|execlp|execle|execv|execvp|execve)")
  .whereNot(_.argument(1).isLiteral)
  .l
```

## Tags utiles

```scala
cpg.call
  .name("(?i)(system|popen|exec.*)")
  .newTagNode("command-execution")
  .store
```

## Que validar manualmente

- Si el argumento del comando incorpora datos externos.
- Si hay allowlist estricta antes del sink.
- Si el comando usa shell (`system`, `popen`) o ejecucion directa (`execve`).
- Si variables de entorno, PATH o working directory pueden ser controladas.
