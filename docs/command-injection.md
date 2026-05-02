# Command Injection

Look for attacker-controlled data reaching functions that execute commands. Start with direct dangerous calls, then confirm whether user input flows into sensitive arguments.

## Dangerous Calls

```scala
cpg.call
  .name("(?i)(system|popen|wordexp|execl|execlp|execle|execv|execvp|execve|posix_spawn|posix_spawnp)")
  .map(c => (c.method.fullName, c.lineNumber, c.code))
  .l
```

## Flow From Input to Execution

```scala
def source = cpg.method.name("main").parameter.name("argv") ++
  cpg.call.name("(?i)(getenv|gets|fgets|scanf|sscanf|read|recv|recvfrom)").argument

def sink = cpg.call
  .name("(?i)(system|popen|wordexp|execl|execlp|execle|execv|execvp|execve|posix_spawn|posix_spawnp)")
  .argument

sink.reachableByFlows(source).p
```

## Prioritization

### Non-constant Command

```scala
cpg.call
  .name("(?i)(system|popen)")
  .whereNot(_.argument(1).isLiteral)
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

### Command Built With Concatenation or Formatting

```scala
def builders = cpg.call.name("(?i)(strcat|strncat|sprintf|snprintf|asprintf)")
def execArgs = cpg.call.name("(?i)(system|popen|exec.*)").argument

execArgs.reachableByFlows(builders).p
```

### Exec With Dynamic Path

```scala
cpg.call
  .name("(?i)(execl|execlp|execle|execv|execvp|execve)")
  .whereNot(_.argument(1).isLiteral)
  .l
```

## Useful Tags

```scala
cpg.call
  .name("(?i)(system|popen|exec.*)")
  .newTagNode("command-execution")
  .store
```

## What to Check Manually

- Whether the command argument includes external input.
- Whether there is a strict allowlist before the sink.
- Whether the code uses a shell (`system`, `popen`) or direct execution (`execve`).
- Whether environment variables, `PATH`, or the working directory can be controlled.
