# Input Validation and Return Values

These queries help find external input used without enough validation and critical function return values that are not checked.

## Common Sources in C/C++

```scala
def source = cpg.method.name("main").parameter.name("argv") ++
  cpg.call.name("(?i)(getenv|gets|fgets|scanf|sscanf|read|recv|recvfrom)").argument
```

## Input Reaching Sensitive Sinks

```scala
def source = cpg.method.name("main").parameter.name("argv") ++
  cpg.call.name("(?i)(getenv|gets|fgets|scanf|sscanf|read|recv|recvfrom)").argument

def sink = cpg.call
  .name("(?i)(system|popen|exec.*|strcpy|strcat|sprintf|memcpy|fopen|open)")
  .argument

sink.reachableByFlows(source).p
```

## Flow Not Protected by a Condition

`notControlledBy` is useful for prioritizing flows that do not appear to be guarded by a nearby check. Adjust the operator pattern for your target.

```scala
def source = cpg.call.name("(?i)(read|recv|fgets|scanf)").argument
def sink = cpg.call.name("(?i)(memcpy|strncpy|open|fopen|system)").argument

sink
  .reachableByFlows(source)
  .notControlledBy(".*(<|>|<=|>=|==|!=).*")
  .p
```

## Unchecked Return Values

Based on `unchecked-read-recv-malloc` from the Joern Query Database.

```scala
implicit val noResolve: NoResolve.type = NoResolve

cpg.call
  .name("(?i)(read|recv|malloc|calloc|realloc|fopen|open)")
  .returnValueNotChecked
  .l
```

## Methods That Take Parameters and Call Sinks

```scala
cpg.method
  .where(_.parameter)
  .where(_.ast.isCall.name("(?i)(system|popen|exec.*|strcpy|memcpy|fopen|open)"))
  .map(m => (m.fullName, m.filename, m.lineNumber))
  .l
```

## Tag Attack Surface Methods

```scala
cpg.method
  .name("(?i).*(parse|decode|handle|request|route|controller|endpoint).*")
  .newTagNode("attack-surface")
  .store
```

## What to Check Manually

- Whether there is an allowlist, normalization, or bounds check before the sink.
- Whether validation is applied to the same value that reaches the sink.
- Whether a return value is used indirectly after an assignment.
- Whether the error path cleans resources or stops execution.
