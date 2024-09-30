# Advanced Joern Cheatsheet for C/C++ Vulnerability Detection

This guide extends basic vulnerability detection with Joern by incorporating advanced queries, tagging, and flow analysis for comprehensive C/C++ code analysis.

## Table of Contents
- [Command Injection](#command-injection)
- [Buffer Overflow](#buffer-overflow)
- [Use After Free](#use-after-free)
- [Input Validation](#input-validation)
- [Memory Leaks](#memory-leaks)
- [Improper SSL/TLS Validation](#improper-ssltls-validation)
- [Directory Traversal](#directory-traversal)

## Command Injection

### Detecting `system` Command Execution
Basic Query:
```joern
cpg.call.name("system").argument.l
```

### Advanced Queries:

1. Tagging command execution calls:

```joern
cpg.call.name("system").l.foreach(_.tag("command-execution"))
```

2. Finding paths to command injections:

```joern
val cmdInjections = cpg.call.name("system")
cmdInjections.reachableBy(cpg.identifier).p
```

3. Identifying user input affecting system calls:

```joern
cpg.call.name("system").argument(1).reachableBy(cpg.identifier.name("userInput")).p
```

## Buffer Overflow
### Finding Dangerous Array Access
#### Basic Query:

```joern
cpg.call.name("strcpy").argument.l
```

#### Advanced Queries:

1. Tagging unsafe array access:

```joern
cpg.call.name("strcpy").l.foreach(_.tag("unsafe-array-access"))
```

2. Analyzing flow from user input to strcpy:

```joern
cpg.call.name("strcpy").argument(1).reachableBy(cpg.identifier.name("userInput")).p
```
3. Highlighting methods containing unsafe strcpy usage:

```joern
cpg.call.name("strcpy").method.l.foreach(_.tag("method-with-unsafe-strcpy"))
```

## Use After Free
### Double Free Vulnerabilities
#### Basic Query:

```joern
cpg.identifier.name("userInput").reachableBy(cpg.call).p
```

#### Advanced Queries:

1. Tagging methods accepting unvalidated input:

```joern
cpg.method.where(_.parameter.reachableBy(cpg.identifier)).l.foreach(_.tag("unvalidated-input"))
```
2. Mapping input validation flows:

```joern
cpg.identifier.reachableBy(cpg.call).p
```
3. Detecting direct user input flows into sensitive functions:

```joern
cpg.call.reachableBy(cpg.identifier.name("userInput")).l.foreach(_.tag("direct-user-input-flow"))
```

## Input Validation
### Unvalidated Input Usage
#### Basic Query:

#### Advanced Queries:

```joern
cpg.parameter.reachableBy(cpg.identifier.name(".*input.*|.*Input.*")).l
```

```joern
cpg.call.name(".*read.*|.*get.*Input.*|.*scanf.*").reachableByFlows(cpg.call.name(".*system.*|.*exec.*")).p
```

```joern
cpg.method.where(method => method.parameter.exists(param => param.reachableBy(cpg.identifier.name(".*input.*|.*Input.*")).nonEmpty)).l.foreach(_.tag("unvalidated-input-method"))
```

## Memory Leaks
### Detecting Memory Allocation without Free
#### Basic Query:

```joern
cpg.call.name("malloc").not(_.isFree)
```

#### Advanced Queries:

1. Tagging potential memory leaks:
   
```joern
cpg.call.name("malloc").not(_.isFree).l.foreach(_.tag("potential-memory-leak"))
```

2. Analyzing allocation and free patterns:

```joern
val allocations = cpg.call.name("malloc")
allocations.reachableBy(cpg.call.name("free")).p
```
   
3. Highlighting leak-prone patterns:

```joern
cpg.call.name("malloc").whereNot(_.argument(1).isCallTo(Operators.addition)).l.foreach(_.tag("leak-prone-pattern"))
```

4. Detecting Memory Allocation Patterns

```joern
cpg.call("malloc").where(_.argument(1).isCallTo(Operators.addition)).code.l
```

5. Finding Large Methods

```joern
cpg.method.filter(_.numberOfLines >= 500).name.l
```

## Improper SSL/TLS Validation
### Incorrect SSL/TLS Certificate Validation
#### Basic Query:

```joern
cpg.call.name("SSL_set_verify").argument.l
```
#### Advanced Queries:

1. Identifying improper validation paths:

```joern
cpg.call.name("SSL_set_verify").reachableBy(cpg.identifier).p
```

## Directory Traversal
#### Basic Query:

```joern
cpg.call("fopen.*").argument(1).whereNot(_.isLiteral).reachableByFlows(cpg.call("strcat")).where(_.method.tag.name("attack_surface"))
```

## Extras 

```
cpg.call("sprintf").argument(2).whereNot(_.isLiteral).code.l

cpg.call("sprintf").argument(2).filterNot(_.isLiteral).dump

cpg.call("malloc").where(_.argument(1).isCallTo(Operators.addition)).code.l

cpg.call("malloc").where(_.argument(1).isCallTo(Operators.addition)).code.l

--------------------------------

def source1 = cpg.call("malloc").where(_.argument(1).isCallTo(Operators.addition))

def source2 = cpg.method.name(".*alloc.*").parameter

def sink1 = cpg.call("memcpy").argument

def sink2 = cpg.call("malloc").where(_.argument(1).isCallTo(Operators.multiplication)).argument

synk.reachableByFlows(source).p

synk.reachableByFlows(source).l

--------------------------------

cpg.call("strcpy.*").code.l

cpg.call("strcpy.*").method.name.l

cpg.method.filter(_.numberOfLines >= 500).name.l

cpg.types.name("vlc_log_t").map( x=> (x.name, x.start.member.name.l)).l

cpg.method.name("vlc_log_t").location.map( x=> (x.lineNumber.get, x.filename)).l


--------------------------------


cpg.call.toList(5)

cpg.file("src/to/path").toList

cpg.identifier("Query|Mutation").toList

cpg.identifier("Query|Mutation").file/

cpg.call("Query").filter(call => call.astParent.astParent.astChildren.isCall("Authorized"))

cpg.call("Query").whereNot(_.astParent.astParent.astChildren.astChildren.isCall(".*Authorized.*)).file.l


-------------------------------


 val src = cpg.call("malloc").where(_.argument(1).arithmetics)
  cpg
    .call("memcpy")
    .filter { call =>
      call
        .argument(1)
        .reachableBy(src)
        .not(_.argument(1).codeExact(call.argument(3).code))
        .hasNext

------------------------------


def buffer_overflow(cpg : io.name_codepropertygraph.Cpg) = {
	def src = cpg.call("malloc").where(_.argument(1).isCallTo(Operators.addition)).l
	cpg.call("memcpy").where { casll =>
		call.argument(1)
		.reachableBy(src)
	}
}

buffer_overflow(cpg).code.l

---------------------------------

buffer_overflow(cpg).where(_.method.name(".*ParseText.*")).l.dump



cpg.call("strncpy|memcpy")
	.whereNot(_.argument(3).isLiteral)
	.where(_.argument(1).code(".*Stack.*"))
	.where(_.method.tag.name("attack_surface"))


-----------------------------------

Directory Traversal

cpg.call("fopen.*")
	.argument(1).whereNot(_.isLiteral)
	.reachableByFlows(cpg.call("strcat"))
	.where(._method.tag.name("attack_surface"))

-----------------------------------

cpg.call("*mg_.").name.dedup.l

cpg.call("*mg_.").method.
	.repeat(_.callee.internal)(_.emit.times(10))
	.newTagNode("attacksurface").store

commit

---------------------------------

https://queries.joern.io/

https://github.com/AppThreat/joern-lib

---------------

https://coda.io/d/How-to-hunt-for-bugs-in-stuff_dhB13mHySs1/How-to-hunt-for-bugs-in-stuff_su3Yj#_lujYE

https://queries.joern.io/?utm_source=coda&utm_medium=iframely

---------------------------------

autopep8 -i

https://readthedocs.org/projects/chucky/downloads/pdf/latest/
```


