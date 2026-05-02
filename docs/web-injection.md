# SQL Injection and XSS

These queries are written with Java/JVM and web frameworks in mind, but the same idea can be adapted to PHP, JavaScript, Python, or Go by changing the sources and sinks.

## SQL Injection: HTTP Parameters to Query

```scala
def source = cpg.call
  .methodFullName(".*HttpServletRequest\\.(getParameter|getHeader|getQueryString).*")

def sink = cpg.call
  .name("(?i)(query|executeQuery|executeUpdate|execute|prepareStatement)")
  .argument

sink.reachableByFlows(source).p
```

## SQL Query Built by Concatenation

```scala
cpg.call
  .name("(?i)(query|executeQuery|executeUpdate|execute|prepareStatement)")
  .where(_.argument.code(".*(SELECT|INSERT|UPDATE|DELETE).*\\+.*"))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## `Statement` Instead of Prepared Statements

```scala
cpg.call
  .methodFullName(".*java\\.sql\\.Statement\\.(execute|executeQuery|executeUpdate).*")
  .l
```

## Prepared Statement With Dynamic SQL

```scala
def source = cpg.call
  .methodFullName(".*HttpServletRequest\\.(getParameter|getHeader|getQueryString).*")

def sink = cpg.call
  .name("(?i)prepareStatement")
  .argument(1)

sink.reachableByFlows(source).p
```

## Reflected XSS in Servlets

Based on `xss-servlet` from the Joern Query Database.

```scala
def source = cpg.call.methodFullNameExact(
  "javax.servlet.http.HttpServletRequest.getParameter:java.lang.String(java.lang.String)"
)

def responseWriter = cpg.call.methodFullNameExact(
  "javax.servlet.http.HttpServletResponse.getWriter:java.io.PrintWriter()"
)

def sinks = cpg.call
  .methodFullNameExact("java.io.PrintWriter.println:void(java.lang.String)")
  .where(_.argument(0).reachableBy(responseWriter))

sinks.where(_.argument(1).reachableBy(source)).l
```

## HTML Output Without Obvious Encoding

```scala
def source = cpg.call.methodFullName(".*HttpServletRequest\\.(getParameter|getHeader|getQueryString).*")
def sink = cpg.call.name("(?i)(print|println|write|append)").argument

sink
  .reachableByFlows(source)
  .whereNot(_.locations.code("(?i).*(escape|encode|sanitize).*"))
  .p
```

## What to Check Manually

- Whether the sink uses bound parameters or string concatenation.
- Whether encoding matches the output context: HTML, attribute, JS, URL, or CSS.
- Whether sanitization and the sink use the same value.
- Whether the framework auto-escapes output by default.
