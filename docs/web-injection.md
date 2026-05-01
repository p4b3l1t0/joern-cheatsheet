# SQL Injection y XSS

Estas queries estan pensadas para Java/JVM y frameworks web, pero la idea se puede adaptar a PHP, JavaScript, Python o Go cambiando fuentes y sinks.

## SQL Injection: parametros HTTP a query

```scala
def source = cpg.call
  .methodFullName(".*HttpServletRequest\\.(getParameter|getHeader|getQueryString).*")

def sink = cpg.call
  .name("(?i)(query|executeQuery|executeUpdate|execute|prepareStatement)")
  .argument

sink.reachableByFlows(source).p
```

## Query SQL construida por concatenacion

```scala
cpg.call
  .name("(?i)(query|executeQuery|executeUpdate|execute|prepareStatement)")
  .where(_.argument.code(".*(SELECT|INSERT|UPDATE|DELETE).*\\+.*"))
  .map(c => (c.method.name, c.lineNumber, c.code))
  .l
```

## `Statement` en lugar de prepared statements

```scala
cpg.call
  .methodFullName(".*java\\.sql\\.Statement\\.(execute|executeQuery|executeUpdate).*")
  .l
```

## Prepared statement con SQL dinamico

```scala
def source = cpg.call
  .methodFullName(".*HttpServletRequest\\.(getParameter|getHeader|getQueryString).*")

def sink = cpg.call
  .name("(?i)prepareStatement")
  .argument(1)

sink.reachableByFlows(source).p
```

## Reflected XSS en servlets

Basado en `xss-servlet` de Joern Query Database.

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

## Output HTML sin encoding aparente

```scala
def source = cpg.call.methodFullName(".*HttpServletRequest\\.(getParameter|getHeader|getQueryString).*")
def sink = cpg.call.name("(?i)(print|println|write|append)").argument

sink
  .reachableByFlows(source)
  .whereNot(_.locations.code("(?i).*(escape|encode|sanitize).*"))
  .p
```

## Que validar manualmente

- Si el sink usa parametros bindados o concatenacion.
- Si el encoding corresponde al contexto HTML, atributo, JS, URL o CSS.
- Si sanitizacion y sink trabajan sobre el mismo dato.
- Si el framework auto-escapa por defecto.
