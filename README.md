# Joern Cheatsheet para Hunting de Vulnerabilidades

Coleccion de queries de Joern orientadas a bug hunting y auditoria de codigo. El objetivo es partir de patrones simples, convertirlos en fuentes/sinks claros y despues refinar resultados con data-flow, control-flow y filtros por contexto.

Joern representa el codigo como un Code Property Graph (CPG). Para hunting, el flujo habitual es:

1. Encontrar llamadas peligrosas o patrones sospechosos.
2. Definir fuentes controlables por atacante y sinks sensibles.
3. Usar `reachableBy` para confirmar conectividad de datos.
4. Usar `reachableByFlows(...).p` para imprimir el path y validar manualmente.
5. Reducir falsos positivos con filtros como `where`, `whereNot`, `controlledBy`, `notControlledBy`, `argumentIndex`, `method`, `callIn`, `caller` y `callee`.

## Guias por Vulnerabilidad

- [Command Injection](docs/command-injection.md)
- [Buffer Overflow y Memory Corruption](docs/buffer-overflow-memory-corruption.md)
- [Use After Free y Double Free](docs/use-after-free.md)
- [Input Validation y Return Values](docs/input-validation.md)
- [Memory Leaks](docs/memory-leaks.md)
- [Directory Traversal, Filesystem y Race Conditions](docs/filesystem-path-traversal.md)
- [TLS, Certificados y Trafico Inseguro](docs/tls-network.md)
- [SQL Injection y XSS](docs/web-injection.md)
- [Enteros, Truncation y Allocation Bugs](docs/integer-overflow.md)

## Snippets Base

### Fuentes frecuentes

```scala
def cliArgs = cpg.method.name("main").parameter.name("argv")

def cInputs = cpg.call
  .name("(?i)(getenv|gets|fgets|scanf|sscanf|read|recv|recvfrom)")
  .argument

def javaHttpInput = cpg.call
  .methodFullName(".*HttpServletRequest\\.(getParameter|getHeader|getCookies|getQueryString).*")
```

### Sinks y data-flow

```scala
def source = cliArgs ++ cInputs
def sink = cpg.call.name("(?i)(system|popen|exec.*)").argument

sink.reachableBy(source).l
sink.reachableByFlows(source).p
```

### Inspeccion rapida

```scala
cpg.call.name("(?i)(strcpy|strcat|sprintf|gets|scanf)").code.l

cpg.method
  .filter(_.numberOfLines >= 500)
  .map(m => (m.name, m.filename, m.lineNumber))
  .l

cpg.call.name(".*")
  .map(c => (c.name, c.method.name, c.lineNumber, c.code))
  .take(20)
  .l
```

## Notas de Uso

- `reachableBy` devuelve fuentes que alcanzan un sink; `reachableByFlows` imprime los caminos y suele ser mejor para explicar hallazgos.
- `callIn` es util cuando se parte desde una definicion de metodo y se quieren listar sus call-sites.
- `whereNot(_.argument(...).isLiteral)` ayuda a priorizar datos dinamicos frente a constantes.
- Para evitar ruido, filtra por archivo, metodo o superficie de ataque cuando puedas: endpoints, parsers, handlers, comandos CLI, entrada de red o codigo expuesto.
- Las queries son heuristicas. Un match no es una vulnerabilidad confirmada hasta revisar sanitizacion, bounds checks, ownership de memoria y contexto de ejecucion.

## Referencias

- [Joern Documentation](https://docs.joern.io/)
- [Data-Flow Steps](https://docs.joern.io/cpgql/data-flow-steps/)
- [CPGQL Reference Card](https://docs.joern.io/cpgql/reference-card/)
- [Joern Query Database](http://queries.joern.io/)
- [Interprocedural Data-flow in Joern](https://joern.io/blog/interproc-dataflow-2024/)
- [AppThreat joern-lib](https://github.com/AppThreat/joern-lib)
