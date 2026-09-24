# Arquitectura — Fase 1

```text
src/art_sim/
├── domain/                     # Entidades Pydantic, errores y puerto Repository
│   ├── exceptions.py
│   ├── models.py
│   └── repositories.py
└── infrastructure/             # Adaptadores externos e implementación Neo4j
    ├── config.py
    ├── cypher_validator.py
    └── neo4j_graph_repository.py
```

`Neo4jGraphRepository` se crea en el composition root con `Neo4jSettings` y
`CypherValidator`. Ningún dato de scanners, Kubernetes o logs se interpola en
Cypher: todos los valores pasan como parámetros validados. La búsqueda usa
`allShortestPaths`, limita la profundidad y ordena por identificadores de
activos para producir un resultado estable antes de que cualquier agente de IA
participe en fases posteriores.
