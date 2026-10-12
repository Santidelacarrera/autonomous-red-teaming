# Nota del proyecto — autonomous-red-teaming (Nexus Security & AI Lab)

> Estado: **100 % de la definición de terminado, pendiente de aprobación humana.**
> `aprobado_santiago` / `aprobado_sistema`: no modificados (los decide una persona).
> La nota del vault (`1_Projects`) no es accesible desde esta sesión: esta es su copia en el repositorio.
> Rama: `feat/autonomous-red-teaming-autonomo-2026-10-12` · base: `main` · costo: $0.

## 1. Tareas y evidencia

| # | Tarea | Hecho | Evidencia (comando → resultado) |
|---|---|---|---|
| 1 | Catálogo de escenarios con objetivo y criterio de éxito | 10 escenarios (`SCN-01..10`), cada uno con objetivo del atacante, criterio de éxito medible y consecuencia del fallo; 34 casos, cada uno en exactamente un escenario; informe con estado por escenario (`held`/`finding`/`fail`) | `python -m art_sim.bas --list-scenarios > docs/bas-scenarios.md` · `pytest tests/security/test_bas_scenarios.py` → 30 passed (incluye: cada caso en un solo escenario, documento == código) |
| 2 | Pruebas de reproducibilidad | Huella de campaña (caso, veredicto, HTTP, detalle, detección; sin ids ni tiempos) fijada en `src/art_sim/bas/expected_fingerprint.sha256` | `pytest tests/security/test_bas_reproducibility.py` → 7 passed: 3 ejecuciones en proceso idénticas; 2 intérpretes independientes desde otro directorio de trabajo → misma huella que la referencia; la huella cambia si se quita un control |
| 3 | Gate de autorización escrita (sin archivo, no corre) | `authorization.py`; `run_campaign` exige un `GrantedAuthorization`; el CLI comprueba antes de crear nada; la autorización es el primer registro del log forense | `python -m art_sim.bas --out /tmp/x` → `refused: not authorised…`, **exit 3**, directorio no creado · `pytest tests/security/test_bas_authorization.py` → 61 passed · **mutación: 12/12 controles del gate desactivados uno a uno → las pruebas fallan en los 12** |
| 4 | Solo laboratorio local | Alcance exactamente `["local-lab"]` (cualquier otro destino invalida el archivo); backends `sqlite`/`postgresql-loopback`; transporte ASGI en proceso; DSN no loopback rechazada antes de crear nada | pruebas de alcance (7 destinos rechazados, backend remoto, DSN remota) incluidas en las 61 anteriores y en `test_bas_framework.py` |

## 2. Definición de terminado

| # | Condición | Estado | Evidencia |
|---|---|---|---|
| 1 | Tareas cumplidas, cada una con evidencia | ✅ | sección 1 |
| 2 | Pruebas automatizadas pasando | ✅ | `ART_BAS_TEST_POSTGRES_DSN=postgresql://bas@127.0.0.1:55432/basdb python -m pytest -q tests` → **634 passed, 97 skipped** (los skipped son suites que exigen Redis/Vault/OTel/etc. sin configurar aquí; antes de este cambio: 543 passed). Sobre PostgreSQL 16 real |
| 3 | Seguridad y lint sin errores altos | ✅ | `python -m ruff check .` → All checks passed · `python -m mypy .` → no issues in 185 files · `python -m bandit -q -c pyproject.toml -r src` → 0 issues · `python -m pip_audit -r requirements.lock` → No known vulnerabilities · `gitleaks detect` (70 commits) → no leaks · `actionlint ci.yml` → limpio |
| 4 | README con instrucciones reproducibles | ✅ | README: sección "Breach-and-attack simulation" (instalar, probar, usar); `docs/bas.md` (gate, escenarios, reproducibilidad); `authorizations/README.md` |
| 5 | Bitácora de decisiones con fecha y motivo | ✅ | sección 3 |
| 6 | Lista de pendientes para Santiago | ✅ | sección 4 |

## 3. Bitácora de decisiones (2026-10-12)

| Decisión | Motivo |
|---|---|
| Rama `feat/autonomous-red-teaming-autonomo-2026-10-12` (nombre real del repo, no «autonomus») creada desde `claude/lucid-hopper-e6odvk` | El gate se construye sobre el framework BAS, que aún no está en `main`; el PR incluye por tanto el commit del BAS (`4354c73`) y el trabajo de hoy |
| La nota vive en `docs/nota-proyecto.md` | El vault no es accesible desde la sesión; el repositorio es el único lugar verificable |
| El gate es una **atestación**, no identidad criptográfica | No hay infraestructura de firmas a costo $0 en el repo; se compensa con CODEOWNERS sobre `authorizations/`, revisión humana, y el hash del archivo en cada log forense. Límite documentado en `docs/bas.md` |
| La autorización se vincula al **digest del catálogo** | Añadir o cambiar un ataque exige una autorización nueva y revisada; evita que el alcance autorizado crezca sin que el dueño lo vea |
| Ventana máxima de **90 días** | Las autorizaciones se renuevan en lugar de vivir para siempre |
| El destino admite **solo** `local-lab`; cualquier otro lo invalida entero | Un archivo con un destino real es un error o un abuso: se rechaza completo, no se filtra |
| **No** se crea `authorizations/local-lab.json` | Es el consentimiento del dueño del sistema; no puedo fabricarlo. Se entrega plantilla inválida a propósito (marcadores, `acknowledges_lab_only: false`) |
| En CI, sin archivo: el paso se omite con aviso y se **comprueba que el gate rechaza** (exit 3, nada creado) | El CI no debe ponerse en rojo por la ausencia de un permiso, y la ausencia del permiso es en sí un comportamiento que probar |
| Estado de escenario `PASS` renombrado a `HELD` | Bandit B105 marcaba `PASS = "pass"`; en lugar de silenciarlo, el nombre describe mejor el resultado («el control aguantó») |
| Sin `# nosec` ni lista de excepciones de gitleaks | Los dos falsos positivos se resolvieron cambiando el código, no ocultando la regla |
| `sanitize_text` endurecido (NFKC, sin caracteres de formato, homoglifos) | La campaña BAS encontró 4 de 16 bypasses; no está en una ruta de producción (el control real es la lista de permitidos), por tanto es defensa en profundidad |
| La DSN remota se rechaza **antes** de crear el log forense | Detectado al planificar las pruebas: antes se rechazaba tarde, con el log ya escrito |
| No se corrigió el hueco de RLS | Es un cambio de esquema en producción; se mantiene como hallazgo abierto `DS-RLS-POSTURE` y diseño en `docs/bas.md` |
| Se reescribió el único commit de la rama del BAS (falso positivo de gitleaks) | Rama propia, sin integrar; solo se reemplazó un commit con `--force-with-lease` fijado a su hash |

## 4. Pendientes para Santiago

1. **Firmar la autorización**: copiar `authorizations/local-lab.template.json` a `authorizations/local-lab.json`, completar nombres, enunciado y fechas, y fijar `catalogue_sha256` con `python -m art_sim.bas --print-catalogue-digest` tras revisar `docs/bas-scenarios.md`. Hasta entonces el CI omite el BAS (por diseño) y `reproduce.sh` lo marca `SKIP`.
2. **Revisar y aprobar el PR** (y decidir el merge). No lo hace esta sesión. Estados `aprobado_santiago`/`aprobado_sistema` sin tocar.
3. **Decidir el cierre del hallazgo RLS** (`DS-RLS-POSTURE`): promover `organization_id` a columna, `ENABLE/FORCE ROW LEVEL SECURITY`, política con `current_setting('app.organization_id')`, rol sin `BYPASSRLS`. Cambio de esquema en producción: requiere decisión y ventana.
4. **Opcional, endurecer el gate**: firma criptográfica del archivo (commit firmado o firma separada) y anclaje del *head* de AegisTrace fuera del escritor.
5. **Copiar esta nota al vault** (`1_Projects`) y actualizar allí los estados, ya que la sesión no puede acceder a él.
6. Pendientes heredados (sin cambios, no tocados): proveedor OIDC real, SIEM real, backend de métricas, AWS/PostgreSQL gestionados, Neo4j sin re-ejecutar (`docs/integrations.md`).

## 5. Riesgos conocidos

- El gate es procedimental: quien tenga escritura en el repo puede redactar el archivo. Mitigado por CODEOWNERS, revisión y el digest del archivo en el log.
- Cualquier cambio del catálogo invalida la autorización vigente (intencionado; fricción asumida).
- La referencia de huella es solo para SQLite; en PostgreSQL el detalle del caso RLS difiere y no se fija.
- El BAS usa credenciales de desarrollo: el proveedor de identidad real está fuera de alcance (las claims de organización firmadas se prueban en `test_org_isolation.py`).
- La campaña demuestra que estos 34 ataques fallan, no que no existan otros.

---
*Nexus Security & AI Lab · componente reutilizable: depende solo de la API pública de la plataforma y no contiene datos de clientes. Pendiente de aprobación humana.*
