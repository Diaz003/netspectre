# NetSpectre v2.0 — Notas del Release

**Fecha:** 8 de septiembre de 2026
**Tag:** `v2.0` · **Commit:** `9d332c1` — `feat(core): release NetSpectre v2.0 with HTTP fingerprinting engine`
**Versión del paquete:** `2.0.0`

---

## ⚡ Novedad estrella: motor de fingerprinting HTTP asíncrono

NetSpectre v2.0 incorpora **`HTTPFingerprinter`** (`http_fingerprinter.py`), un motor
de identificación de servicios web de detección multicapa, construido sobre
`asyncio` + `aiohttp`.

### Puntuación de confianza por capas (0–100 %)

| Capa | Peso | Qué detecta |
|---|---|---|
| Cabeceras HTTP | **45 pts** | `Server:`, cookies de sesión (`sysauth` → LuCI), `X-Powered-By` |
| HTML / JS | **40 pts** | Variables JS (`G_FEATURES`), endpoints (`/cgi-bin/luci/`), generador `<meta>` |
| Estado / rutas | **15 pts** | Códigos de estado, rutas firma (`/webfig/`, `/HNAP1/`, `/ISAPI/`…), `robots.txt` |

- ~60 expresiones regulares **precompiladas al cargar el módulo** (nada se compila en caliente).
- El servicio final es el de la evidencia con más puntos; el umbral de confianza
  orienta la lectura (verde ≥ 60 %, amarillo ≥ 30 %).
- `extra_info` extrae metadatos expuestos: MACs, modelo, serial, versión de
  hardware/firmware.

### Robustez

- Timeout por petición **+ tope global** (`overall_timeout`, 25 s por objetivo).
- Errores TLS/SSL distinguidos (`handshake failed`, `certificate rejected`).
- Redirecciones seguidas (hasta 5) registrando la cadena, con segunda pasada
  sin `allow_redirects` para puntuar las cabeceras *originales*.
- Los fallos de red nunca lanzan excepción: llegan en `result.error`.
- Salida estructurada con dataclass `HTTPFingerprint` (`service`,
  `confidence_score`, `server_header`, `extra_info`, `title`, `redirects`,
  `layers`) y `as_dict()` listo para JSON.

---

## 🧩 Nuevo comando REPL: `fingerprint` (alias `fp`)

```text
netspectre > ports 192.168.1.0/24
netspectre > fingerprint
```

- **Selección de objetivos en cascada:** puertos HTTP abiertos del último
  `ports` → si no hay auditoría de puertos, sondea **80/443/8080** sobre los
  hosts descubiertos con `hosts` → objetivo explícito
  (`fingerprint <cidr|ip> [rango]`).
- Ejecución **async real** (`asyncio.TaskGroup`, semáforo 16 concurrentes,
  tope de 200 objetivos).
- **Degradación elegante:** sin `aiohttp` el resto de la herramienta funciona
  igual y `fingerprint` avisa con un mensaje limpio.

### Flujo de auditoría completo

```text
ports → fingerprint → risks → save
```

---

## 🔗 Integración con el motor

- **Columna BANNER de `ports`:** los endpoints ya huellados muestran el
  servicio identificado con su confianza — `nginx [73%] · 小米路由器` —
  en lugar del banner TCP crudo.
- **`risks` ahora evalúa fingerprints** (`WEB_PANEL_RULES`): genera hallazgos
  automáticos por paneles de administración expuestos (LuCI, WebFig, HNAP →
  HIGH) e interfaces de gestión HTTP sin TLS (MEDIUM), cada uno con su
  recomendación `↳ fix:` de remediación.
- Los hallazgos web fluyen a `status`, `build_report` (risk_summary) y por
  tanto al **risk gate** de CI (`--max-high` / `--max-medium`).
- Los resultados se exportan bajo la clave `fingerprints` en `save` y en
  `--plain --json`.

---

## 📦 Empaquetado e instalación

- **`pyproject.toml`** (versión `2.0.0`): instalable con `pip`/`pipx`;
  comando `netspectre` en el PATH; `aiohttp` como dependencia **opcional**:

  ```bash
  pip install netspectre               # núcleo (solo stdlib)
  pip install "netspectre[fingerprint]"  # con motor HTTP async
  ```

- **`requirements.txt`**: documenta la dependencia opcional
  (`aiohttp>=3.9,<4`) con notas de instalación (incluido el caso PEP 668 de
  Debian/Ubuntu).
- El **núcleo sigue siendo solo stdlib**: host discovery, auditoría TCP/UDP,
  riesgos, perfiles, export JSON y risk gate funcionan sin instalar nada.

---

## 🤝 CI/CD (GitHub Actions)

`.github/workflows/ci.yml` valida en **Python 3.11 y 3.13**:

- **job `core`** — sin `aiohttp`: compila todos los módulos, comprueba que el
  banner de versión coincide con `pyproject.toml`, smoke test de ayuda/status
  y verifica que `fingerprint` degrada con mensaje limpio.
- **job `fingerprint-engine`** — con `aiohttp` (instala el extra
  `[fingerprint]`): compila el motor, comprueba que los pesos de las capas
  suman 100 y que el comando está disponible en el REPL.

---

## 🌐 Interfaz web y documentación

- **`guide.html`**: tarjeta completa del comando `fingerprint` (qué hace /
  para qué / ejemplo realista), tabla de pesos por capas (45/40/15) y receta
  del flujo `ports → fingerprint → risks → save`.
- **`index.html`** (demo interactiva): comando `fingerprint` simulado con
  datos por host, entrada en `help`, chip contextual, riesgos web en la demo
  y auto-demo actualizada.
- **`README.md`**: versión 2.0.0, sección de fingerprinting HTTP con tabla de
  capas, dependencia opcional y flujos de trabajo.

---

## 🧹 Higiene del repositorio

- `.gitignore` ampliado: `ip.txt`, logs (`*.log`) y artefactos de
  escaneo/risks (`netspectre-report-*.json`, `netspectre-risks-*`).
- Limpieza de artefactos regenerados del árbol de trabajo
  (`__pycache__/`, `netspectre.egg-info/`).

---

## ✔️ Verificación en vivo (router real del laboratorio)

- `ports 192.168.31.1 80,443` → `fingerprint` → **`nginx [73%]`** en ambos
  endpoints, `server: nginx/1.2.2`, título `小米路由器`, marcadores LuCI.
- `risks` → 2 hallazgos **MED `web-luci`** con remediación
  (`bind LuCI to the LAN only, force HTTPS, strong root password…`).
- `save` → JSON válido con `"version": "2.0.0"` y clave `fingerprints`
  (2 entradas, confianza 73 %).
- Pipeline `--plain --json` (regresión): válido, con hallazgos web incluidos.

---

## ⚠️ Aviso legal

NetSpectre es software libre proporcionado **"tal cual" (AS-IS)**, sin
garantía de ningún tipo. El autor no asume responsabilidad por el mal uso,
daños o consecuencias derivadas de su utilización. Úsalo únicamente en redes
para las que tengas autorización explícita.
