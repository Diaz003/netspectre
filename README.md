# NetSpectre

> **v2.0** — nuevo motor de fingerprinting HTTP asíncrono (`fingerprint`),
> hallazgos de riesgo desde paneles web expuestos y empaquetado pip.
> El núcleo sigue siendo 100 % librería estándar.

```text
   _   _    _ _____ _____ ____  _____   ____ ___  ____  _____
  | \ | |  / \|_   _|_   _/ ___||_   _| / ___/ _ \|  _ \| ____|
  |  \| | / _ \ | |   | | \___ \  | |  | |  | | | | | |_) |  _|
  | |\  |/ ___ \| |   | |  ___) | | |  | |__| |_| |  _ <| |___
  |_| \_/_/   \_\_|   |_| |____/  |_|   \____\___/|_| \_\_____|
```

**NetSpectre** es una herramienta de auditoría de redes locales con menú
interactivo en bucle (estilo Metasploit/Aircrack-ng), estética ANSI y motor
100 % Python estándar — **sin dependencias externas**.

| | |
|---|---|
| 🐍 Requisitos | Python 3.11+ (probado en 3.13) — solo librería estándar |
| 📦 Instalación | Cero dependencias: clona y ejecuta (`pip install -r requirements.txt` solo para fingerprinting) |
| 🖥️ Plataformas | Linux · macOS · Windows |
| 🎨 Interfaz | REPL con colores ANSI, banners y prompt contextual |
| 🔍 Motor | Sondeo TCP connect, ICMP raw opcional, caché ARP/OUI |

---

## ⚠️ Aviso legal — uso autorizado únicamente

> NetSpectre es una herramienta de **auditoría y educación**. Escanear redes,
> hosts o puertos **sin autorización expresa del propietario es ilegal** en la
> mayoría de jurisdicciones.
>
> **Úsala exclusivamente sobre:**
> - tu propia red doméstica o de laboratorio,
> - redes de clientes con un contrato/consentimiento firmado (pentesting),
> - entornos de práctica que tú controles.
>
> El autor no se hace responsable del mal uso de esta herramienta.

---

## 🚀 Instalación

```bash
# 1) clona el repositorio
git clone <url-del-repo> NetSpectre
cd NetSpectre

# 2) (opcional) revisa el código — es un único fichero legible
less netspectre.py

# 3) ejecuta
python3 netspectre.py
```

> **Nota:** en la mayoría de sistemas Linux/macOS modernos el binario se llama
> `python3` (no `python`). En Windows funciona `python netspectre.py`.

**Todo el núcleo funciona sin instalar nada**: descubrimiento de hosts,
auditoría de puertos TCP/UDP, informe de riesgos y export JSON usan únicamente
la librería estándar.

### Dependencia opcional: fingerprinting HTTP

El comando `fingerprint` usa el motor async de `http_fingerprinter.py`, que
depende de [`aiohttp`](https://docs.aiohttp.org/). Instálalo con:

```bash
pip install -r requirements.txt
# o solo la dependencia:
pip install aiohttp
```

- En Debian/Ubuntu con PEP 668 puede hacer falta `pip install --user --break-system-packages aiohttp`, o mejor crear un venv:
  ```bash
  python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
  ```
- Sin `aiohttp`, el resto de NetSpectre funciona igual y `fingerprint`
  responde con un aviso limpio: `aiohttp is not installed — pip install aiohttp`.
- Requisito de Python: 3.11+ (el motor usa `asyncio.TaskGroup`). El resto de la
  herramienta funciona en 3.8+, pero se recomienda la misma versión para todo.

---

## 📖 Uso

### Modo interactivo (REPL)

```bash
python3 netspectre.py
# o con objetivo preconfigurado:
python3 netspectre.py --target 192.168.1.0/24
```

Al arrancar verás el banner, la IP local detectada y un prompt contextual:

```text
netspectre (no target) > set target 192.168.1.0/24
  [✓] target => 192.168.1.0/24
netspectre (192.168.1.0/24) > hosts
  [+] sondeando 254 host(s) ...
```

### Modo no interactivo (un disparo y sale)

```bash
python3 netspectre.py --plain              # descubre hosts + audita puertos top100
python3 netspectre.py -t 10.0.0.0/24 --plain
```

### Banderas de línea de comandos

| Bandera | Descripción |
|---|---|
| `-t, --target CIDR\|IP` | Objetivo por defecto de la sesión |
| `-p, --profile NOMBRE` | Carga un perfil guardado al arrancar (`-t` tiene prioridad) |
| `--plain` | Ejecuta `hosts` + `ports` automáticamente y sale |
| `--ports SPEC` | En `--plain`: conjunto TCP a auditar — `top100`, `all`, `22,80,443`, `1000-2000` (gana al perfil) |
| `--udp [SPEC]` | En `--plain`: añade la auditoría UDP — bare `--udp` = top-24, o spec (`53,123,161`) |
| `--max-high N` | Puerta CI: `exit 1` si hay más de N hallazgos high (gana al perfil) |
| `--max-medium N` | Puerta CI: `exit 1` si hay más de N hallazgos medium |
| `--json` | Con `--plain`: vuelca el informe JSON a stdout (el progreso va a stderr) |
| `--no-color` | Desactiva los colores ANSI |
| `--log FICHERO` | Vuelca cada evento (HOST-UP / PORT-OPEN) a un fichero |
| `-V, --version` | Muestra la versión |

---

## 🧾 Referencia de comandos

| Comando | Alias | Descripción |
|---|---|---|
| `help [comando]` | `?`, `h` | Lista los comandos o detalla uno |
| `hosts [cidr\|ip]` | `scan`, `sweep` | Descubre hosts activos (sondeo TCP; ICMP opcional) |
| `ports [cidr\|ip] [rango]` | `portscan`, `audit` | Audita puertos TCP abiertos + banners |
| `udp [cidr\|ip] [rango]` | `udpscan` | Audita puertos UDP con sondas por servicio (DNS, NTP, SNMP…) |
| `fingerprint [cidr\|ip] [rango]` | `fp` | Identifica servicios HTTP con el motor async v2.0 (confianza 0-100%) |
| `risks [all\|high\|medium]` | `risk`, `vulns` | Hallazgos de riesgo de la última auditoría, por severidad |
| `risks md\|csv [filtro] [fichero]` | | Exporta los hallazgos a Markdown o CSV para ticketing |
| `osint` | `arp` | Intel local: hostname, IP de salida y caché ARP con fabricante |
| `set [opción] [valor]` | `config` | Ver o cambiar opciones de sesión |
| `profile save\|load\|list\|show\|delete [nombre]` | `profiles`, `pf` | Guarda/carga configuraciones de sesión entre ejecuciones |
| `status` | `st`, `info` | Resumen de sesión y estadísticas de sondeo |
| `history` | `hist` | Historial de comandos (persiste entre sesiones) |
| `save [fichero.json]` | `report`, `export` | Exporta los resultados a un informe JSON |
| `clear` | `cls` | Limpia la pantalla |
| `exit` | `quit`, `q` | Salir (también vale `Ctrl+D` / `Ctrl+C`) |

### Rangos de puertos aceptados por `ports`

```text
ports                          # top100 — los 65 puertos TCP más comunes
ports 22,80,443                # lista explícita
ports 1000-2000                # rango
ports 22,80,8000-8100          # mezcla de listas y rangos
ports 192.168.1.0/24 all       # los 65535 puertos (lento: ~2 min por host caído)
```

### 🚨 Resaltado de riesgo

Al terminar cada auditoría, NetSpectre clasifica los servicios peligrosos
detectados y los señala en tres sitios:

1. **En vivo** — cada puerto abierto catalogado lleva insignia:
   `[RISK:servicio]` (rojo, nivel alto) o `[warn:servicio]` (amarillo, medio).
2. **Resumen priorizado** — al cerrar el escaneo se listan los hallazgos
   (high primero) con el motivo, p. ej.:
   ```text
   [!] 2 risky exposure(s): 1 high, 1 medium
       [RISK:smb] 192.168.1.1    445/tcp  microsoft-ds  SMB: EternalBlue/WannaCry vector...
       [warn:ftp] 192.168.1.150  21/tcp   ftp           plaintext credentials...
   ```
3. **Informe JSON** (`save`) — clave `risk_summary` con contadores `high`/`medium`
   y la lista de hallazgos (`ip`, `port`, `service`, `level`, `tag`, `reason`);
   cada puerto también lleva sus campos `risk` y `risk_level`.

Catálogo actual — **high**: telnet (23), adb (5555), ipmi (623), redis (6379),
memcached (11211), docker API (2375), rdp (3389), vnc (5900/5901), smb (445),
tftp (69/udp) · **medium**: ftp (21), netbios (139), snmp (161), mssql (1433),
mysql (3306), postgresql (5432), nfs (2049), upnp (5000), k8s-api (6443),
elasticsearch (9200) y, en UDP: ntp (123), netbios (137/138), snmp (161/162),
syslog (514), ssdp (1900), nfs (2049), sip (5060), memcached (11211).

### 📡 Escaneo UDP (`udp`)

UDP no tiene handshake: un servicio mudo y un puerto filtrado se ven igual
desde fuera. NetSpectre envía **sondas específicas por protocolo** para hacer
que los servicios reales respondan y aplica la semántica de estados de nmap:

```text
udp                        # top: los 24 puertos UDP más comunes del LAN
udp 192.168.1.1 53,123,161 # lista explícita
udp 192.168.1.0/24         # sobre los hosts vivos en memoria
set udp_timeout 3s         # tiempo de espera por respuesta (def. 2s)
set udp_workers 64         # hilos del barrido UDP
```

| Estado | Significado |
|---|---|
| `open` | el servicio respondió (se muestra la respuesta clasificada) |
| `open|filtered` | sin respuesta ni error ICMP — lo habitual en servicios mudos |
| `closed` | el objetivo devolvió ICMP "port unreachable" |
| `filtered` | otro error ICMP (bloqueo, host inalcanzable…) |

Sondas incluidas: DNS/mDNS (query A), NTP (modo cliente), SNMPv2c `sysDescr.0`
(con comunidad `public`), NetBIOS node-status (RFC 1002) y SSDP `M-SEARCH`.

### 🔎 Fingerprinting HTTP (`fingerprint`)

Motor asíncrono de NetSpectre v2.0 (`http_fingerprinter.py`, basado en
`asyncio` + `aiohttp`) que identifica el software que hay detrás de cada
servicio web detectado por `ports`. Requiere instalar la dependencia opcional
(`pip install -r requirements.txt`); sin ella, el resto de la herramienta
funciona igual y el comando avisa con un error limpio.

```text
ports 192.168.1.0/24        # primero el auditório TCP
fingerprint                 # huella de todos los puertos HTTP abiertos en memoria
fingerprint 192.168.1.1     # objetivo directo (usa el rango de sesión filtrado a HTTP)
fingerprint 192.168.1.1 80,8080
```

Salida de ejemplo:

```text
┌─────────────────────────── HTTP FINGERPRINTS ───────────────────────────┐
  TARGET            PORT   SERVICE                        SERVER / ERROR
  192.168.1.1       80     nginx [73%]                    nginx/1.2.2 · MiRouter
  [✓] 1/1 endpoint(s) fingerprinted — stored in session (use 'save' to export)
```

La **confianza (0-100%)** se calcula sumando tres capas ponderadas con tope:

| Capa | Peso máx. | Qué mira |
|---|---|---|
| Cabeceras | 45 | `Server`, `Set-Cookie` (PHPSESSID, sysauth/LuCI, JSESSIONID…), `X-Powered-By`, `WWW-Authenticate` |
| HTML | 40 | variables JS (`G_FEATURES`), endpoints (`/cgi-bin/luci/`, `/HNAP1/`, `/ISAPI/`), `<meta generator>`, título |
| Estado/rutas | 15 | códigos 200/302/401/403 y respuestas a rutas firma (`/webfig/`, `/webman/index.cgi`…) |

Cada petición sigue redirecciones (hasta 5, registradas en el resultado), aplica
timeout por petición y un tope global por objetivo, y captura errores TLS/SSL
sin romper el barrido. Los metadatos expuestos (MAC, modelo, serial, firmware)
se extraen del HTML al campo `extra_info`. Los resultados quedan en memoria y
se exportan con `save` bajo la clave `fingerprints` del informe JSON.

### 💾 Perfiles de sesión (`profile`)

Guarda la configuración completa (objetivo, rangos, timeouts, workers, ICMP)
en `~/.netspectre/profiles/<nombre>.json` y recárgala en cualquier ejecución:

```text
profile save office router del laboratorio   # guarda con nota
profile list                                 # tabla de perfiles guardados
profile show office                          # detalle de valores
profile load office                          # aplica todo al sesión actual
profile delete office                        # borra el perfil
```

```bash
# también al arrancar:
python3 netspectre.py --profile office
python3 netspectre.py --profile office -t 127.0.0.1   # -t gana al perfil
```

Tras cargar un perfil, el prompt lo recuerda: `netspectre (10.0.0.0/24:@office) >`.
Si un valor guardado deja de pasar la validación (p. ej. un timeout fuera de
rango tras una actualización), el resto del perfil se aplica y los valores
rechazados se reportan.

### 🔗 Salida JSON para tuberías (`--plain --json`)

En modo no interactivo, `--json` imprime el informe completo (hosts, puertos
tcp/udp, `risk_summary`) por **stdout** limpio — banners y progreso van por
**stderr**, así que puedes enviar la salida directamente a `jq` u otras
herramientas:

```bash
python3 netspectre.py --plain --json -t 192.168.1.0/24 | jq .

# hosts vivos:
python3 netspectre.py --plain --json -t 192.168.1.0/24 2>/dev/null | jq '.hosts[].ip'

# hallazgos de riesgo en una línea:
python3 netspectre.py --plain --json -t 192.168.1.0/24 2>/dev/null \
  | jq -r '.risk_summary.findings[] | "\(.proto) \(.ip):\(.port) [\(.level)] \(.tag)"'

# guardar el progreso en un log y el informe en un fichero:
python3 netspectre.py --plain --json -t 10.0.0.0/24 2>scan.log >informe.json

# restringir el conjunto de puertos TCP desde la CLI (sin tocar el perfil):
python3 netspectre.py --plain --json -t 192.168.1.10 --ports 22,445,6379 | jq '.open_ports'
python3 netspectre.py --plain -t 10.0.0.5 --ports 8000-8100

# incluir la auditoría UDP en la tubería (bare --udp = top-24; o un spec):
python3 netspectre.py --plain --json -t 192.168.1.1 --udp | jq '.udp'
python3 netspectre.py --plain --json -t 192.168.1.1 --udp 53,123,161 | jq '.udp'

# auditoría completa TCP+UDP, filtrando hallazgos con su remedio:
python3 netspectre.py --plain --json -t 10.0.0.0/24 --udp \
  | jq -r '.risk_summary.findings[] | "\(.proto)/\(.port) [\(.level)] \(.tag): \(.fix)"'
```

`--json` sin `--plain` es un error (sería ambiguo con el REPL).

### 🚧 Puerta de riesgo para CI (`max_high` / `max_medium`)

En `--plain`, los límites de severidad convierten a NetSpectre en un gate
de seguridad: si los hallazgos superan los límites, imprime el motivo y
**sale con código 1** para que tu pipeline falle. Se fijan por CLI o dentro
de un perfil (se guardan con `profile save` como el resto de opciones):

```bash
# gate por CLI: cero tolerancia a SMB/telnet/redis expuestos
python3 netspectre.py --plain -t 10.0.0.0/24 --max-high 0

# con UDP e informe JSON en la tubería (el JSON sale igual; el exit code decide el CI)
python3 netspectre.py --plain --json -t 10.0.0.0/24 --udp --max-high 2 --max-medium 5 \
  > informe.json; echo "gate exit=$?"

# perfil 'ci-gate' con los límites guardados (ver 'set max_high')
python3 netspectre.py --plain --profile ci-gate -t 10.0.0.0/24
```

Salida al fallar:

```text
  [x] risk gate FAILED — high findings: 1 > limit 0
  [x] audit does not pass the configured severity thresholds (exit 1)
```

`off` desactiva un límite; los flags CLI tienen prioridad sobre el perfil.

### 🚩 Informe de riesgo (`risks`)

Consolida los hallazgos TCP + UDP de la última auditoría en una sola tabla
ordenada por severidad (HIGH primero), con el motivo de cada exposición y el
host más expuesto puntuado (high=2, med=1) para priorizar la remediación:

```text
risks               # todos los hallazgos
risks high          # solo severidad alta
risks medium        # solo severidad media
```

```text
┌────────────────── RISK REPORT — ALL (4 FINDING(S)) ───────────────────┐
  SEV      HOST              PORT       SERVICE         REASON
  HIGH     192.168.31.1      69/udp     tftp            TFTP: no auth, no encryption...
           ↳ fix: disable unless essential; chroot with read-only dirs; restrict source IPs
  HIGH     192.168.31.1      445/tcp    microsoft-ds    SMB: EternalBlue/WannaCry vector...
           ↳ fix: disable SMBv1, keep patched, require signing, restrict with host firewall
  MED      192.168.31.1      137/udp    netbios-ns      NetBIOS name service: leaks...
           ↳ fix: disable NetBIOS over TCP/IP if unused; block 137-139 outbound/inbound
  [!] most exposed host: 192.168.31.1 (risk score 6) — prioritize remediation there
```

#### Exportar a Markdown / CSV para ticketing

```text
risks md                        # informe Markdown con fecha en el nombre
risks md high solo-criticos.md  # filtrado, con nombre propio
risks csv                       # CSV plano: severity,ip,port,proto,service,tag,reason,fix,evidence
risks csv medium tickets.csv
```

El **Markdown** incluye resumen tabular + una sección por hallazgo con motivo,
remediación, evidencia y casilla `- [ ] Remediado` (lista para pegar en un
ticket y marcar el avance). El **CSV** usa el módulo `csv` de Python (escapes
correctos) e import directo en Excel/Sheets/Jira.

Cada hallazgo incluye una **remediación concreta** (línea `↳ fix:`) del
catálogo `REMEDIATIONS` de netspectre.py: p. ej. `requirepass` + bind local
para Redis, unix socket o TLS con client certs para la API de Docker, SNMPv3
authPriv sin comunidades `public`/`private`, `restrict default noquery` en
NTP, SMBv1 desactivado con firmas requeridas… El mismo texto viaja en el
campo `fix` de cada finding del informe JSON (`save` y `--plain --json`),
listo para generar tareas en tu gestor de incidencias.

### Opciones de `set`

| Opción | Valores | Descripción |
|---|---|---|
| `target` | CIDR o IP | Objetivo de la sesión, ej. `set target 192.168.1.0/24` |
| `port_range` | `top100`, `all`, lista/rango | Rango usado por `ports` |
| `host_timeout` | 0.05 – 10 s | Timeout por sonda en descubrimiento (def. `0.5s`) |
| `port_timeout` | 0.05 – 10 s | Timeout por sonda de puerto (def. `1.0s`) |
| `workers` | 1 – 1024 | Hilos para descubrimiento de hosts (def. `128`) |
| `port_workers` | 1 – 2048 | Hilos para auditoría de puertos (def. `256`) |
| `udp_timeout` | 0.5 – 15 s | Timeout por sonda UDP (def. `2.0s`) |
| `udp_workers` | 1 – 1024 | Hilos para la auditoría UDP (def. `128`) |
| `udp_range` | `top`, `all`, lista/rango | Rango usado por `udp` |
| `max_high` | 0, 1, 2… o `off` | Puerta CI: falla (`--plain` → `exit 1`) si hay más high findings que este límite |
| `max_medium` | 0, 1, 2… o `off` | Igual para hallazgos medium |
| `ping_sweep` | `on` / `off` | Barrido ICMP previo — **requiere root/Administrador** |

---

## 🧪 Ejemplo de sesión completa

```text
$ python3 netspectre.py
netspectre (no target) > set target 192.168.1.0/24
netspectre (192.168.1.0/24) > hosts
  [✓] 192.168.1.1     up — router.local · F8:66:C2:11:22:33 (TP-Link)
  [✓] 192.168.1.77    up — raspberrypi.local · DC:A6:32:DE:AD:01 (Raspberry Pi)
  [+] escaneo completado en 2.1s — 2 host(s) activos de 254

netspectre (192.168.1.0/24) > ports
  [✓] 192.168.1.1     53/tcp     domain
  [✓] 192.168.1.1     80/tcp     http           HTTP/1.1 200 OK
  [✓] 192.168.1.77    22/tcp     ssh            SSH-2.0-OpenSSH_9.2p1
  [✓] 192.168.1.77    445/tcp    microsoft-ds   [RISK:smb]
  [✓] 192.168.1.150   6379/tcp   redis          [RISK:redis]

netspectre (192.168.1.0/24) > udp 192.168.1.1 53,137
  [✓] 192.168.1.1     53/udp      domain          dns-response (0 answer(s))
  [✓] 192.168.1.1     137/udp     netbios-ns      [warn:netbios] netbios-response
  [+] UDP audit complete — 2 confirmed open, 0 open|filtered

netspectre (192.168.1.0/24) > save
  [✓] informe guardado en netspectre-report-20260906-213000.json (2 host(s), 5 puerto(s))
  [!] incluye resumen de riesgo: 2 high, 0 medium finding(s)
netspectre (192.168.1.0/24) > exit
```

El informe `save` genera un JSON con hosts (IP, hostname, MAC, fabricante) y
puertos abiertos (puerto, servicio, banner), listo para archivar o procesar.

---

## 🔬 Cómo funciona por dentro

- **Descubrimiento de hosts** — sondeo TCP `connect()` en paralelo (hilos) contra
  los puertos 80/443/22/445 de cada IP del CIDR. Opcionalmente un ping ICMP raw
  (`set ping_sweep on`) previo a la sonda TCP.
- **Auditoría de puertos** — `connect()` por puerto; distingue `open` /
  `closed` / `filtered` por código de error del socket. Los puertos del
  catálogo de riesgo (`RISK_PORTS`) se marcan con insignias y alimentan el
  resumen priorizado y el bloque `risk_summary` del informe JSON.
- **Captura de banners** — en puertos que hablan primero (SSH, FTP, SMTP…)
  lee la respuesta; en HTTP plano envía un `HEAD /` para el header `Server`.
  En puertos TLS (443, 8443…) no envía texto plano — solo marca el estado.
- **Auditoría UDP** — datagramas con payloads por servicio (DNS, NTP, SNMP,
  NetBIOS, SSDP…); clasifica `open` por respuesta válida, `closed` por ICMP
  port-unreachable y `open|filtered` ante el silencio (semántica nmap), con
  reintentos cortos para mitigar rate-limiting de algunos firewalls.
- **ARP y fabricante** — lee la caché ARP del sistema (`ip neigh` / `arp -a`) y
  mapea el prefijo MAC contra una tabla OUI reducida (Raspberry Pi, VMware,
  Apple, TP-Link, Espressif, …).
- **IP local** — se detecta con un socket UDP "conectado" a 8.8.8.8: no se
  envía ningún paquete.

## ⚡ Rendimiento

Un /24 con los valores por defecto tarda ~2-4 s en descubrimiento y ~2-4 s la
auditoría top100 por host vivo. Sube `workers`/`port_workers` o baja los
timeouts en redes rápidas; súbelos en WiFi saturadas o con hosts que descartan
paquetes (estados `filtered`).

## 📂 Estructura del proyecto

```text
netspectre.py          # la herramienta completa (solo librería estándar)
http_fingerprinter.py  # motor async de fingerprinting HTTP (v2.0, requiere aiohttp)
requirements.txt       # dependencia opcional para el fingerprinting
pyproject.toml         # empaquetado pip/pipx (extra opcional [fingerprint])
index.html             # demo web interactiva del REPL (motor simulado, sin paquetes reales)
guide.html             # guía visual de comandos
.github/workflows/     # CI: pruebas con y sin aiohttp (Python 3.11/3.13)
README.md
```

---

## ⚠️ Recordatorio final

Escanear sistemas ajenos sin permiso es delito en la mayoría de países
(lect. del art. 197 CP en España, Computer Fraud and Abuse Act en EE. UU.,
etc.). NetSpectre se ofrece tal cual, con fines **educativos y de auditoría
autorizada**. Eres responsable de cómo lo usas.
