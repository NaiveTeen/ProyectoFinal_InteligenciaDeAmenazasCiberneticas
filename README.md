# MGM-Shield: laboratorio DevSecOps contra vishing y ransomware

MVP para el proyecto de Inteligencia de Amenazas Cibernéticas (caso MGM Resorts).
**Todo es simulado**: empleados, IPs y datos ficticios. Úsalo solo en tu propia máquina.

## Componentes
| Ruta | Qué es |
|---|---|
| `app/helpdesk.py` | Portal de help desk. `MGM_MODE=insecure` (vulnerable) o `secure` (verificación fuera de banda + límite de intentos) |
| `monitor/monitor.py` | Monitor de IoCs (reglas R1-R6, archivos canario) + contención automática simulada |
| `lab/simulate.py` | Escenarios: `legit`, `vishing`, `ransomware` |
| `tests/` | Pruebas automáticas (pytest) |
| `.github/workflows/devsecops.yml` | Pipeline: Gitleaks, Bandit, pip-audit, pytest, Trivy, despliegue de prueba |
| `Dockerfile`, `docker-compose.yml` | Opcionales (requieren Docker) |

## Ejecutar SIN Docker (Windows PowerShell)
Requiere Python 3.10+.
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q tests

# Terminal 1: portal VULNERABLE
$env:MGM_MODE="insecure"; python -m flask --app app.helpdesk:wsgi run -p 5000
# Terminal 2: monitor
python monitor/monitor.py
# Terminal 3: escenarios
python lab/simulate.py legit
python lab/simulate.py vishing        # cuenta comprometida + alerta CRITICAL + bloqueo
python lab/simulate.py ransomware     # alerta de archivos canario + aislamiento simulado
```
En Linux/macOS: `source .venv/bin/activate` y `MGM_MODE=insecure python -m flask ...`.

**Versión defendida:** detén el portal, borra las carpetas `logs` y `canary`, arráncalo con
`$env:MGM_MODE="secure"` y repite `python lab/simulate.py vishing`: el ataque queda bloqueado.
Guarda capturas de ambas corridas: son tu evidencia para validar la hipótesis.

## Con Docker (opcional)
```
MGM_MODE=secure docker compose up --build
docker compose --profile attacker up -d attacker   # contenedor Kali
```

## Reglas del monitor
R1 reset de MFA + login desde IP nueva (CRITICAL) · R2 fuerza bruta · R3 reset fuera de horario ·
R4 resets denegados repetidos · R5 archivos canario alterados (CRITICAL) · R6 reset sin verificación.
Las alertas se guardan en `logs/alerts.jsonl` con `detection_seconds` (tu métrica de tiempo de detección).

## Pentesting (contra tu propio lab)
`nmap -sV -p- 127.0.0.1` y pruebas de los endpoints `/helpdesk/reset_mfa` y `/login` en ambos modos.
