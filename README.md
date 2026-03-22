# FirmaRED — Sistema de Firma Digital de Viáticos
## Subsecretaría de Inspección del Trabajo — Provincia de Buenos Aires

---

## Requisitos

- **Node.js 18 o superior** — https://nodejs.org (descargar instalador LTS)
- Cualquier sistema operativo: Windows, Linux, macOS

---

## Instalación (5 minutos)

### 1. Copiar los archivos al servidor

Copiar toda esta carpeta `firmared/` al servidor donde va a correr el sistema.

### 2. Instalar dependencias

```bash
cd firmared
npm install
```

### 3. Iniciar el servidor

```bash
npm start
```

El servidor quedará escuchando en `http://localhost:3000`

---

## Acceso desde los inspectores

Una vez iniciado el servidor, los inspectores acceden desde cualquier dispositivo (PC, iPhone, Android, tablet) ingresando la dirección IP del servidor en el browser:

```
http://[IP-DEL-SERVIDOR]:3000
```

Por ejemplo: `http://192.168.1.100:3000`

> Si el servidor tiene dominio propio: `https://firmared.trabajo.gba.gob.ar`

---

## Credenciales de acceso

### Administradores
| Usuario | Contraseña | Perfil |
|---|---|---|
| `admin` | `admin2026` | Administrador general |
| `directora` | `dir2026` | Directora Provincial |
| `asesoria` | `ases2026` | Asesoría |

### Inspectores
- **Usuario**: inicial del primer nombre + primer apellido (minúsculas, sin tildes ni espacios)
- **Contraseña**: número de legajo

**Ejemplos:**
| Inspector | Usuario | Contraseña |
|---|---|---|
| Angulo Estrada, Yamila | `yangulo` | `601806` |
| Abalos, Christian Hernan | `cabalos` | `602455` |
| García, Juan Carlos | `jgarcia` | `601234` |

> ⚠️ **Nota sobre legajo duplicado**: Polero, Andrés (601144) y Traversa, Gonzalo (601144) comparten legajo. Verificar con RRHH cuál es el correcto antes de distribuir credenciales.

---

## Flujo de uso

### Asesoría (admin)
1. Inicia sesión con usuario `asesoria`
2. Tab **"Subir planilla"** → selecciona inspector → mes/año → sube el PDF → asigna
3. Tab **"Historial"** → ve todas las planillas firmadas

### Inspector (desde cualquier dispositivo)
1. Inicia sesión con su usuario y legajo
2. **Primera vez**: dibuja su firma en el recuadro → "Guardar firma" (queda guardada permanentemente)
3. Cuando hay planilla pendiente: toca **"Ver planilla completa"** → el PDF se abre en el visor nativo del dispositivo
4. Toca **"Confirmar y firmar planilla"** → el servidor estampa la firma → el PDF firmado se descarga automáticamente
5. El historial muestra todas las planillas firmadas con links de descarga

---

## Estructura de archivos

```
firmared/
├── server.js              ← Servidor principal (Node.js + Express)
├── package.json           ← Dependencias
├── data/
│   ├── usuarios.json      ← 207 inspectores + 3 admins
│   ├── historial.json     ← Registro de firmas
│   └── planillas_asignadas.json  ← Planillas subidas
├── planillas/             ← PDFs originales subidos por la asesoría
├── firmadas/              ← PDFs con firma estampada
└── public/
    └── index.html         ← Interfaz de usuario
```

---

## Configuración avanzada

### Cambiar el puerto
```bash
PORT=8080 npm start
```

### Producción con HTTPS (recomendado para acceso externo)

Para producción real con HTTPS, instalar **nginx** como proxy inverso o usar **Let's Encrypt** para SSL. Ejemplo de configuración nginx:

```nginx
server {
    listen 443 ssl;
    server_name firmared.trabajo.gba.gob.ar;
    ssl_certificate /etc/letsencrypt/live/.../fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/.../privkey.pem;
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
    }
}
```

### Mantener el servidor activo con PM2
```bash
npm install -g pm2
pm2 start server.js --name firmared
pm2 startup   # para que arranque al reiniciar el servidor
pm2 save
```

---

## Coordenadas de firma (planilla PBA)

Las coordenadas están calibradas para el formulario oficial de viáticos del Ministerio de Trabajo PBA (página A4-legal, 612 × 1008 pts):

- **Zona 1 — "Firma del agente"**: centrada en línea x=78.2–209.6, y=215.8 desde abajo
- **Zona 2 — "Firma del agente y N° de DNI"**: centrada en línea x=243.5–375.0, y=91.5 desde abajo

Si el formulario cambia, editar las coordenadas en `server.js` función `stamparFirma()`.

---

## Soporte

En caso de problemas técnicos, revisar los logs en la consola donde corre `npm start`.
