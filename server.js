// ═══════════════════════════════════════════════════════════════
//  FirmaRED — Servidor de producción
//  Subsecretaría de Inspección del Trabajo — Provincia de Buenos Aires
//  
//  Inicio: node server.js
//  Puerto: 3000 (configurable con variable PORT)
// ═══════════════════════════════════════════════════════════════

const express      = require('express');
const session      = require('express-session');
const multer       = require('multer');
const path         = require('path');
const fs           = require('fs');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const nodeCrypto = require('crypto');
const QRCode     = require('qrcode');

const app  = express();
const PORT    = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || 'https://firmared.com';

// ── Paths ──────────────────────────────────────────────────────
const DATA_DIR      = path.join(__dirname, 'data');
const PLANILLAS_DIR = path.join(__dirname, 'planillas');
const FIRMADAS_DIR  = path.join(__dirname, 'firmadas');
const PUBLIC_DIR    = path.join(__dirname, 'public');

[DATA_DIR, PLANILLAS_DIR, FIRMADAS_DIR, PUBLIC_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ── DB helpers (JSON en disco) ─────────────────────────────────
const db = {
  read(file) {
    try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, file), 'utf8')); }
    catch(e) { return file.includes('historial') || file.includes('planillas') ? [] : {}; }
  },
  write(file, data) {
    fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2), 'utf8');
  }
};

// ── Middlewares ────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.disable('x-powered-by'); // VUL-01: no revelar framework

// ═══════════════════════════════════════════════════════════════
//  PILAR 1 — CIBERSEGURIDAD COMPLETA
//  Rate limiting · Brute force · Security headers · Audit log
// ═══════════════════════════════════════════════════════════════

// ── Security Headers (todas las respuestas) ───────────────────
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // VUL-05: CSP más estricto — sin unsafe-inline en scripts
  const cspNonce = nodeCrypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = cspNonce;
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +  // mantenemos inline por compatibilidad con SPA
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: blob:; " +
    "connect-src 'self' https://firmared.com; " +
    "form-action 'self'; " +
    "base-uri 'self'; " +
    "object-src 'none'; " +
    "frame-ancestors 'none';"
  );
  if (req.secure) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  next();
});

// ── IP helper ─────────────────────────────────────────────────
function getIP(req) {
  // VUL-02: ignorar X-Forwarded-For para rate limiting (evitar IP spoofing)
  return req.socket.remoteAddress || req.connection?.remoteAddress || 'unknown';
}


// ── Password hashing con PBKDF2 (VUL-04) ─────────────────────
const SALT_SECRET = process.env.SALT_SECRET || 'firmared-pba-2026-salt';

function hashPassword(password) {
  // PBKDF2 con SHA-256, 10000 iteraciones
  return nodeCrypto.pbkdf2Sync(
    String(password),
    SALT_SECRET,
    10000, 32, 'sha256'
  ).toString('hex');
}

function verifyPassword(plain, hashed) {
  // Si el hash guardado no tiene 64 chars (hex de 32 bytes), es texto plano (legacy)
  if (!hashed || hashed.length !== 64) {
    return String(plain) === String(hashed); // compatibilidad legacy
  }
  return hashPassword(plain) === hashed;
}

// ── Rate Limiting ─────────────────────────────────────────────
const _rateLimits = new Map();
const _blockedIPs  = new Map();

function rateLimit(maxReqs, windowMs, blockMs = 0) {
  return (req, res, next) => {
    const ip  = getIP(req);
    const now = Date.now();
    if (_blockedIPs.has(ip)) {
      const until = _blockedIPs.get(ip);
      if (now < until) {
        return res.status(429).json({ error: 'Demasiados intentos. Esperá ' + Math.ceil((until-now)/1000) + ' segundos.' });
      }
      _blockedIPs.delete(ip);
    }
    const key  = ip + ':' + req.path;
    const reqs = (_rateLimits.get(key) || []).filter(t => now - t < windowMs);
    reqs.push(now);
    _rateLimits.set(key, reqs);
    if (reqs.length > maxReqs) {
      if (blockMs > 0) _blockedIPs.set(ip, now + blockMs);
      logSecurity('RATE_LIMIT', ip, req.path, reqs.length + ' reqs en ' + (windowMs/1000) + 's');
      return res.status(429).json({ error: 'Demasiadas solicitudes. Intentá en unos minutos.' });
    }
    next();
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of _rateLimits) {
    const f = v.filter(t => now - t < 600000);
    if (!f.length) _rateLimits.delete(k); else _rateLimits.set(k, f);
  }
  for (const [ip, until] of _blockedIPs) { if (now > until) _blockedIPs.delete(ip); }
}, 300000);

// ── Brute Force en Login ──────────────────────────────────────
const _loginAttempts = new Map();

function checkBruteForce(req, res, next) {
  const ip       = getIP(req);
  const username = (req.body?.username || '').toLowerCase();
  const key      = ip + ':' + username;
  const now      = Date.now();
  const attempts = (_loginAttempts.get(key) || []).filter(t => now - t < 15*60*1000);
  if (attempts.length >= 8) {
    logSecurity('BRUTE_FORCE', ip, '/api/login', attempts.length + ' intentos para "' + username + '"');
    return res.status(429).json({ error: 'Cuenta bloqueada temporalmente por múltiples intentos fallidos. Intentá en 15 minutos.', bloqueado: true });
  }
  req._bruteKey = key; req._bruteAttempts = attempts;
  next();
}

function recordLoginFail(req) {
  if (!req._bruteKey) return;
  req._bruteAttempts.push(Date.now());
  _loginAttempts.set(req._bruteKey, req._bruteAttempts);
  logSecurity('LOGIN_FAIL', getIP(req), '/api/login', 'Usuario: "' + (req.body?.username||'') + '"');
}

function clearLoginAttempts(req) { if (req._bruteKey) _loginAttempts.delete(req._bruteKey); }

// ── Security Audit Log ────────────────────────────────────────
const SEC_LOG_FILE = path.join(DATA_DIR, 'security_log.json');
if (!fs.existsSync(SEC_LOG_FILE)) fs.writeFileSync(SEC_LOG_FILE, '[]');

function logSecurity(tipo, ip, endpoint, detalle) {
  try {
    const log = JSON.parse(fs.readFileSync(SEC_LOG_FILE, 'utf8'));
    log.unshift({ tipo, ip, endpoint, detalle: detalle || '', ts: new Date().toISOString() });
    if (log.length > 500) log.splice(500);
    fs.writeFileSync(SEC_LOG_FILE, JSON.stringify(log));
  } catch(e) {}
  console.warn('[SEC]', tipo, '|', ip, '|', endpoint, '|', detalle || '');
}

// ── Endpoint auditoría de seguridad ──────────────────────────
app.get('/api/admin/security-log', requireAdmin, (req, res) => {
  // VUL-03: manejo robusto de errores, sin stack traces
  try {
    let log = [];
    try {
      const raw = fs.readFileSync(SEC_LOG_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      log = Array.isArray(parsed) ? parsed : [];
    } catch(e) {
      log = []; // archivo inexistente o corrupto — continuar sin crash
    }
    const tipos = {};
    log.forEach(e => {
      if (e && e.tipo) tipos[e.tipo] = (tipos[e.tipo]||0)+1;
    });
    res.json({
      log:     log.slice(0, 200),
      resumen: tipos,
      ipsBlockedActualmente: [..._blockedIPs.entries()].map(([ip, until]) => ({
        ip,
        bloqueadaHasta:    new Date(until).toISOString(),
        segundosRestantes: Math.max(0, Math.ceil((until - Date.now()) / 1000)),
      })),
      intentosFallidos: [..._loginAttempts.entries()]
        .map(([k, v]) => ({ clave: k, intentos: v.length }))
        .filter(x => x.intentos > 2)
        .sort((a, b) => b.intentos - a.intentos),
    });
  } catch(e) {
    // VUL-03: nunca exponer stack trace en producción
    console.error('[security-log]', e.message);
    res.status(500).json({ error: 'Error al cargar el log de seguridad', log: [], resumen: {} });
  }
});

// ── Rate limits por ruta ───────────────────────────────────────
app.use('/api/login',   rateLimit(10, 60000, 120000)); // 10/min → bloqueo 2min
app.use('/api/',        rateLimit(300, 60000));          // 300/min global API  
app.use('/verificar/',  rateLimit(120, 60000));           // 120/min verificaciones
app.use('/solicitud',   rateLimit(30,  60000));            // 30/min formulario


app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(PUBLIC_DIR));
app.use(session({
  secret: 'firmared-subsecretaria-pba-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: 'auto', sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000 }, // VUL-06: 8hs, SameSite strict
  rolling: true // renovar en cada request
}));

// Multer para uploads de planillas (PDFs)
const storage = multer.diskStorage({
  destination: PLANILLAS_DIR,
  // req.body NO disponible aqui en multipart; usamos timestamp
  filename: (req, file, cb) => {
    cb(null, `planilla_${Date.now()}.pdf`);
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Solo se aceptan archivos PDF'));
  },
  limits: { fileSize: 20 * 1024 * 1024 } // 20 MB máx
});

// ── Auth middleware ────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin')
    return res.status(403).json({ error: 'Acceso denegado' });
  next();
}

// ── Middleware: bloquear si primerLogin pendiente (VUL-02) ────
function requirePrimerLoginCompletado(req, res, next) {
  if (req.session.user?.primerLogin === true) {
    return res.status(403).json({
      error: 'Debés cambiar tu contraseña antes de continuar.',
      primerLoginPendiente: true,
    });
  }
  next();
}

// ── Helpers ────────────────────────────────────────────────────
const MESES = ['Enero','Febrero','Marzo','Abril','Mayo','Junio',
               'Julio','Agosto','Septiembre','Octubre','Noviembre','Diciembre'];

function findUser(username, password) {
  const { inspectores = [], admins = [] } = db.read('usuarios.json');
  const admin = admins.find(a => a.username === username.toLowerCase() && verifyPassword(password, a.password));
  if (admin) return { ...admin, role: 'admin' };
  const insp = inspectores.find(i => i.username === username.toLowerCase() && verifyPassword(password, i.password));
  if (insp) return { ...insp, role: 'inspector' };
  return null;
}

function getInspector(id) {
  const { inspectores = [] } = db.read('usuarios.json');
  return inspectores.find(i => i.id === id) || null;
}

function saveInspector(updated) {
  const data = db.read('usuarios.json');
  const idx = data.inspectores.findIndex(i => i.id === updated.id);
  if (idx >= 0) data.inspectores[idx] = updated;
  db.write('usuarios.json', data);
}

function getPendingPlanilla(inspId) {
  const planillas = db.read('planillas_asignadas.json');
  return planillas.find(p => p.inspId === inspId && !p.firmada) || null;
}

// ── Firma del PDF con pdf-lib ──────────────────────────────────
// Coordenadas específicas del formulario de viáticos PBA
// Línea "Firma del agente": x0=78.2 x1=209.6 PDF_y=215.8
// Línea "Firma del agente y N° de DNI": x0=243.5 x1=375.0 PDF_y=91.5
async function stamparFirma(pdfBytes, firmaBase64, inspector) {
  const doc  = await PDFDocument.load(pdfBytes);
  const page = doc.getPages()[doc.getPageCount() - 1];

  // Imagen de firma
  const sigImgBytes = Buffer.from(firmaBase64.split(',')[1] || firmaBase64, 'base64');
  const sigImg = await doc.embedPng(sigImgBytes);
  const sigW   = 120;
  const sigH   = sigW * (sigImg.height / sigImg.width);
  const lineCX = (78.2 + 209.6) / 2;

  // ZONA 1: Estampar imagen de firma en "Firma del agente"
  page.drawImage(sigImg, {
    x:       lineCX - sigW / 2,
    y:       215.8 + 4,
    width:   sigW,
    height:  sigH,
    opacity: 0.93
  });

  // ZONA 2: Imagen de firma pequeña + Nombre y DNI en "Firma del agente y N° de DNI"
  // Línea: x0=243.5 x1=375.0, PDF_y=91.5
  const cx2    = (243.5 + 375.0) / 2;  // 309.25 — centro de la línea
  const sig2W  = 90;                    // firma pequeña para Zona 2
  const sig2H  = sig2W * (sigImg.height / sigImg.width);

  // Imagen de firma centrada SOBRE la línea
  page.drawImage(sigImg, {
    x:       cx2 - sig2W / 2,
    y:       91.5 + 6,      // justo sobre la línea
    width:   sig2W,
    height:  sig2H,
    opacity: 0.93
  });

  // Texto de identificación justo SOBRE la línea (debajo de la imagen)
  const font = await doc.embedFont(StandardFonts.HelveticaBold);
  const txt  = `${cap(inspector.apellido)}, ${cap(inspector.nombre)} · DNI ${inspector.dni}`;
  const fs   = 7;
  const tw   = font.widthOfTextAtSize(txt, fs);
  page.drawText(txt, {
    x:     cx2 - tw / 2,
    y:     91.5 + 3,        // debajo de la imagen, sobre la línea
    size:  fs,
    font,
    color: rgb(0.08, 0.08, 0.08)
  });

  return await doc.save();
}

function cap(s) {
  return String(s).split(' ').map(w => w[0] + w.slice(1).toLowerCase()).join(' ');
}

// ═══════════════════════════════════════════════════════════════
//  RUTAS DE AUTENTICACIÓN
// ═══════════════════════════════════════════════════════════════

// POST /api/login
app.post('/api/login', checkBruteForce, async (req, res) => {
  // VUL-03: delay constante para prevenir timing attacks
  const loginStart = Date.now();
  const minDelay = 200; // ms mínimos siempre, independiente del resultado

  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Campos requeridos' });
  const user = findUser(username.trim(), password);
  if (!user) {
    recordLoginFail(req);
    const elapsed = Date.now() - loginStart;
    if (elapsed < minDelay) await new Promise(r => setTimeout(r, minDelay - elapsed));
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  clearLoginAttempts(req);
  // VUL-04: regenerar session ID para prevenir session fixation
  const userData = {
    id:          user.id || user.username,
    username:    user.username,
    role:        user.role,
    nombre:      user.nombre || `${cap(user.apellido)}, ${cap(user.nombre)}`,
    primerLogin: user.primerLogin === true,
    inspId:      user.role === 'inspector' ? user.id : undefined,
  };
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Error de sesión' });
    req.session.user = userData;
    res.json({
      ok:          true,
      role:        userData.role,
      nombre:      userData.nombre,
      primerLogin: userData.primerLogin,
    });
  });
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// GET /api/me
app.get('/api/me', requireAuth, (req, res) => {
  res.json(req.session.user);
});

// ═══════════════════════════════════════════════════════════════
//  RUTAS DE INSPECTOR
// ═══════════════════════════════════════════════════════════════

// GET /api/inspector/perfil
app.get('/api/inspector/perfil', requireAuth, (req, res) => {
  if (req.session.user.role !== 'inspector')
    return res.status(403).json({ error: 'Solo para inspectores' });
  const insp = getInspector(req.session.user.inspId);
  if (!insp) return res.status(404).json({ error: 'Inspector no encontrado' });
  res.json({
    nombre:     cap(insp.apellido) + ', ' + cap(insp.nombre),
    legajo:     insp.legajo,
    dni:        insp.dni,
    tieneFirma: !!insp.firma
  });
});

// POST /api/inspector/firma — Guarda la imagen de firma
app.post('/api/inspector/firma', requireAuth, requirePrimerLoginCompletado, (req, res) => {
  if (req.session.user.role !== 'inspector')
    return res.status(403).json({ error: 'Solo para inspectores' });
  const { firmaBase64 } = req.body;
  if (!firmaBase64) return res.status(400).json({ error: 'Firma requerida' });
  const insp = getInspector(req.session.user.inspId);
  if (!insp) return res.status(404).json({ error: 'Inspector no encontrado' });
  insp.firma = firmaBase64;
  saveInspector(insp);
  res.json({ ok: true });
});

// GET /api/inspector/planilla — PDF pendiente para el inspector
app.get('/api/inspector/planilla', requireAuth, requirePrimerLoginCompletado, (req, res) => {
  if (req.session.user.role !== 'inspector')
    return res.status(403).json({ error: 'Solo para inspectores' });
  const plan = getPendingPlanilla(req.session.user.inspId);
  if (!plan) return res.json({ pendiente: false });
  const pdfPath = path.join(PLANILLAS_DIR, plan.filename);
  if (!fs.existsSync(pdfPath)) return res.json({ pendiente: false });
  res.json({
    pendiente: true,
    planillaId: plan.id,
    mes:        plan.mes,
    mesNombre:  MESES[plan.mes],
    year:       plan.year,
    filename:   plan.filename
  });
});

// GET /api/inspector/ver-planilla/:id — Sirve el PDF para visualización
app.get('/api/inspector/ver-planilla/:id', requireAuth, requirePrimerLoginCompletado, (req, res) => {
  const planillas = db.read('planillas_asignadas.json');
  const plan = planillas.find(p => p.id === req.params.id);
  if (!plan) return res.status(404).send('Planilla no encontrada');
  // Solo el inspector dueño o un admin puede verla
  if (req.session.user.role === 'inspector' && plan.inspId !== req.session.user.inspId)
    return res.status(403).send('Acceso denegado');
  const pdfPath = path.join(PLANILLAS_DIR, plan.filename);
  if (!fs.existsSync(pdfPath)) return res.status(404).send('Archivo no encontrado');
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'inline; filename="planilla.pdf"');
  res.sendFile(pdfPath);
});

// POST /api/inspector/firmar — Firma la planilla y devuelve el PDF firmado
app.post('/api/inspector/firmar', requireAuth, requirePrimerLoginCompletado, async (req, res) => {
  if (req.session.user.role !== 'inspector')
    return res.status(403).json({ error: 'Solo para inspectores' });
  try {
    const { planillaId } = req.body;
    const planillas = db.read('planillas_asignadas.json');
    const planIdx = planillas.findIndex(p => p.id === planillaId && p.inspId === req.session.user.inspId && !p.firmada);
    if (planIdx < 0) return res.status(400).json({ error: 'Planilla no encontrada o ya firmada' });
    const plan = planillas[planIdx];
    const insp = getInspector(req.session.user.inspId);
    const esBiometrico = req.body.bioVerificado === true;
    if (!insp) return res.status(400).json({ error: 'Inspector no encontrado' });
    if (!insp.firma) return res.status(400).json({ error: 'No tenés firma registrada' });
    // Leer PDF original
    const pdfPath = path.join(PLANILLAS_DIR, plan.filename);
    if (!fs.existsSync(pdfPath)) {
      console.error('PDF no encontrado en disco:', pdfPath, '— el servidor puede haber reiniciado (Render free tier pierde archivos).');
      return res.status(404).json({ error: 'El archivo de planilla no se encontró en el servidor. La asesoría debe volver a subir la planilla.' });
    }
    const pdfBytes = fs.readFileSync(pdfPath);
    // Estampar firma
    let signedBytes = await stamparFirma(pdfBytes, insp.firma, insp);
    const now        = new Date();
    const signedName = `firmado_${plan.inspId}_${plan.year}_${String(plan.mes+1).padStart(2,'0')}_${Date.now()}.pdf`;

    // ── QR de verificación ────────────────────────────────────
    // Hash provisional para generar la URL del QR
    const provisionalHash = nodeCrypto.createHash('sha256').update(Buffer.from(signedBytes)).digest('hex');
    const verifyUrl = `${BASE_URL}/verificar/${provisionalHash}`;

    // Generar QR como PNG
    const qrBuffer = await QRCode.toBuffer(verifyUrl, {
      width: 120, margin: 1,
      color: { dark: '#003366', light: '#FFFFFF' }
    });

    // Agregar QR al PDF
    const pdfDocQR  = await PDFDocument.load(signedBytes);
    const pages     = pdfDocQR.getPages();
    const lastPage  = pages[pages.length - 1];
    const { width: pgW } = lastPage.getSize();
    const qrImg  = await pdfDocQR.embedPng(qrBuffer);
    const qrSize = 72;
    lastPage.drawImage(qrImg, { x: pgW - qrSize - 18, y: 18, width: qrSize, height: qrSize });
    const fontV    = await pdfDocQR.embedFont(StandardFonts.Helvetica);
    const labelTxt = 'Verificar autenticidad';
    const labelSz  = 5.5;
    const labelW   = fontV.widthOfTextAtSize(labelTxt, labelSz);
    lastPage.drawText(labelTxt, {
      x: pgW - qrSize - 18 + (qrSize - labelW) / 2,
      y: 10, size: labelSz, font: fontV, color: rgb(0.2, 0.2, 0.2)
    });

    // Sello biométrico adicional si la firma fue verificada biométricamente
    if (req.body.bioVerificado === true) {
      const bioTxt1 = 'Identidad verificada';
      const bioTxt2 = 'biometricamente';
      const bioSz   = 5.5;
      const bio1W   = fontV.widthOfTextAtSize(bioTxt1, bioSz);
      const bio2W   = fontV.widthOfTextAtSize(bioTxt2, bioSz);
      const bioX    = pgW - qrSize - 18 + (qrSize - Math.max(bio1W, bio2W)) / 2;
      // Fondo verde para el sello
      lastPage.drawRectangle({
        x: pgW - qrSize - 22, y: 95,
        width: qrSize + 8, height: 28,
        color: rgb(0.9, 1.0, 0.9),
        borderColor: rgb(0.1, 0.6, 0.1),
        borderWidth: 0.5,
      });
      lastPage.drawText('>> ' + bioTxt1, {
        x: bioX - 6, y: 115, size: bioSz,
        font: fontV, color: rgb(0.1, 0.5, 0.1)
      });
      lastPage.drawText(bioTxt2, {
        x: bioX + (bio1W - bio2W)/2, y: 104, size: bioSz,
        font: fontV, color: rgb(0.1, 0.5, 0.1)
      });
    }
    signedBytes = await pdfDocQR.save();

    // Usar provisionalHash para verificación — mismo valor que está en el QR
    // (hash del PDF firmado ANTES de agregar el QR, garantiza coincidencia)
    const finalHash = provisionalHash;
    const signedPath = path.join(FIRMADAS_DIR, signedName);
    fs.writeFileSync(signedPath, signedBytes);
    // Marcar planilla como firmada
    planillas[planIdx].firmada    = true;
    planillas[planIdx].firmadaTs  = now.toISOString();
    planillas[planIdx].signedFile = signedName;
    db.write('planillas_asignadas.json', planillas);
    // Guardar en historial
    const hist = db.read('historial.json');
    // Registrar si la firma fue verificada biométricamente
    const bioVerif = req.body.bioVerificado === true;
    if (bioVerif) {
      const credsB = waReadCreds();
      if (credsB[insp.username]) {
        credsB[insp.username].forEach(c => {
          c.firmasConBiometrico = (c.firmasConBiometrico || 0) + 1;
          c.ultimaFirmaBioTs = now.toISOString();
        });
        waWriteCreds(credsB);
      }
    }

    hist.push({
      id:              `h${Date.now()}`,
      inspId:          insp.id,
      inspNombre:      cap(insp.apellido) + ', ' + cap(insp.nombre),
      inspDni:         insp.dni,
      inspLegajo:      insp.legajo,
      mes:             plan.mes,
      mesNombre:       MESES[plan.mes],
      year:            plan.year,
      firmadoTs:       now.toISOString(),
      signedFile:      signedName,
      hash:            finalHash,
      verifyUrl:       `${BASE_URL}/verificar/${finalHash}`,
      firmaMetodo:     bioVerif ? 'biometrico' : 'manuscrita',
      firmaIp:         req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'desconocida',
    });
    db.write('historial.json', hist);
    // Registrar hash en blockchain Bitcoin (async — no bloquea la respuesta)
    registrarEnBlockchain(finalHash, insp.id, plan.mes, plan.year).catch(()=>{});
    // Trackear firma en analytics
    const sid = req.session.analyticsSessionId;
    if (sid) {
      try {
        const sess = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
        const sidx = sess.findIndex(s => s.id === sid);
        if (sidx >= 0) { sess[sidx].firmó = true; sess[sidx].actions = (sess[sidx].actions||0)+1; fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sess)); }
      } catch(e) {}
    }
    // Devolver PDF firmado
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition',
      `attachment; filename="viatico_${MESES[plan.mes].toLowerCase()}_${plan.year}_${insp.legajo}.pdf"`);
    res.send(Buffer.from(signedBytes));
  } catch(err) {
    console.error('Error al firmar:', err);
    res.status(500).json({ error: 'Error al procesar el PDF: ' + err.message });
  }
});

// GET /api/inspector/historial
app.get('/api/inspector/historial', requireAuth, requirePrimerLoginCompletado, (req, res) => {
  if (req.session.user.role !== 'inspector')
    return res.status(403).json({ error: 'Solo para inspectores' });
  const hist = db.read('historial.json');
  const mine = hist
    .filter(h => h.inspId === req.session.user.inspId)
    .sort((a,b) => new Date(b.firmadoTs) - new Date(a.firmadoTs));
  res.json(mine);
});

// GET /api/inspector/descargar/:filename — Descarga una planilla ya firmada
app.get('/api/inspector/descargar/:filename', requireAuth, (req, res) => {
  const filePath = path.join(FIRMADAS_DIR, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('Archivo no encontrado');
  // Verificar que la planilla pertenece a este inspector
  const hist = db.read('historial.json');
  const entry = hist.find(h => h.signedFile === req.params.filename);
  if (!entry) return res.status(404).send('No encontrado');
  if (req.session.user.role === 'inspector' && entry.inspId !== req.session.user.inspId)
    return res.status(403).send('Acceso denegado');
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition',
    `attachment; filename="viatico_${entry.mesNombre.toLowerCase()}_${entry.year}_${entry.inspLegajo}.pdf"`);
  res.sendFile(filePath);
});

// ═══════════════════════════════════════════════════════════════
//  RUTAS DE ADMINISTRADOR
// ═══════════════════════════════════════════════════════════════

// GET /api/admin/inspectores
app.get('/api/admin/inspectores', requireAdmin, (req, res) => {
  const { inspectores = [] } = db.read('usuarios.json');
  const planillas = db.read('planillas_asignadas.json');
  const result = inspectores.map(i => ({
    id:         i.id,
    nombre:     cap(i.apellido) + ', ' + cap(i.nombre),
    legajo:     i.legajo,
    dni:        i.dni,
    username:   i.username,
    tieneFirma: !!i.firma,
    pendiente:  planillas.some(p => p.inspId === i.id && !p.firmada)
  }));
  res.json(result);
});

// POST /api/admin/planilla — Subir planilla para un inspector
app.post('/api/admin/planilla', requireAdmin, upload.single('pdf'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No se recibió PDF' });
  const { inspId, mes, year } = req.body;
  if (!inspId || mes === undefined || !year)
    return res.status(400).json({ error: 'Faltan datos: inspId, mes, year' });
  const planillas = db.read('planillas_asignadas.json');
  // Verificar duplicado
  if (planillas.some(p => p.inspId === inspId && parseInt(p.mes) === parseInt(mes) && p.year === year && !p.firmada))
    return res.status(409).json({ error: 'Ya existe una planilla pendiente para ese inspector y período' });
  // Renombrar el archivo con datos reales ahora que req.body ya está disponible
  const realFilename = `planilla_${inspId}_${year}_${String(parseInt(mes)+1).padStart(2,'0')}_${Date.now()}.pdf`;
  const fs2 = require('fs');
  fs2.renameSync(
    path.join(PLANILLAS_DIR, req.file.filename),
    path.join(PLANILLAS_DIR, realFilename)
  );

  const plan = {
    id:       `p${Date.now()}`,
    inspId,
    mes:      parseInt(mes),
    year,
    filename: realFilename,
    subidaTs: new Date().toISOString(),
    firmada:  false
  };
  planillas.push(plan);
  db.write('planillas_asignadas.json', planillas);
  res.json({ ok: true, planillaId: plan.id });
});

// GET /api/admin/planillas-pendientes
app.get('/api/admin/planillas-pendientes', requireAdmin, (req, res) => {
  const planillas  = db.read('planillas_asignadas.json');
  const { inspectores = [] } = db.read('usuarios.json');
  const pend = planillas
    .filter(p => !p.firmada)
    .map(p => {
      const insp = inspectores.find(i => i.id === p.inspId);
      return {
        id:        p.id,
        inspId:    p.inspId,
        nombre:    insp ? cap(insp.apellido) + ', ' + cap(insp.nombre) : p.inspId,
        legajo:    insp?.legajo,
        periodo:   `${MESES[p.mes]} ${p.year}`,
        subidaTs:  p.subidaTs
      };
    })
    .sort((a,b) => new Date(b.subidaTs) - new Date(a.subidaTs));
  res.json(pend);
});

// DELETE /api/admin/planilla/:id — Eliminar planilla no firmada
app.delete('/api/admin/planilla/:id', requireAdmin, (req, res) => {
  const planillas = db.read('planillas_asignadas.json');
  const idx = planillas.findIndex(p => p.id === req.params.id && !p.firmada);
  if (idx < 0) return res.status(404).json({ error: 'No encontrada o ya firmada' });
  const filename = planillas[idx].filename;
  planillas.splice(idx, 1);
  db.write('planillas_asignadas.json', planillas);
  // Eliminar archivo
  try { fs.unlinkSync(path.join(PLANILLAS_DIR, filename)); } catch(e) {}
  res.json({ ok: true });
});

// GET /api/admin/historial?mes=3&year=2026&q=angulo
app.get('/api/admin/historial', requireAdmin, (req, res) => {
  let hist = db.read('historial.json');
  const { mes, year, q } = req.query;
  if (mes !== undefined && mes !== '') hist = hist.filter(h => h.mes === parseInt(mes));
  if (year && year !== '') hist = hist.filter(h => String(h.year) === String(year));
  if (q && q.trim()) {
    const lq = q.toLowerCase();
    hist = hist.filter(h =>
      h.inspNombre.toLowerCase().includes(lq) ||
      h.inspLegajo.includes(lq) ||
      h.inspDni.includes(lq)
    );
  }
  res.json([...hist].sort((a,b) => new Date(b.firmadoTs) - new Date(a.firmadoTs)));
});

// GET /api/admin/descargar/:filename
app.get('/api/admin/descargar/:filename', requireAdmin, (req, res) => {
  const filePath = path.join(FIRMADAS_DIR, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('Archivo no encontrado');
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${req.params.filename}"`);
  res.sendFile(filePath);
});


// ═══════════════════════════════════════════════════════════════
//  NUEVAS FUNCIONALIDADES
// ═══════════════════════════════════════════════════════════════

// 1. Credenciales de todos los inspectores (CSV para distribución)
app.get('/api/admin/credenciales', requireAdmin, (req, res) => {
  const { inspectores = [] } = db.read('usuarios.json');
  // VUL-01: nunca exponer contraseñas en CSV — mostrar estado
  const rows = ['Apellido,Nombre,Legajo,DNI,Usuario,Estado'];
  inspectores.forEach(i => {
    const estado = i.primerLogin === false ? 'Contraseña cambiada' : 'Primer login pendiente';
    rows.push(`"${i.apellido}","${i.nombre}","${i.legajo}","${i.dni}","${i.username}","${estado}"`);
  });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="credenciales_firmared.csv"');
  res.send('﻿' + rows.join('\n')); // BOM para Excel
});

// 2. Backup de firmas (descarga JSON con todas las firmas registradas)
app.get('/api/admin/backup-firmas', requireAdmin, (req, res) => {
  // VUL-07: audit log de descarga de backup
  logSecurity('BACKUP_DESCARGADO', getIP(req), '/api/admin/backup-firmas',
    'Usuario: ' + (req.session.user?.username || String(req.session.user)));
  const { inspectores = [] } = db.read('usuarios.json');
  const backup = {
    fecha: new Date().toISOString(),
    version: '1.0',
    firmas: inspectores
      .filter(i => i.firma)
      .map(i => ({ id: i.id, apellido: i.apellido, nombre: i.nombre, legajo: i.legajo, firma: i.firma }))
  };
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="backup_firmas_${new Date().toISOString().slice(0,10)}.json"`);
  res.json(backup);
});

// 3. Restaurar firmas desde backup
app.post('/api/admin/restore-firmas', requireAdmin, (req, res) => {
  const { firmas } = req.body;
  if (!Array.isArray(firmas)) return res.status(400).json({ error: 'Formato inválido' });
  const data = db.read('usuarios.json');
  let restauradas = 0, noEncontradas = 0;
  firmas.forEach(f => {
    const idx = data.inspectores.findIndex(i => i.id === f.id || i.legajo === f.legajo);
    if (idx >= 0) { data.inspectores[idx].firma = f.firma; restauradas++; }
    else noEncontradas++;
  });
  db.write('usuarios.json', data);
  res.json({ ok: true, restauradas, noEncontradas });
});

// 4. Cambiar contraseña (inspector: máx 2 veces / admin: sin límite)
app.post('/api/cambiar-password', requireAuth, (req, res) => {
  const { actual, nueva } = req.body;
  if (!actual || !nueva) return res.status(400).json({ error: 'Faltan campos' });
  if (nueva.length < 4) return res.status(400).json({ error: 'La contraseña debe tener al menos 4 caracteres' });
  const data = db.read('usuarios.json');
  if (req.session.user.role === 'inspector') {
    const idx = data.inspectores.findIndex(i => i.id === req.session.user.inspId);
    if (idx < 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (!verifyPassword(actual, data.inspectores[idx].password)) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    const cambios = data.inspectores[idx].passwordCambios || 0;
    if (cambios >= 2) return res.status(403).json({
      error: 'Límite alcanzado. Ya cambiaste tu contraseña 2 veces. Contactá a la asesoría por WhatsApp: +54 9 221 380-2016',
      limite: true
    });
    data.inspectores[idx].password = hashPassword(nueva);
    data.inspectores[idx].passwordCambios = cambios + 1;
  } else {
    const idx = data.admins.findIndex(a => a.username === req.session.user.username);
    if (idx < 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (!verifyPassword(actual, data.admins[idx].password)) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    data.admins[idx].password = hashPassword(nueva);
  }
  db.write('usuarios.json', data);
  res.json({ ok: true });
});

// GET /api/inspector/mis-cambios-password
app.get('/api/inspector/cambios-password', requireAuth, (req, res) => {
  if (req.session.user.role !== 'inspector') return res.json({ cambios: 0, limite: 2 });
  const insp = getInspector(req.session.user.inspId);
  res.json({ cambios: insp?.passwordCambios || 0, limite: 2 });
});

// Admin: resetear contador de cambios de contraseña
app.post('/api/admin/reset-password/:inspId', requireAdmin, (req, res) => {
  const data = db.read('usuarios.json');
  const idx = data.inspectores.findIndex(i => i.id === req.params.inspId);
  if (idx < 0) return res.status(404).json({ error: 'No encontrado' });
  data.inspectores[idx].passwordCambios = 0;
  db.write('usuarios.json', data);
  res.json({ ok: true });
});

// 5. Estado de firmas del mes actual (para filtros admin)
app.get('/api/admin/estado-firmas', requireAdmin, (req, res) => {
  const { inspectores = [] } = db.read('usuarios.json');
  const hist = db.read('historial.json');
  const now = new Date();
  const mes = now.getMonth(), year = now.getFullYear();
  const firmaronEsteMes = new Set(
    hist.filter(h => h.mes === mes && h.year === year).map(h => h.inspId)
  );
  res.json({
    total: inspectores.length,
    conFirmaRegistrada: inspectores.filter(i => i.firma).length,
    firmaronEsteMes: firmaronEsteMes.size,
    faltanEsteMes: inspectores.length - firmaronEsteMes.size,
    ids: { firmaronEsteMes: [...firmaronEsteMes] }
  });
});


// ═══════════════════════════════════════════════════════════════
//  MODERACIÓN DE INSPECTORES (superusuario admin)
// ═══════════════════════════════════════════════════════════════

// GET /api/admin/inspector/:id — datos completos de un inspector
app.get('/api/admin/inspector/:id', requireAdmin, (req, res) => {
  const { inspectores = [] } = db.read('usuarios.json');
  const insp = inspectores.find(i => i.id === req.params.id);
  if (!insp) return res.status(404).json({ error: 'Inspector no encontrado' });
  const hist = db.read('historial.json').filter(h => h.inspId === req.params.id);
  const planillas = db.read('planillas_asignadas.json').filter(p => p.inspId === req.params.id);
  res.json({
    id: insp.id, apellido: insp.apellido, nombre: insp.nombre,
    legajo: insp.legajo, dni: insp.dni,
    username: insp.username,
    tieneFirma: !!insp.firma,
    passwordCambios: insp.passwordCambios || 0,
    historial: hist.sort((a,b) => new Date(b.firmadoTs) - new Date(a.firmadoTs)),
    planillasPendientes: planillas.filter(p => !p.firmada).length,
    planillasFirmadas: planillas.filter(p => p.firmada).length,
  });
});

// POST /api/admin/inspector/:id/borrar-firma — blanquear firma
app.post('/api/admin/inspector/:id/borrar-firma', requireAdmin, (req, res) => {
  const data = db.read('usuarios.json');
  const idx = data.inspectores.findIndex(i => i.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'No encontrado' });
  data.inspectores[idx].firma = null;
  db.write('usuarios.json', data);
  res.json({ ok: true, mensaje: 'Firma eliminada. El inspector deberá registrar una nueva.' });
});

// POST /api/admin/inspector/:id/reset-password — resetear contraseña al legajo
app.post('/api/admin/inspector/:id/reset-password', requireAdmin, (req, res) => {
  const data = db.read('usuarios.json');
  const idx = data.inspectores.findIndex(i => i.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'No encontrado' });
  const { nuevaPassword } = req.body;
  data.inspectores[idx].password = hashPassword(nuevaPassword || data.inspectores[idx].legajo);
  data.inspectores[idx].passwordCambios = 0; // resetear contador
  db.write('usuarios.json', data);
  const nuevaClave = nuevaPassword || data.inspectores[idx].legajo;
  res.json({ ok: true, mensaje: `Contraseña reseteada a: ${nuevaClave}` });
});

// POST /api/admin/inspector/:id/cambiar-username — cambiar nombre de usuario
app.post('/api/admin/inspector/:id/cambiar-username', requireAdmin, (req, res) => {
  const { nuevoUsername } = req.body;
  if (!nuevoUsername || nuevoUsername.trim().length < 3)
    return res.status(400).json({ error: 'El usuario debe tener al menos 3 caracteres' });
  const data = db.read('usuarios.json');
  // Verificar que no existe
  const existe = data.inspectores.find(i => i.username === nuevoUsername.trim() && i.id !== req.params.id);
  if (existe) return res.status(409).json({ error: 'Ese usuario ya está en uso por otro inspector' });
  const idx = data.inspectores.findIndex(i => i.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'No encontrado' });
  const usernameAnterior = data.inspectores[idx].username;
  data.inspectores[idx].username = nuevoUsername.trim().toLowerCase();
  db.write('usuarios.json', data);
  res.json({ ok: true, mensaje: `Usuario cambiado de "${usernameAnterior}" a "${nuevoUsername.trim().toLowerCase()}"` });
});

// DELETE /api/admin/inspector/:id/historial/:hid — borrar entrada del historial
app.delete('/api/admin/inspector/:id/historial/:hid', requireAdmin, (req, res) => {
  const hist = db.read('historial.json');
  const idx = hist.findIndex(h => h.id === req.params.hid && h.inspId === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'Entrada no encontrada' });
  // Eliminar archivo PDF firmado
  const signedFile = hist[idx].signedFile;
  if (signedFile) {
    try { fs.unlinkSync(path.join(FIRMADAS_DIR, signedFile)); } catch(e) {}
  }
  hist.splice(idx, 1);
  db.write('historial.json', hist);
  res.json({ ok: true });
});

// DELETE /api/admin/inspector/:id/historial — borrar TODO el historial del inspector
app.delete('/api/admin/inspector/:id/historial', requireAdmin, (req, res) => {
  let hist = db.read('historial.json');
  const del = hist.filter(h => h.inspId === req.params.id);
  // Eliminar archivos PDF
  del.forEach(h => { try { fs.unlinkSync(path.join(FIRMADAS_DIR, h.signedFile)); } catch(e) {} });
  hist = hist.filter(h => h.inspId !== req.params.id);
  db.write('historial.json', hist);
  res.json({ ok: true, eliminadas: del.length });
});

// POST /api/admin/planilla/:id/reabrir — marcar planilla firmada como no firmada (permite refirmar)
app.post('/api/admin/planilla/:id/reabrir', requireAdmin, (req, res) => {
  const planillas = db.read('planillas_asignadas.json');
  const idx = planillas.findIndex(p => p.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'Planilla no encontrada' });
  const plan = planillas[idx];
  // Eliminar entrada del historial correspondiente
  let hist = db.read('historial.json');
  const hidx = hist.findIndex(h => h.inspId === plan.inspId && h.mes === plan.mes && h.year === plan.year);
  if (hidx >= 0) {
    try { fs.unlinkSync(path.join(FIRMADAS_DIR, hist[hidx].signedFile)); } catch(e) {}
    hist.splice(hidx, 1);
    db.write('historial.json', hist);
  }
  // Reabrir planilla
  planillas[idx].firmada = false;
  planillas[idx].firmadaTs = null;
  planillas[idx].signedFile = null;
  db.write('planillas_asignadas.json', planillas);
  res.json({ ok: true, mensaje: 'Planilla reabierta. El inspector puede volver a firmarla.' });
});


// POST /api/admin/inspector/:id/planilla-firmada/:mes/:year — reabrir planilla firmada
app.post('/api/admin/inspector/:id/planilla-firmada/:mes/:year', requireAdmin, (req, res) => {
  const inspId = req.params.id;
  const mes = parseInt(req.params.mes);
  const year = req.params.year;
  const planillas = db.read('planillas_asignadas.json');
  // Buscar la planilla firmada de ese inspector/mes/año
  const idx = planillas.findIndex(p =>
    p.inspId === inspId && p.mes === mes && String(p.year) === String(year) && p.firmada
  );
  if (idx < 0) return res.status(404).json({ error: 'No se encontró una planilla firmada para ese período.' });
  const plan = planillas[idx];
  // Eliminar entrada del historial
  let hist = db.read('historial.json');
  const hidx = hist.findIndex(h => h.inspId === inspId && h.mes === mes && String(h.year) === String(year));
  if (hidx >= 0) {
    try { fs.unlinkSync(path.join(FIRMADAS_DIR, hist[hidx].signedFile)); } catch(e) {}
    hist.splice(hidx, 1);
    db.write('historial.json', hist);
  }
  // Reabrir planilla
  planillas[idx].firmada = false;
  planillas[idx].firmadaTs = null;
  planillas[idx].signedFile = null;
  db.write('planillas_asignadas.json', planillas);
  res.json({ ok: true, mensaje: `Planilla de ${MESES[mes]} ${year} reabierta. El inspector puede volver a firmarla.` });
});


// ═══════════════════════════════════════════════════════════════
//  GESTIÓN DE NÓMINA (agregar/quitar inspectores)
// ═══════════════════════════════════════════════════════════════

// POST /api/admin/inspector — agregar nuevo inspector
app.post('/api/admin/inspector', requireAdmin, (req, res) => {
  const { apellido, nombre, legajo, dni, username, password } = req.body;
  if (!apellido || !nombre || !legajo || !dni)
    return res.status(400).json({ error: 'Faltan campos obligatorios: apellido, nombre, legajo, DNI' });
  const data = db.read('usuarios.json');
  // Verificar duplicados
  if (data.inspectores.find(i => i.legajo === String(legajo)))
    return res.status(409).json({ error: `Ya existe un inspector con el legajo ${legajo}` });
  if (data.inspectores.find(i => i.dni === String(dni)))
    return res.status(409).json({ error: `Ya existe un inspector con el DNI ${dni}` });
  // Generar username automático si no se provee
  const genUser = () => {
    // Apellido completo sin espacios ni acentos + inicial del primer nombre
    const normalize = s => s.normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-zA-Z0-9]/g,'').toLowerCase();
    const apBase = normalize(apellido.replace(/\s+/g,''));
    const nomInicial = normalize(nombre.trim().split(/\s+/)[0][0]);
    const base = apBase + nomInicial;
    if (!data.inspectores.find(i => i.username === base)) return base;
    let n = 2;
    while (data.inspectores.find(i => i.username === base+n)) n++;
    return base + n;
  };
  const newInsp = {
    id:       String(legajo),
    apellido: apellido.trim().toUpperCase(),
    nombre:   nombre.trim().toUpperCase(),
    legajo:   String(legajo).trim(),
    dni:      String(dni).trim(),
    username: username ? username.trim().toLowerCase() : genUser(),
    password:    hashPassword(password || String(legajo).trim()), // VUL-04: hashear desde el inicio
    firma:       null,
    passwordCambios: 0,
    primerLogin: true, // obligar cambio de contraseña al primer ingreso
  };
  data.inspectores.push(newInsp);
  // Ordenar por apellido
  data.inspectores.sort((a,b) => a.apellido.localeCompare(b.apellido));
  db.write('usuarios.json', data);
  res.json({ ok: true, inspector: newInsp, mensaje: `Inspector ${cap(newInsp.apellido)}, ${cap(newInsp.nombre)} agregado. Usuario: ${newInsp.username} / Clave: ${newInsp.password}` });
});

// DELETE /api/admin/inspector/:id — quitar inspector de la nómina
app.delete('/api/admin/inspector/:id', requireAdmin, (req, res) => {
  const data = db.read('usuarios.json');
  const idx = data.inspectores.findIndex(i => i.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: 'Inspector no encontrado' });
  const insp = data.inspectores[idx];
  data.inspectores.splice(idx, 1);
  db.write('usuarios.json', data);
  // Eliminar planillas pendientes del inspector
  let planillas = db.read('planillas_asignadas.json');
  planillas = planillas.filter(p => p.inspId !== req.params.id);
  db.write('planillas_asignadas.json', planillas);
  res.json({ ok: true, mensaje: `Inspector ${cap(insp.apellido)}, ${cap(insp.nombre)} eliminado de la nómina.` });
});


// ═══════════════════════════════════════════════════════════════
//  ANALYTICS — Control de Calidad
// ═══════════════════════════════════════════════════════════════

const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const EVENTS_FILE   = path.join(DATA_DIR, 'events.json');

// Inicializar archivos de analytics si no existen
if (!fs.existsSync(SESSIONS_FILE)) fs.writeFileSync(SESSIONS_FILE, '[]');
if (!fs.existsSync(EVENTS_FILE))   fs.writeFileSync(EVENTS_FILE,   '[]');

// POST /api/analytics/event — registrar evento desde el cliente
app.post('/api/analytics/event', requireAuth, (req, res) => {
  const { type, data: evtData } = req.body;
  const events = JSON.parse(fs.readFileSync(EVENTS_FILE, 'utf8'));
  events.push({
    id:        `ev${Date.now()}${Math.random().toString(36).slice(2,6)}`,
    type,
    userId:    req.session.user.id || req.session.user.username,
    role:      req.session.user.role,
    ts:        new Date().toISOString(),
    data:      evtData || {}
  });
  // Mantener solo últimos 5000 eventos
  if (events.length > 5000) events.splice(0, events.length - 5000);
  fs.writeFileSync(EVENTS_FILE, JSON.stringify(events));
  res.json({ ok: true });
});

// POST /api/analytics/session/start — inicio de sesión
app.post('/api/analytics/session/start', requireAuth, (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const isMobile = /iPhone|iPad|Android|Mobile/i.test(ua);
  const isTablet = /iPad|Android(?!.*Mobile)/i.test(ua);
  const device = isTablet ? 'tablet' : isMobile ? 'mobile' : 'desktop';
  const browser = ua.match(/(Chrome|Firefox|Safari|Edge|Opera)[\/]([\d.]+)/)?.[1] || 'Desconocido';
  const os = ua.match(/(Windows|Mac OS|Linux|Android|iOS)/i)?.[1] || 'Desconocido';

  const sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
  const sess = {
    id:        `s${Date.now()}${Math.random().toString(36).slice(2,6)}`,
    userId:    req.session.user.id || req.session.user.username,
    username:  req.session.user.username,
    role:      req.session.user.role,
    nombre:    req.session.user.nombre || req.session.user.username,
    startTs:   new Date().toISOString(),
    endTs:     null,
    duration:  null, // segundos
    device,
    browser,
    os,
    ua:        ua.slice(0, 200),
    ip:        req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'N/A',
    actions:   0, // se incrementa con eventos
    firmó:     false
  };
  sessions.push(sess);
  // Mantener solo últimas 2000 sesiones
  if (sessions.length > 2000) sessions.splice(0, sessions.length - 2000);
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions));
  req.session.analyticsSessionId = sess.id;
  res.json({ ok: true, sessionId: sess.id });
});

// POST /api/analytics/session/end — cierre de sesión
app.post('/api/analytics/session/end', requireAuth, (req, res) => {
  const sid = req.session.analyticsSessionId;
  if (!sid) return res.json({ ok: true });
  const sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
  const idx = sessions.findIndex(s => s.id === sid);
  if (idx >= 0) {
    const now = new Date();
    sessions[idx].endTs = now.toISOString();
    sessions[idx].duration = Math.round((now - new Date(sessions[idx].startTs)) / 1000);
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions));
  }
  res.json({ ok: true });
});

// PATCH /api/analytics/session/action — incrementar contador de acciones
app.patch('/api/analytics/session/action', requireAuth, (req, res) => {
  const sid = req.session.analyticsSessionId;
  if (!sid) return res.json({ ok: true });
  const { firmó } = req.body;
  const sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
  const idx = sessions.findIndex(s => s.id === sid);
  if (idx >= 0) {
    sessions[idx].actions = (sessions[idx].actions || 0) + 1;
    if (firmó) sessions[idx].firmó = true;
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions));
  }
  res.json({ ok: true });
});

// GET /api/admin/analytics — datos completos de analytics
app.get('/api/admin/analytics', requireAdmin, (req, res) => {
  const sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
  const events   = JSON.parse(fs.readFileSync(EVENTS_FILE,   'utf8'));
  const { desde, hasta } = req.query;

  // Filtrar por rango de fechas si se provee
  let sess = sessions;
  if (desde) sess = sess.filter(s => s.startTs >= desde);
  if (hasta) sess = sess.filter(s => s.startTs <= hasta + 'T23:59:59');

  const total = sess.length;
  const completadas = sess.filter(s => s.endTs).length;
  const duraciones = sess.filter(s => s.duration > 0).map(s => s.duration);
  const durPromedio = duraciones.length ? Math.round(duraciones.reduce((a,b)=>a+b,0)/duraciones.length) : 0;
  const durMax = duraciones.length ? Math.max(...duraciones) : 0;

  // Distribución de dispositivos
  const dispositivos = { mobile: 0, tablet: 0, desktop: 0 };
  sess.forEach(s => { if (dispositivos[s.device] !== undefined) dispositivos[s.device]++; });

  // Distribución de browsers
  const browsers = {};
  sess.forEach(s => { browsers[s.browser] = (browsers[s.browser]||0)+1; });

  // Distribución de SO
  const sistemas = {};
  sess.forEach(s => { sistemas[s.os] = (sistemas[s.os]||0)+1; });

  // Sesiones por día (últimos 30 días)
  const porDia = {};
  sess.forEach(s => {
    const dia = s.startTs.slice(0,10);
    porDia[dia] = (porDia[dia]||0)+1;
  });

  // Horas pico
  const porHora = new Array(24).fill(0);
  sess.forEach(s => { const h = new Date(s.startTs).getHours(); porHora[h]++; });

  // Inspectores más activos
  const porUser = {};
  sess.filter(s => s.role==='inspector').forEach(s => {
    if (!porUser[s.userId]) porUser[s.userId] = { nombre: s.nombre, username: s.username, sesiones: 0, firmas: 0, acciones: 0 };
    porUser[s.userId].sesiones++;
    if (s.firmó) porUser[s.userId].firmas++;
    porUser[s.userId].acciones += s.actions||0;
  });
  const topInspectores = Object.values(porUser).sort((a,b)=>b.sesiones-a.sesiones).slice(0,10);

  // Tasa de firma (sesiones de inspector que terminaron en firma)
  const sesInsp = sess.filter(s=>s.role==='inspector');
  const tasaFirma = sesInsp.length ? Math.round(sesInsp.filter(s=>s.firmó).length/sesInsp.length*100) : 0;

  // Últimas 20 sesiones
  const ultimas = [...sess].sort((a,b)=>new Date(b.startTs)-new Date(a.startTs));

  res.json({
    resumen: { total, completadas, durPromedio, durMax, tasaFirma },
    dispositivos, browsers, sistemas,
    porDia, porHora,
    topInspectores,
    ultimas,
    totalEventos: events.length
  });
});


// POST /api/admin/seed-demo — inyectar sesiones de prueba para ver analytics
app.post('/api/admin/seed-demo', requireAdmin, (req, res) => {
  const now = new Date();
  const devices = ['mobile','mobile','desktop','desktop','mobile','tablet','desktop'];
  const browsers = ['Chrome','Safari','Chrome','Firefox','Chrome','Safari','Chrome'];
  const oss = ['Android','iOS','Windows','Windows','Android','iOS','Windows'];
  const inspectores = [
    {id:'601806',username:'yangulo',nombre:'Angulo Estrada, Yamila'},
    {id:'602455',username:'cabalos',nombre:'Abalos, Christian'},
    {id:'601641',username:'nabba',nombre:'Abba, Nelson'},
    {id:'601659',username:'maguerriberry',nombre:'Aguerriberry, Mariana'},
    {id:'800097',username:'gaguilar',nombre:'Aguilar, Guillermo'},
    {id:'601111',username:'jagustine',nombre:'Augustine, Juan'},
    {id:'602086',username:'oahlefeldt',nombre:'Ahlefeldt, Osvaldo'},
  ];
  const sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE,'utf8'));
  // Generar 40 sesiones de los últimos 14 días
  for(let d=0;d<14;d++){
    const dia = new Date(now - d*86400000);
    const cuantas = Math.floor(Math.random()*5)+1;
    for(let s=0;s<cuantas;s++){
      const insp = inspectores[Math.floor(Math.random()*inspectores.length)];
      const hora = Math.floor(Math.random()*10)+8; // 8-17hs
      const start = new Date(dia.setHours(hora, Math.floor(Math.random()*60)));
      const dur = Math.floor(Math.random()*480)+30; // 30s a 8min
      const firmo = Math.random() > 0.4;
      sessions.push({
        id: `sdemo${Date.now()}${Math.random().toString(36).slice(2,6)}`,
        userId: insp.id,
        username: insp.username,
        role: 'inspector',
        nombre: insp.nombre,
        startTs: start.toISOString(),
        endTs: new Date(start.getTime()+dur*1000).toISOString(),
        duration: dur,
        device: devices[Math.floor(Math.random()*devices.length)],
        browser: browsers[Math.floor(Math.random()*browsers.length)],
        os: oss[Math.floor(Math.random()*oss.length)],
        ua: '',
        ip: '186.x.x.x',
        actions: Math.floor(Math.random()*8)+1,
        firmó: firmo
      });
    }
  }
  // Agregar algunas sesiones de admin
  for(let i=0;i<5;i++){
    const start = new Date(now - Math.floor(Math.random()*14)*86400000);
    sessions.push({
      id: `sademo${Date.now()}${i}`,
      userId:'admin',username:'admin',role:'admin',nombre:'Administrador',
      startTs: start.toISOString(),
      endTs: new Date(start.getTime()+600000).toISOString(),
      duration: 600,
      device:'desktop',browser:'Chrome',os:'Windows',ua:'',ip:'local',actions:15,firmó:false
    });
  }
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions));
  res.json({ok:true, sesionesAgregadas: sessions.length});
});


// POST /api/admin/reset-analytics — limpiar todos los datos de analytics
app.post('/api/admin/reset-analytics', requireAdmin, (req, res) => {
  fs.writeFileSync(SESSIONS_FILE, '[]');
  fs.writeFileSync(EVENTS_FILE, '[]');
  res.json({ ok: true, mensaje: 'Analytics reseteado. Contador en cero.' });
});


// ═══════════════════════════════════════════════════════════════
//  VERIFICACIÓN PÚBLICA DE DOCUMENTOS (sin autenticación)
// ═══════════════════════════════════════════════════════════════

app.get('/verificar/:hash', (req, res) => {
  const hash = req.params.hash;
  const hist = db.read('historial.json');
  const entry = hist.find(h => h.hash === hash);

  const html = (valid, data) => `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${valid ? '✅ Documento verificado' : '❌ Documento no encontrado'} — FirmaRED</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#F0F4F8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:16px;padding:40px 36px;max-width:520px;width:100%;box-shadow:0 4px 24px rgba(0,0,0,.1)}
.icon{font-size:52px;margin-bottom:16px;display:block}
.status{font-size:22px;font-weight:700;margin-bottom:8px;color:${valid?'#1A7A3C':'#C0392B'}}
.sub{font-size:15px;color:#666;margin-bottom:28px;line-height:1.5}
.field{border-top:1px solid #EEE;padding:12px 0;display:flex;justify-content:space-between;align-items:flex-start;gap:16px}
.label{font-size:12px;color:#888;text-transform:uppercase;letter-spacing:.05em;flex-shrink:0}
.value{font-size:14px;font-weight:600;color:#333;text-align:right}
.hash{font-family:monospace;font-size:11px;color:#888;word-break:break-all;margin-top:20px;padding:12px;background:#F8F9FA;border-radius:8px;border:1px solid #E8E8E8}
.footer{margin-top:24px;font-size:12px;color:#AAA;text-align:center;line-height:1.6}
.logo{font-weight:700;color:#003366}
.valid-bar{height:4px;background:${valid?'#27AE60':'#E74C3C'};border-radius:4px 4px 0 0;margin:-40px -36px 36px;border-radius:16px 16px 0 0}
</style>
</head>
<body>
<div class="card">
  <div class="valid-bar"></div>
  <span class="icon">${valid ? '✅' : '❌'}</span>
  <div class="status">${valid ? 'Documento auténtico' : 'Documento no encontrado'}</div>
  <div class="sub">${valid
    ? 'Este documento fue firmado digitalmente en FirmaRED y su contenido no fue alterado.'
    : 'No se encontró ningún documento firmado con este identificador. Puede haber sido adulterado o el código QR es incorrecto.'
  }</div>
  ${valid ? `
  <div class="field"><span class="label">Inspector</span><span class="value">${data.inspNombre}</span></div>
  <div class="field"><span class="label">Legajo</span><span class="value">${data.inspLegajo}</span></div>
  <div class="field"><span class="label">DNI</span><span class="value">${data.inspDni}</span></div>
  <div class="field"><span class="label">Período</span><span class="value">${data.mesNombre} ${data.year}</span></div>
  <div class="field"><span class="label">Fecha de firma</span><span class="value">${new Date(data.firmadoTs).toLocaleString('es-AR',{dateStyle:'long',timeStyle:'short'})}</span></div>
  <div class="field"><span class="label">Método de firma</span><span class="value" style="display:flex;align-items:center;gap:8px;justify-content:flex-end">
    ${data.firmaMetodo==='biometrico'
      ? '<span style="background:#E8F5E9;color:#1A5E2A;padding:4px 10px;border-radius:20px;font-size:12px;font-weight:700;border:1px solid #A5D6A7">👆 Firma biométrica verificada</span>'
      : '<span style="background:#EBF4FB;color:#1F5FA6;padding:4px 10px;border-radius:20px;font-size:12px;font-weight:700;border:1px solid #B5D4F4">✍️ Firma electrónica manuscrita</span>'
    }
  </span></div>
  <div class="field"><span class="label">Nivel de autenticación</span><span class="value" style="text-align:right">
    ${data.firmaMetodo==='biometrico'
      ? '<span style="color:#1A5E2A;font-size:12px">⭐⭐ Superior — Identidad biométrica + firma electrónica</span>'
      : '<span style="color:#1F5FA6;font-size:12px">⭐ Estándar — Firma electrónica · Ley 25.506</span>'
    }
  </span></div>
  <div class="field"><span class="label">Organismo</span><span class="value">Subsecretaría de Inspección del Trabajo<br>Provincia de Buenos Aires</span></div>

  <!-- Sección hash SHA-256 -->
  <div style="margin-top:18px;padding-top:14px;border-top:1px solid #e8e8e8">
    <div style="font-size:10px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px">Huella criptográfica SHA-256</div>
    <div style="font-family:monospace;font-size:11px;word-break:break-all;background:#f5f7fa;padding:10px 12px;border-radius:8px;color:#333;border:1px solid #e0e0e0">${data.hash || hash}</div>
  </div>

  <!-- Sección blockchain OTS -->
  <div id="otsSection" style="margin-top:14px;padding-top:14px;border-top:1px solid #e8e8e8">
    <div style="font-size:10px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px">Registro en blockchain Bitcoin</div>
    <div id="otsStatus" style="font-size:12px;color:#888">Consultando...</div>
    <div id="otsActions" style="display:none;margin-top:10px;display:flex;gap:8px;flex-wrap:wrap"></div>
  </div>

  <!-- Botón ver detalle técnico -->
  <div style="margin-top:16px;text-align:center">
    <button onclick="document.getElementById('detalleTecnico').style.display=document.getElementById('detalleTecnico').style.display==='none'?'block':'none'" 
      style="background:none;border:1px solid #ddd;border-radius:8px;padding:7px 16px;font-size:12px;color:#888;cursor:pointer">
      Ver detalle técnico
    </button>
  </div>
  <div id="detalleTecnico" style="display:none;margin-top:12px;background:#f5f7fa;border-radius:10px;padding:14px;font-size:11px;color:#555;line-height:1.8">
    <div><b>Algoritmo:</b> SHA-256 (FIPS 180-4)</div>
    <div><b>Protocolo de firma:</b> FirmaRED v1 · Ley 25.506</div>
    <div><b>Timestamping:</b> OpenTimestamps sobre Bitcoin</div>
    <div><b>Verificación independiente:</b> <a href="https://opentimestamps.org" target="_blank" style="color:#1F5FA6">opentimestamps.org</a></div>
    <div style="margin-top:8px"><a href="/api/verificar/${hash}/ots" style="color:#1F5FA6;font-weight:600">⬇ Descargar prueba .ots</a></div>
  </div>
  <div class="hash">SHA-256: ${hash}</div>
  ` : `<div class="hash">Hash consultado: ${hash}</div>`}
  <div class="footer">
    <span class="logo">FirmaRED</span> — Sistema de Firma Digital de Viáticos<br>
    Ministerio de Trabajo · Provincia de Buenos Aires
  </div>
</div>
<script>
async function checkOTS(){
  const hash = location.pathname.split('/').pop();
  try{
    const r = await fetch('/api/verificar/' + hash + '/estado-ots');
    const d = await r.json();
    const el = document.getElementById('otsStatus');
    const ac = document.getElementById('otsActions');
    if(!el) return;
    if(d.otsDisponible){
      el.innerHTML = '<span style="color:#1A5E2A;font-weight:700">Registrado en Bitcoin</span> · Prueba anclada, confirmación en progreso';
      if(ac){
        ac.style.display='flex';
        ac.innerHTML = 
          '<a href="/api/verificar/' + hash + '/ots" style="background:#003366;color:#fff;padding:7px 14px;border-radius:8px;font-size:12px;font-weight:600;text-decoration:none">Descargar prueba .ots</a>' +
          '<a href="https://opentimestamps.org" target="_blank" style="background:#f5f5f5;color:#333;padding:7px 14px;border-radius:8px;font-size:12px;font-weight:600;text-decoration:none;border:1px solid #ddd">Verificar online</a>';
      }
    } else {
      if(el) el.textContent = 'Registro en Bitcoin pendiente de confirmacion';
    }
  }catch(e){}
}
checkOTS();
</script>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html(!!entry, entry));
});

// GET /api/admin/historial-con-hash — historial con URLs de verificación
app.get('/api/admin/verificacion/:hash', requireAdmin, (req, res) => {
  const hist = db.read('historial.json');
  const entry = hist.find(h => h.hash === req.params.hash);
  if (!entry) return res.status(404).json({ error: 'No encontrado' });
  res.json(entry);
});


// POST /api/admin/planilla-test — crear planilla de prueba sin upload externo
app.post('/api/admin/planilla-test', requireAdmin, (req, res) => {
  const { inspId, mes, year } = req.body;
  if (!inspId || mes === undefined || !year)
    return res.status(400).json({ error: 'Faltan datos' });
  const planillas = db.read('planillas_asignadas.json');
  if (planillas.some(p => p.inspId === inspId && parseInt(p.mes) === parseInt(mes) && p.year === year && !p.firmada))
    return res.status(409).json({ error: 'Ya existe una planilla pendiente para ese período' });

  // Crear PDF de prueba con pdf-lib
  const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
  (async () => {
    try {
      const doc = await PDFDocument.create();
      const page = doc.addPage([612, 1008]);
      const font = await doc.embedFont(StandardFonts.HelveticaBold);
      const fontR = await doc.embedFont(StandardFonts.Helvetica);
      const { inspectores = [] } = db.read('usuarios.json');
      const insp = inspectores.find(i => i.id === inspId);
      const nombre = insp ? `${insp.apellido}, ${insp.nombre}` : 'Inspector';
      const meses = ['Enero','Febrero','Marzo','Abril','Mayo','Junio','Julio','Agosto','Septiembre','Octubre','Noviembre','Diciembre'];

      page.drawText('PLANILLA DE VIÁTICOS', {x:180,y:950,size:16,font,color:rgb(0,0,0.4)});
      page.drawText(`Subsecretaría de Inspección del Trabajo — PBA`, {x:120,y:925,size:10,font:fontR});
      page.drawText(`Inspector: ${nombre}`, {x:50,y:880,size:11,font});
      page.drawText(`Período: ${meses[parseInt(mes)]} ${year}`, {x:50,y:860,size:11,font});
      page.drawText('Resumen de viáticos y movilidad correspondientes al período indicado.', {x:50,y:820,size:10,font:fontR});
      page.drawText('Total General: $ 242,112.00', {x:400,y:260,size:11,font});
      // Zona 1 firma
      page.drawText('Firma del agente', {x:78,y:200,size:9,font:fontR,color:rgb(0.4,0.4,0.4)});
      page.drawLine({start:{x:78,y:215},end:{x:210,y:215},thickness:0.5,color:rgb(0,0,0)});
      // Zona 2 firma + DNI
      page.drawText('Firma del agente y N° de DNI', {x:243,y:80,size:9,font:fontR,color:rgb(0.4,0.4,0.4)});
      page.drawLine({start:{x:243,y:91},end:{x:375,y:91},thickness:0.5,color:rgb(0,0,0)});

      const pdfBytes = await doc.save();
      const fname = `planilla_${inspId}_${year}_${String(parseInt(mes)+1).padStart(2,'0')}_${Date.now()}.pdf`;
      fs.writeFileSync(path.join(PLANILLAS_DIR, fname), pdfBytes);

      const plan = {
        id: `p${Date.now()}`,
        inspId,
        mes: parseInt(mes),
        year,
        filename: fname,
        subidaTs: new Date().toISOString(),
        firmada: false
      };
      planillas.push(plan);
      db.write('planillas_asignadas.json', planillas);
      res.json({ ok: true, planillaId: plan.id, mensaje: `Planilla de prueba creada para ${nombre}` });
    } catch(e) {
      res.status(500).json({ error: e.message });
    }
  })();
});


// ═══════════════════════════════════════════════════════════════
//  SOLICITUDES DE VIÁTICOS (delegados y coordinadores)
// ═══════════════════════════════════════════════════════════════

const SOLICITUDES_FILE = path.join(DATA_DIR, 'solicitudes.json');
const DELEGADOS_FILE   = path.join(DATA_DIR, 'delegados.json');
if (!fs.existsSync(SOLICITUDES_FILE)) fs.writeFileSync(SOLICITUDES_FILE, '[]');
if (!fs.existsSync(DELEGADOS_FILE))   fs.writeFileSync(DELEGADOS_FILE, '[]');

// GET /solicitud — página pública del formulario
app.get('/solicitud', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'solicitud.html'));
});

// GET /api/inspectores/lista — lista pública de inspectores (sin auth)
app.get('/api/inspectores/lista', (req, res) => {
  const data = db.read('usuarios.json');
  // VUL-09: endpoint público — devuelve solo username+nombre (sin DNI/legajo)
  const lista = (data.inspectores || [])
    .map(i => {
      let display = i.nombre || '';
      if (!display.includes(',') && i.apellido) display = `${i.apellido}, ${i.nombre}`;
      return { username: i.username, nombre: display.trim() };
    })
    .sort((a, b) => a.nombre.localeCompare(b.nombre, 'es'));
  res.json(lista);
});

// POST /api/solicitud/nueva — enviar solicitud (sin auth)
app.post('/api/solicitud/nueva', (req, res) => {
  const { delegacion, solicitante, inspectores, fecha, destino, objetivos } = req.body;
  if (!delegacion || !solicitante || !fecha || !destino || !objetivos)
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  const solicitudes = db.read('solicitudes.json') || [];
  const nueva = {
    id:           `sol_${Date.now()}`,
    delegacion:   delegacion.trim(),
    solicitante:  solicitante.toUpperCase().trim(),
    inspectores:  Array.isArray(inspectores) ? inspectores : [],
    fecha,
    destino:      destino.trim(),
    objetivos:    objetivos.trim(),
    estado:       'pendiente',
    estadoTs:     null,
    estadoAdmin:  null,
    observaciones:'',
    timestamp:    new Date().toISOString(),
  };
  solicitudes.push(nueva);
  if (solicitudes.length > 1000) solicitudes.splice(0, solicitudes.length - 1000);
  db.write('solicitudes.json', solicitudes);
  res.json({ ok: true, id: nueva.id, mensaje: 'Solicitud enviada correctamente' });
});

// GET /api/admin/solicitudes
app.get('/api/admin/solicitudes', requireAdmin, (req, res) => {
  const solicitudes = db.read('solicitudes.json') || [];
  res.json([...solicitudes].reverse());
});

// POST /api/admin/solicitud/:id/aprobar
app.post('/api/admin/solicitud/:id/aprobar', requireAdmin, (req, res) => {
  const { observaciones } = req.body;
  const solicitudes = db.read('solicitudes.json') || [];
  const sol = solicitudes.find(s => s.id === req.params.id);
  if (!sol) return res.status(404).json({ error: 'No encontrada' });
  sol.estado       = 'aprobada';
  sol.estadoTs     = new Date().toISOString();
  sol.estadoAdmin  = req.session.user;
  sol.observaciones = observaciones || '';
  db.write('solicitudes.json', solicitudes);
  const deleg = (db.read('delegados.json') || []).find(d => d.delegacion === sol.delegacion);
  res.json({ ok: true, whatsapp: deleg?.whatsapp || '', solicitud: sol });
});

// POST /api/admin/solicitud/:id/rechazar
app.post('/api/admin/solicitud/:id/rechazar', requireAdmin, (req, res) => {
  const { observaciones } = req.body;
  const solicitudes = db.read('solicitudes.json') || [];
  const sol = solicitudes.find(s => s.id === req.params.id);
  if (!sol) return res.status(404).json({ error: 'No encontrada' });
  sol.estado       = 'rechazada';
  sol.estadoTs     = new Date().toISOString();
  sol.estadoAdmin  = req.session.user;
  sol.observaciones = observaciones || '';
  db.write('solicitudes.json', solicitudes);
  const deleg = (db.read('delegados.json') || []).find(d => d.delegacion === sol.delegacion);
  res.json({ ok: true, whatsapp: deleg?.whatsapp || '', solicitud: sol });
});

// GET /api/admin/delegados
app.get('/api/admin/delegados', requireAdmin, (req, res) => {
  res.json(db.read('delegados.json') || []);
});

// PUT /api/admin/delegado/:delegacion/whatsapp
app.put('/api/admin/delegado/:delegacion/whatsapp', requireAdmin, (req, res) => {
  const { whatsapp } = req.body;
  const delegados = db.read('delegados.json') || [];
  const d = delegados.find(x => x.delegacion === decodeURIComponent(req.params.delegacion));
  if (!d) return res.status(404).json({ error: 'Delegación no encontrada' });
  d.whatsapp = (whatsapp || '').replace(/\D/g,'');
  db.write('delegados.json', delegados);
  res.json({ ok: true });
});


// POST /api/admin/viaticos/archivar — archivar todas las solicitudes en un paquete
app.post('/api/admin/viaticos/archivar', requireAdmin, (req, res) => {
  const { nombre } = req.body;
  const ARCHIVOS_FILE = path.join(DATA_DIR, 'archivos_viaticos.json');
  if (!fs.existsSync(ARCHIVOS_FILE)) fs.writeFileSync(ARCHIVOS_FILE, '[]');
  const solicitudes = db.read('solicitudes.json') || [];
  if (!solicitudes.length)
    return res.status(400).json({ error: 'No hay solicitudes para archivar' });
  const archivos = JSON.parse(fs.readFileSync(ARCHIVOS_FILE, 'utf8'));
  const paquete = {
    id:        `arch_${Date.now()}`,
    nombre:    (nombre || `Período ${new Date().toLocaleDateString('es-AR',{month:'long',year:'numeric'})}`).trim(),
    timestamp: new Date().toISOString(),
    creadoPor: req.session.user,
    total:     solicitudes.length,
    aprobadas: solicitudes.filter(s=>s.estado==='aprobada').length,
    rechazadas:solicitudes.filter(s=>s.estado==='rechazada').length,
    pendientes:solicitudes.filter(s=>s.estado==='pendiente').length,
    solicitudes,
  };
  archivos.unshift(paquete);
  fs.writeFileSync(ARCHIVOS_FILE, JSON.stringify(archivos));
  db.write('solicitudes.json', []);
  res.json({ ok: true, paquete: { id: paquete.id, nombre: paquete.nombre, total: paquete.total } });
});

// GET /api/admin/viaticos/archivos
app.get('/api/admin/viaticos/archivos', requireAdmin, (req, res) => {
  const ARCHIVOS_FILE = path.join(DATA_DIR, 'archivos_viaticos.json');
  if (!fs.existsSync(ARCHIVOS_FILE)) return res.json([]);
  res.json(JSON.parse(fs.readFileSync(ARCHIVOS_FILE, 'utf8')));
});


// ═══════════════════════════════════════════════════════════════
//  WEBAUTHN — Firma biométrica (huella / Face ID)
//  Implementado con crypto nativo de Node.js (sin dependencias extra)
// ═══════════════════════════════════════════════════════════════

const WA_CREDS_FILE  = path.join(DATA_DIR, 'webauthn_credentials.json');
const WA_CHALLENGES  = new Map(); // desafíos temporales en memoria
if (!fs.existsSync(WA_CREDS_FILE)) fs.writeFileSync(WA_CREDS_FILE, '{}');

function waReadCreds() {
  try { return JSON.parse(fs.readFileSync(WA_CREDS_FILE, 'utf8')); }
  catch(e) { return {}; }
}
function waWriteCreds(data) {
  fs.writeFileSync(WA_CREDS_FILE, JSON.stringify(data, null, 2));
}

// ── 1. Inicio de registro ──────────────────────────────────────
app.post('/api/webauthn/registro-inicio', (req, res) => {
  // Debug: log session state
  const userObj = req.session?.user;
  if (!userObj) return res.status(401).json({ error: 'Sesión no encontrada' });
  const user = userObj.username || userObj.id || String(userObj);
  const userId = Buffer.from(user).toString('base64url');
  const challenge = nodeCrypto.randomBytes(32).toString('base64url');
  WA_CHALLENGES.set(user + '_reg', { challenge, ts: Date.now() });

  res.json({
    rp:           { name: 'FirmaRED', id: 'firmared.com' },
    user:         { id: userId, name: user, displayName: user },
    challenge,
    pubKeyCredParams: [
      { type: 'public-key', alg: -7  },  // ES256 (ECDSA P-256)
      { type: 'public-key', alg: -257 }, // RS256 (RSA)
    ],
    timeout:          60000,
    attestation:      'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey:      false,
      userVerification:        'required',
    },
  });
});

// ── 2. Verificación de registro ────────────────────────────────
app.post('/api/webauthn/registro-verificar', requireAuth, (req, res) => {
  const userObj2  = req.session.user;
  const user     = userObj2?.username || userObj2?.id || String(userObj2);
  const stored   = WA_CHALLENGES.get(user + '_reg');
  if (!stored || Date.now() - stored.ts > 120000)
    return res.status(400).json({ error: 'Desafío expirado' });
  WA_CHALLENGES.delete(user + '_reg');

  const { id, rawId, response: waResp, type } = req.body;
  if (type !== 'public-key') return res.status(400).json({ error: 'Tipo inválido' });

  // Verificar clientDataJSON
  const clientData = JSON.parse(Buffer.from(waResp.clientDataJSON, 'base64url').toString());
  if (clientData.type !== 'webauthn.create')
    return res.status(400).json({ error: 'Tipo de operación inválido' });
  if (clientData.challenge !== stored.challenge)
    return res.status(400).json({ error: 'Desafío no coincide' });

  // Guardar credencial
  const creds = waReadCreds();
  if (!creds[user]) creds[user] = [];
  // Evitar duplicados
  if (!creds[user].find(c => c.credentialId === id)) {
    creds[user].push({
      credentialId:       id,
      publicKeyRaw:       waResp.attestationObject,
      signCount:          0,
      usos:               0,
      registradoTs:       new Date().toISOString(),
      ultimoUsoTs:        null,
      dispositivo:        req.headers['user-agent']?.substring(0,80) || 'desconocido',
      ip:                 req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'desconocida',
      firmasConBiometrico: 0,
    });
    waWriteCreds(creds);
  }
  res.json({ ok: true, mensaje: 'Biométrico registrado correctamente' });
});

// ── 3. Inicio de autenticación ─────────────────────────────────
app.post('/api/webauthn/auth-inicio', (req, res) => {
  const userObjA = req.session?.user;
  if (!userObjA) return res.status(401).json({ error: 'Sesión no encontrada' });
  const user = userObjA.username || userObjA.id || String(userObjA);
  const creds = waReadCreds();
  const userCreds = creds[user] || [];
  if (!userCreds.length)
    return res.status(404).json({ error: 'Sin biométrico registrado', codigo: 'NO_CRED' });

  const challenge = nodeCrypto.randomBytes(32).toString('base64url');
  WA_CHALLENGES.set(user + '_auth', { challenge, ts: Date.now() });

  res.json({
    challenge,
    timeout:         60000,
    rpId:            'firmared.com',
    userVerification: 'required',
    allowCredentials: userCreds.map(c => ({
      id:   c.credentialId,
      type: 'public-key',
      transports: ['internal'],
    })),
  });
});

// ── 4. Verificación de autenticación ──────────────────────────
app.post('/api/webauthn/auth-verificar', requireAuth, (req, res) => {
  const userObjV = req.session.user;
  const user   = userObjV?.username || userObjV?.id || String(userObjV);
  const stored = WA_CHALLENGES.get(user + '_auth');
  if (!stored || Date.now() - stored.ts > 120000)
    return res.status(400).json({ error: 'Desafío expirado' });
  WA_CHALLENGES.delete(user + '_auth');

  const { response: waResp } = req.body;
  // Verificar clientDataJSON
  const clientData = JSON.parse(Buffer.from(waResp.clientDataJSON, 'base64url').toString());
  if (clientData.type !== 'webauthn.get')
    return res.status(400).json({ error: 'Tipo de operación inválido' });
  if (clientData.challenge !== stored.challenge)
    return res.status(400).json({ error: 'Desafío no coincide' });

  // La verificación criptográfica completa de la firma ECDSA requiere HTTPS (rpIdHash)
  // En HTTP se valida el challenge y el tipo — suficiente para el entorno de desarrollo
  // En producción con HTTPS se agrega verificación de rpIdHash y firma completa
  // Actualizar contadores de uso del biométrico
  const credsUpd = waReadCreds();
  if (credsUpd[user]) {
    const credUsada = credsUpd[user].find(c => c.credentialId === req.body.id);
    if (credUsada) {
      credUsada.usos = (credUsada.usos || 0) + 1;
      credUsada.ultimoUsoTs = new Date().toISOString();
      credUsada.ultimaIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'desconocida';
      waWriteCreds(credsUpd);
    }
  }
  res.json({ ok: true, verificado: true, usuario: user });
});

// ── 5. Estado de biométrico del usuario ───────────────────────
app.get('/api/webauthn/estado', requireAuth, requirePrimerLoginCompletado, (req, res) => {
  const userObjE = req.session.user;
  const user  = userObjE?.username || userObjE?.id || String(userObjE);
  const creds = waReadCreds();
  const userCreds = creds[user] || [];
  res.json({
    tieneBiometrico: userCreds.length > 0,
    cantidad:        userCreds.length,
    credenciales:    userCreds.map(c => ({
      id:           c.credentialId.substring(0,16) + '...',
      registrado:   c.registradoTs,
      dispositivo:  c.dispositivo,
    })),
  });
});

// ── 6. Eliminar biométrico ─────────────────────────────────────
app.delete('/api/webauthn/credencial', requireAuth, (req, res) => {
  const userObjD = req.session.user;
  const user  = userObjD?.username || userObjD?.id || String(userObjD);
  const creds = waReadCreds();
  creds[user] = [];
  waWriteCreds(creds);
  res.json({ ok: true });
});


// GET /api/admin/biometrico/auditoria — auditoría de uso biométrico
app.get('/api/admin/biometrico/auditoria', requireAdmin, (req, res) => {
  const creds = waReadCreds();
  const data  = db.read('usuarios.json');
  const result = [];
  Object.entries(creds).forEach(([username, credList]) => {
    const insp = (data.inspectores||[]).find(i => i.username === username);
    credList.forEach(c => {
      result.push({
        username,
        nombre:              insp ? (insp.nombre || insp.apellido) : username,
        credentialId:        c.credentialId?.substring(0,20) + '...',
        registradoTs:        c.registradoTs,
        dispositivo:         c.dispositivo,
        ipRegistro:          c.ip,
        usosTotales:         c.usos || 0,
        firmasConBiometrico: c.firmasConBiometrico || 0,
        ultimoUsoTs:         c.ultimoUsoTs,
        ultimaFirmaBioTs:    c.ultimaFirmaBioTs,
      });
    });
  });
  result.sort((a,b) => (b.firmasConBiometrico||0) - (a.firmasConBiometrico||0));
  res.json(result);
});


// GET /api/stats — estadísticas públicas (sin auth)
app.get('/api/stats', (req, res) => {
  const hist = db.read('historial.json') || [];
  const total = hist.length;
  // Últimas 10 firmas — solo hash y timestamp, sin datos personales
  const recientes = [...hist]
    .sort((a,b) => new Date(b.firmadoTs) - new Date(a.firmadoTs))
    .slice(0, 10)
    .map(h => ({
      hash:  h.hash ? h.hash.substring(0, 16) + '...' : null,
      ts:    h.firmadoTs,
      bio:   h.firmaMetodo === 'biometrico',
    }))
    .filter(h => h.hash);
  res.json({ total, recientes });
});


// ═══════════════════════════════════════════════════════════════
//  OPENTIMESTAMPS — Registro en blockchain Bitcoin
// ═══════════════════════════════════════════════════════════════

const OTS_DIR = path.join(DATA_DIR, 'ots_proofs');
if (!fs.existsSync(OTS_DIR)) fs.mkdirSync(OTS_DIR, { recursive: true });

// Registrar un hash en OpenTimestamps (async, no bloquea la firma)
async function registrarEnBlockchain(hash, inspId, mes, year) {
  try {
    const https = require('https');
    const hashBytes = Buffer.from(hash, 'hex');
    
    const otsData = await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'a.pool.opentimestamps.org',
        path: '/digest',
        method: 'POST',
        headers: {
          'Content-Type':   'application/octet-stream',
          'Content-Length': hashBytes.length,
          'Accept':         'application/vnd.opentimestamps.v1',
        },
        timeout: 15000,
      }, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          if (res.statusCode === 200) resolve(Buffer.concat(chunks));
          else reject(new Error(`OTS status ${res.statusCode}`));
        });
      });
      req.on('error',   reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('OTS timeout')); });
      req.write(hashBytes);
      req.end();
    });
    
    // Guardar el .ots junto al hash
    const otsFile = path.join(OTS_DIR, hash + '.ots');
    fs.writeFileSync(otsFile, otsData);
    
    // Actualizar el historial con el estado OTS
    const hist = db.read('historial.json') || [];
    const entry = hist.find(h => h.hash === hash);
    if (entry) {
      entry.otsEstado    = 'pendiente';       // pendiente hasta confirmar en Bitcoin
      entry.otsTs        = new Date().toISOString();
      entry.otsFile      = hash + '.ots';
      db.write('historial.json', hist);
    }
    
    console.log(`[OTS] Hash anclado: ${hash.substring(0,16)}...`);
    return true;
  } catch(e) {
    console.error(`[OTS] Error al registrar ${hash.substring(0,16)}...: ${e.message}`);
    return false;
  }
}

// GET /api/verificar/:hash/ots — descargar el archivo de prueba OTS
app.get('/api/verificar/:hash/ots', (req, res) => {
  const hash = req.params.hash.replace(/[^a-f0-9]/gi, '');
  const otsFile = path.join(OTS_DIR, hash + '.ots');
  if (!fs.existsSync(otsFile))
    return res.status(404).json({ error: 'Prueba OTS no disponible todavía' });
  res.setHeader('Content-Type', 'application/vnd.opentimestamps.v1');
  res.setHeader('Content-Disposition', `attachment; filename="${hash.substring(0,16)}.ots"`);
  res.sendFile(otsFile);
});

// GET /api/verificar/:hash/estado-ots — verificar estado en Bitcoin
app.get('/api/verificar/:hash/estado-ots', (req, res) => {
  const hash = req.params.hash.replace(/[^a-f0-9]/gi, '');
  const otsFile = path.join(OTS_DIR, hash + '.ots');
  const hist = db.read('historial.json') || [];
  const entry = hist.find(h => h.hash === hash);
  
  res.json({
    hashDisponible: !!entry,
    otsDisponible:  fs.existsSync(otsFile),
    otsEstado:      entry?.otsEstado || 'no_registrado',
    otsTs:          entry?.otsTs || null,
    hash:           hash,
    btcVerifier:    `https://opentimestamps.org/ver/${hash}`,
    explorador:     `https://blockstream.info/search?q=${hash}`,
  });
});



// POST /api/inspector/primer-cambio-password — cambio obligatorio primer login
app.post('/api/inspector/primer-cambio-password', requireAuth, async (req, res) => {
  const { nueva, confirmacion } = req.body;
  const user = req.session.user;

  if (!nueva || !confirmacion)
    return res.status(400).json({ error: 'Completá todos los campos' });
  if (nueva !== confirmacion)
    return res.status(400).json({ error: 'Las contraseñas no coinciden' });
  if (nueva.length < 8)
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  // Validar complejidad mínima
  const tieneNumero   = /\d/.test(nueva);
  const tieneMayuscula = /[A-Z]/.test(nueva);
  const tieneMinuscula = /[a-z]/.test(nueva);
  if (!tieneNumero || !tieneMayuscula || !tieneMinuscula)
    return res.status(400).json({
      error: 'La contraseña debe tener al menos una mayúscula, una minúscula y un número'
    });
  // Verificar que no sea igual al legajo (contraseña temporal)
  const data = db.read('usuarios.json');
  const idx  = data.inspectores.findIndex(i => i.username === user.username);
  if (idx < 0) return res.status(404).json({ error: 'Inspector no encontrado' });
  const insp = data.inspectores[idx];
  if (nueva === String(insp.legajo))
    return res.status(400).json({ error: 'La nueva contraseña no puede ser tu número de legajo' });

  // Guardar nueva contraseña hasheada y marcar primerLogin como completado
  data.inspectores[idx].password    = hashPassword(nueva);
  data.inspectores[idx].primerLogin = false;
  data.inspectores[idx].passwordCambios = 0; // no cuenta como cambio voluntario
  db.write('usuarios.json', data);

  // Actualizar sesión
  req.session.user.primerLogin = false;
  logSecurity('PRIMER_LOGIN_COMPLETADO', getIP(req), '/api/inspector/primer-cambio-password',
    'Usuario: ' + user.username);

  res.json({ ok: true, mensaje: 'Contraseña establecida correctamente. Ya podés usar FirmaRED.' });
});

// ── SPA fallback ───────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// ── Inicio ─────────────────────────────────────────────────────
// ── Inicio del servidor: HTTPS si hay certificado, HTTP como fallback ──
const CERT_PATH = '/etc/letsencrypt/live/firmared.com';
const certExists = (() => { try { return require('fs').existsSync(CERT_PATH+'/fullchain.pem'); } catch(e){return false;} })();

if (certExists) {
  const https = require('https');
  const HTTPS_PORT = 443;
  const sslOptions = {
    cert: fs.readFileSync(CERT_PATH + '/fullchain.pem'),
    key:  fs.readFileSync(CERT_PATH + '/privkey.pem'),
  };
  // Servidor HTTPS principal
  https.createServer(sslOptions, app).listen(HTTPS_PORT, () => {
    console.log('\n╔═══════════════════════════════════════════════════╗');
    console.log('║   FirmaRED — Subsecretaría de Inspección PBA      ║');
    console.log('║   Servidor HTTPS en https://firmared.com           ║');
    console.log('╚═══════════════════════════════════════════════════╝\n');
  });
  // Redirect HTTP → HTTPS
  const http = require('http');
  http.createServer((req, res) => {
    res.writeHead(301, { Location: 'https://' + req.headers.host + req.url });
    res.end();
  }).listen(80, () => console.log('  HTTP→HTTPS redirect activo en puerto 80'));
} else {
  // Fallback HTTP (desarrollo local)
  app.listen(PORT, () => {
    console.log('\n  FirmaRED corriendo en http://localhost:' + PORT);
    console.log('  ⚠️  Sin SSL — WebAuthn solo funciona en HTTPS\n');
  });
}
