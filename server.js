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

const app  = express();
const PORT = process.env.PORT || 3000;

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
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(PUBLIC_DIR));
app.use(session({
  secret: 'firmared-subsecretaria-pba-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 días
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

// ── Helpers ────────────────────────────────────────────────────
const MESES = ['Enero','Febrero','Marzo','Abril','Mayo','Junio',
               'Julio','Agosto','Septiembre','Octubre','Noviembre','Diciembre'];

function findUser(username, password) {
  const { inspectores = [], admins = [] } = db.read('usuarios.json');
  const admin = admins.find(a => a.username === username.toLowerCase() && a.password === password);
  if (admin) return { ...admin, role: 'admin' };
  const insp = inspectores.find(i => i.username === username.toLowerCase() && i.password === password);
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
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Campos requeridos' });
  const user = findUser(username.trim(), password);
  if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  req.session.user = {
    id:       user.id || user.username,
    username: user.username,
    role:     user.role,
    nombre:   user.nombre || `${cap(user.apellido)}, ${cap(user.nombre)}`
  };
  if (user.role === 'inspector') req.session.user.inspId = user.id;
  res.json({ ok: true, role: user.role, nombre: req.session.user.nombre });
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
app.post('/api/inspector/firma', requireAuth, (req, res) => {
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
app.get('/api/inspector/planilla', requireAuth, (req, res) => {
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
app.get('/api/inspector/ver-planilla/:id', requireAuth, (req, res) => {
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
app.post('/api/inspector/firmar', requireAuth, async (req, res) => {
  if (req.session.user.role !== 'inspector')
    return res.status(403).json({ error: 'Solo para inspectores' });
  try {
    const { planillaId } = req.body;
    const planillas = db.read('planillas_asignadas.json');
    const planIdx = planillas.findIndex(p => p.id === planillaId && p.inspId === req.session.user.inspId && !p.firmada);
    if (planIdx < 0) return res.status(400).json({ error: 'Planilla no encontrada o ya firmada' });
    const plan = planillas[planIdx];
    const insp = getInspector(req.session.user.inspId);
    if (!insp || !insp.firma) return res.status(400).json({ error: 'No tenés firma registrada' });
    // Leer PDF original
    const pdfPath = path.join(PLANILLAS_DIR, plan.filename);
    if (!fs.existsSync(pdfPath)) {
      console.error('PDF no encontrado en disco:', pdfPath, '— el servidor puede haber reiniciado (Render free tier pierde archivos).');
      return res.status(404).json({ error: 'El archivo de planilla no se encontró en el servidor. La asesoría debe volver a subir la planilla.' });
    }
    const pdfBytes = fs.readFileSync(pdfPath);
    // Estampar firma
    const signedBytes = await stamparFirma(pdfBytes, insp.firma, insp);
    // Guardar PDF firmado
    const now        = new Date();
    const signedName = `firmado_${plan.inspId}_${plan.year}_${String(plan.mes+1).padStart(2,'0')}_${Date.now()}.pdf`;
    const signedPath = path.join(FIRMADAS_DIR, signedName);
    fs.writeFileSync(signedPath, signedBytes);
    // Marcar planilla como firmada
    planillas[planIdx].firmada    = true;
    planillas[planIdx].firmadaTs  = now.toISOString();
    planillas[planIdx].signedFile = signedName;
    db.write('planillas_asignadas.json', planillas);
    // Guardar en historial
    const hist = db.read('historial.json');
    hist.push({
      id:         `h${Date.now()}`,
      inspId:     insp.id,
      inspNombre: cap(insp.apellido) + ', ' + cap(insp.nombre),
      inspDni:    insp.dni,
      inspLegajo: insp.legajo,
      mes:        plan.mes,
      mesNombre:  MESES[plan.mes],
      year:       plan.year,
      firmadoTs:  now.toISOString(),
      signedFile: signedName
    });
    db.write('historial.json', hist);
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
app.get('/api/inspector/historial', requireAuth, (req, res) => {
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
  const rows = ['Apellido,Nombre,Legajo,DNI,Usuario,Contraseña'];
  inspectores.forEach(i => {
    rows.push(`"${i.apellido}","${i.nombre}","${i.legajo}","${i.dni}","${i.username}","${i.password}"`);
  });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="credenciales_firmared.csv"');
  res.send('﻿' + rows.join('\n')); // BOM para Excel
});

// 2. Backup de firmas (descarga JSON con todas las firmas registradas)
app.get('/api/admin/backup-firmas', requireAdmin, (req, res) => {
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
    if (data.inspectores[idx].password !== actual) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    const cambios = data.inspectores[idx].passwordCambios || 0;
    if (cambios >= 2) return res.status(403).json({
      error: 'Límite alcanzado. Ya cambiaste tu contraseña 2 veces. Contactá a la asesoría por WhatsApp: +54 9 221 380-2016',
      limite: true
    });
    data.inspectores[idx].password = nueva;
    data.inspectores[idx].passwordCambios = cambios + 1;
  } else {
    const idx = data.admins.findIndex(a => a.username === req.session.user.username);
    if (idx < 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (data.admins[idx].password !== actual) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    data.admins[idx].password = nueva;
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

// ── SPA fallback ───────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// ── Inicio ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════╗
║   FirmaRED — Subsecretaría de Inspección PBA      ║
║   Servidor iniciado en http://localhost:${PORT}      ║
╚═══════════════════════════════════════════════════╝

  Admin:    usuario "admin"     clave "admin2026"
  Directora: usuario "directora" clave "dir2026"
  Asesoría: usuario "asesoria"  clave "ases2026"
  Inspectores: usuario = inicial+apellido / clave = N° legajo
  Ejemplo: Angulo Yamila → yangulo / 601806
`);
});
