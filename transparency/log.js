/**
 * FirmaRED Document Transparency Log v1
 * Registro público append-only de verificaciones — inspirado en Certificate Transparency
 * Estructura: árbol Merkle SHA-256, auditable independientemente
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const LOG_FILE = path.join(__dirname, '..', 'data', 'transparency.json');

// ── Árbol Merkle ────────────────────────────────────────────
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

const merkleRoot = (leaves) => {
  if (!leaves.length) return sha256('empty');
  if (leaves.length === 1) return leaves[0];
  const pairs = [];
  for (let i = 0; i < leaves.length; i += 2) {
    const left  = leaves[i];
    const right = leaves[i+1] || left;
    pairs.push(sha256(left + right));
  }
  return merkleRoot(pairs);
};

// ── Estado del log ───────────────────────────────────────────
const loadLog = () => {
  if (!fs.existsSync(LOG_FILE)) return { entries: [], root: sha256('genesis'), size: 0 };
  try { return JSON.parse(fs.readFileSync(LOG_FILE, 'utf8')); }
  catch { return { entries: [], root: sha256('genesis'), size: 0 }; }
};

const saveLog = (log) => {
  fs.writeFileSync(LOG_FILE, JSON.stringify(log, null, 2));
};

// ── Agregar entrada al log ───────────────────────────────────
const appendEntry = (tipo, hash, metadata = {}) => {
  const log = loadLog();
  const entry = {
    index:     log.size,
    timestamp: new Date().toISOString(),
    tipo,                     // 'verificacion' | 'firma' | 'anclaje'
    hash,                     // SHA-256 del documento
    metadata,                 // datos públicos sin PII
    prevRoot:  log.root,
  };

  // Hash de la entrada completa
  entry.entryHash = sha256(JSON.stringify({
    index: entry.index, timestamp: entry.timestamp,
    tipo: entry.tipo, hash: entry.hash, prevRoot: entry.prevRoot
  }));

  // Actualizar raíz Merkle
  // Hojas en orden cronológico (entry más reciente al final)
  const allEntries = [...log.entries].reverse();
  const leaves = [...allEntries.map(e => e.entryHash), entry.entryHash];
  entry.merkleRoot = merkleRoot(leaves);

  log.entries.unshift(entry); // más reciente primero
  if (log.entries.length > 1000) log.entries = log.entries.slice(0, 1000);
  log.root = entry.merkleRoot;
  log.size = (log.size || 0) + 1;
  log.lastUpdated = entry.timestamp;

  saveLog(log);
  return entry;
};

// ── Verificar integridad del log ─────────────────────────────
const verifyLog = () => {
  const log = loadLog();
  if (!log.entries.length) return { ok: true, reason: 'Log vacío' };

  // Reconstruir raíz desde las entradas
  // Orden cronológico para verificación
  const leaves = [...log.entries].reverse().map(e => e.entryHash);
  const computed = merkleRoot(leaves);
  const ok = computed === log.root;

  return {
    ok,
    size: log.size,
    root: log.root,
    computed,
    reason: ok ? 'Integridad verificada' : 'ALERTA: raíz Merkle no coincide — log posiblemente manipulado'
  };
};

// ── Prueba de inclusión ──────────────────────────────────────
const proofOfInclusion = (hash) => {
  const log = loadLog();
  const entry = log.entries.find(e => e.hash === hash);
  if (!entry) return { incluido: false };
  return {
    incluido:    true,
    index:       entry.index,
    timestamp:   entry.timestamp,
    tipo:        entry.tipo,
    entryHash:   entry.entryHash,
    merkleRoot:  entry.merkleRoot,
    prevRoot:    entry.prevRoot,
  };
};

module.exports = { appendEntry, verifyLog, proofOfInclusion, loadLog };
