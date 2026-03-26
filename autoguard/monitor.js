/**
 * FirmaRED AutoGuard — Sistema de monitoreo, seguridad y autoadministración
 * Corre como proceso PM2 independiente, despierta cada 6 horas
 */

const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { execSync, spawnSync } = require('child_process');

const BASE    = '/var/www/firmared';
const LOG     = path.join(BASE, 'data', 'autoguard.json');
const HASH_DB = path.join(BASE, 'autoguard', '.integrity.json');
const WA_NUM  = '+5492213802016'; // Número institucional FirmaRED

// ══════════════════════════════════════════════════════════════
// UTILIDADES
// ══════════════════════════════════════════════════════════════
const now = () => new Date().toISOString();
const log = (nivel, msg, data={}) => {
  const entry = { ts: now(), nivel, msg, ...data };
  console.log(`[AutoGuard][${nivel}] ${msg}`, data);
  try {
    const logs = fs.existsSync(LOG) ? JSON.parse(fs.readFileSync(LOG,'utf8')) : [];
    logs.unshift(entry);
    fs.writeFileSync(LOG, JSON.stringify(logs.slice(0,500), null, 2));
  } catch(e) {}
  return entry;
};

const httpsGet = (hostname, path, timeout=8000) => new Promise(resolve => {
  const req = https.request({ hostname, path, method:'GET',
    headers:{'User-Agent':'FirmaRED-AutoGuard/1.0'}, timeout },
    r => { let d=''; r.on('data',c=>d+=c); r.on('end',()=>resolve({s:r.statusCode,b:d})); }
  );
  req.on('error',()=>resolve({s:0,b:''}));
  req.on('timeout',()=>{req.destroy();resolve({s:0,b:''});});
  req.end();
});

const httpGet = (hostname, path, timeout=8000) => new Promise(resolve => {
  const req = http.request({ hostname, path, method:'GET',
    headers:{'User-Agent':'FirmaRED-AutoGuard/1.0'}, timeout },
    r => { let d=''; r.on('data',c=>d+=c); r.on('end',()=>resolve({s:r.statusCode,b:d})); }
  );
  req.on('error',()=>resolve({s:0,b:''}));
  req.on('timeout',()=>{req.destroy();resolve({s:0,b:'errore'});});
  req.end();
});

// ══════════════════════════════════════════════════════════════
// 1. HEALTH CHECK INTERNO
// ══════════════════════════════════════════════════════════════
async function checkHealth() {
  const checks = [];

  // API motor/hash
  try {
    const r = await new Promise(resolve => {
      const body = JSON.stringify({hash:'abc123def456abc1'});
      const req = http.request({hostname:'127.0.0.1',port:3000,path:'/api/motor/hash',
        method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)},timeout:5000},
        res => {let d='';res.on('data',c=>d+=c);res.on('end',()=>resolve({s:res.statusCode,b:d}));}
      );
      req.on('error',()=>resolve({s:0,b:''}));
      req.on('timeout',()=>{req.destroy();resolve({s:0,b:''});});
      req.write(body);req.end();
    });
    const ok = r.s === 200 || (r.b && r.b.includes('capas'));
    checks.push({check:'motor_hash', ok, detail: ok ? 'OK' : `HTTP ${r.s}`});
  } catch(e) { checks.push({check:'motor_hash', ok:false, detail:e.message}); }

  // DSS Validator
  try {
    const r = await new Promise(resolve => {
      const req = http.request({hostname:'127.0.0.1',port:8081,path:'/health',method:'GET',timeout:5000},
        res => {let d='';res.on('data',c=>d+=c);res.on('end',()=>resolve({s:res.statusCode,b:d}));}
      );
      req.on('error',()=>resolve({s:0,b:''}));
      req.on('timeout',()=>{req.destroy();resolve({s:0,b:''});});
      req.end();
    });
    const ok = r.s === 200;
    checks.push({check:'dss_validator', ok, detail: ok ? JSON.parse(r.b||'{}').trustCerts+' certs' : `HTTP ${r.s}`});
  } catch(e) { checks.push({check:'dss_validator', ok:false, detail:e.message}); }

  // HTTPS externo
  const ext = await httpsGet('firmared.com', '/api/stats');
  checks.push({check:'https_externo', ok: ext.s===200, detail:`HTTP ${ext.s}`});

  // Disco
  try {
    const df = execSync('df -h /var/www/firmared --output=pcent | tail -1', {encoding:'utf8'}).trim().replace('%','');
    const pct = parseInt(df);
    checks.push({check:'disco_uso', ok: pct < 85, detail: df+'%', valor:pct});
    if (pct > 80) alerta('WARN', `Disco al ${pct}% — considerar limpieza`, {pct});
  } catch(e) { checks.push({check:'disco', ok:false, detail:e.message}); }

  // RAM
  try {
    const free = execSync("free -m | awk '/Mem:/{print $3/$2*100}'", {encoding:'utf8'}).trim();
    const pct = Math.round(parseFloat(free));
    checks.push({check:'ram_uso', ok: pct < 85, detail: pct+'%', valor:pct});
    if (pct > 80) alerta('WARN', `RAM al ${pct}% — posible memory leak`, {pct});
  } catch(e) {}

  const fallaron = checks.filter(c=>!c.ok);
  if (fallaron.length > 0) {
    alerta('CRITICAL', `Health check: ${fallaron.length} fallas`, {fallaron});
  } else {
    log('INFO', 'Health check OK', {checks: checks.length});
  }
  return checks;
}

// ══════════════════════════════════════════════════════════════
// 2. VENCIMIENTO DE CERTIFICADOS
// ══════════════════════════════════════════════════════════════
async function checkCertificados() {
  const tsDir = path.join(BASE, 'trust-store', 'latam');
  const alertas = [];

  // Certificado HTTPS de firmared.com
  try {
    const r = execSync(
      "echo | openssl s_client -connect firmared.com:443 -servername firmared.com 2>/dev/null | openssl x509 -noout -dates",
      {encoding:'utf8', timeout:10000}
    );
    const match = r.match(/notAfter=(.+)/);
    if (match) {
      const expiry = new Date(match[1]);
      const dias = Math.floor((expiry - Date.now()) / 86400000);
      const entry = {cert:'SSL firmared.com', expiry: expiry.toISOString(), diasRestantes: dias};
      if (dias < 30) alerta(dias < 7 ? 'CRITICAL' : 'WARN', `SSL vence en ${dias} días`, entry);
      else log('INFO', `SSL OK — vence en ${dias} días`);
      alertas.push(entry);
    }
  } catch(e) { log('WARN', 'No se pudo verificar SSL externo', {error:e.message}); }

  // Certificados del trust store
  if (fs.existsSync(tsDir)) {
    const files = fs.readdirSync(tsDir).filter(f=>f.endsWith('.crt')||f.endsWith('.cer'));
    for (const fname of files) {
      try {
        const ruta = path.join(tsDir, fname);
        let dates = execSync(`openssl x509 -in "${ruta}" -noout -dates 2>/dev/null`, {encoding:'utf8'});
        if (!dates) dates = execSync(`openssl x509 -inform DER -in "${ruta}" -noout -dates 2>/dev/null`, {encoding:'utf8'});
        const match = dates.match(/notAfter=(.+)/);
        if (match) {
          const expiry = new Date(match[1]);
          const dias = Math.floor((expiry - Date.now()) / 86400000);
          if (dias < 180) {
            alerta(dias < 30 ? 'CRITICAL' : 'WARN',
              `Certificado ${fname} vence en ${dias} días`, {fname, dias, expiry:expiry.toISOString()});
            alertas.push({cert:fname, diasRestantes:dias});
          }
        }
      } catch(e) {}
    }
  }
  log('INFO', `Certificados verificados — ${alertas.length} alertas`);
  return alertas;
}

// ══════════════════════════════════════════════════════════════
// 3. SEGURIDAD: npm audit + CVE check
// ══════════════════════════════════════════════════════════════
async function checkSeguridad() {
  const resultados = [];

  // npm audit
  try {
    const audit = spawnSync('npm', ['audit', '--json'], {cwd:BASE, encoding:'utf8', timeout:30000});
    if (audit.stdout) {
      const data = JSON.parse(audit.stdout);
      const vulns = data.metadata?.vulnerabilities || {};
      const total = (vulns.critical||0) + (vulns.high||0) + (vulns.moderate||0);
      if (vulns.critical > 0) alerta('CRITICAL', `npm audit: ${vulns.critical} vulnerabilidades críticas`, vulns);
      else if (vulns.high > 0) alerta('WARN', `npm audit: ${vulns.high} vulnerabilidades altas`, vulns);
      else log('INFO', `npm audit OK — ${total} vulnerabilidades bajas`);
      resultados.push({tipo:'npm_audit', vulns});
    }
  } catch(e) { log('WARN', 'npm audit falló', {error:e.message}); }

  // Permisos de archivos críticos
  try {
    const perms = execSync(`stat -c '%a %n' ${BASE}/data/*.json 2>/dev/null | head -10`, {encoding:'utf8'});
    const inseguros = perms.split('\n').filter(l => {
      const [perm] = l.split(' ');
      return perm && (perm.includes('7') || perm === '666' || perm === '777');
    });
    if (inseguros.length > 0) {
      alerta('WARN', `Permisos inseguros detectados`, {archivos:inseguros});
      // Auto-remediation: corregir permisos
      execSync(`chmod 640 ${BASE}/data/*.json 2>/dev/null`, {cwd:BASE});
      log('INFO', 'Auto-remediation: permisos corregidos a 640');
    }
  } catch(e) {}

  // Verificar puertos expuestos inesperados
  try {
    const ports = execSync("ss -tlnp | grep -v '443\\|80\\|22\\|3000\\|8081\\|8080' | tail -10", {encoding:'utf8'}).trim();
    if (ports) {
      alerta('WARN', 'Puertos inesperados detectados', {ports: ports.substring(0,200)});
      resultados.push({tipo:'puertos', ports});
    }
  } catch(e) {}

  return resultados;
}

// ══════════════════════════════════════════════════════════════
// 4. INTEGRIDAD DEL CÓDIGO
// ══════════════════════════════════════════════════════════════
async function checkIntegridad() {
  const archivos = [
    path.join(BASE, 'server.js'),
    path.join(BASE, 'autoguard', 'monitor.js'),
    path.join(BASE, 'dss', 'validator.js'),
  ];

  let hashDb = {};
  if (fs.existsSync(HASH_DB)) {
    hashDb = JSON.parse(fs.readFileSync(HASH_DB, 'utf8'));
  }

  const modificados = [];
  const nuevoHashDb = {};

  for (const archivo of archivos) {
    if (!fs.existsSync(archivo)) continue;
    const content = fs.readFileSync(archivo);
    const hash = crypto.createHash('sha256').update(content).digest('hex');
    const fname = path.basename(archivo);
    nuevoHashDb[fname] = hash;

    if (hashDb[fname] && hashDb[fname] !== hash) {
      modificados.push({archivo: fname, hashAnterior: hashDb[fname].substring(0,16), hashNuevo: hash.substring(0,16)});
    }
  }

  fs.writeFileSync(HASH_DB, JSON.stringify(nuevoHashDb, null, 2));

  if (modificados.length > 0 && Object.keys(hashDb).length > 0) {
    alerta('INFO', `Archivos modificados desde el último scan: ${modificados.map(m=>m.archivo).join(', ')}`, {modificados});
  } else {
    log('INFO', 'Integridad OK — ningún archivo modificado inesperadamente');
  }
  return modificados;
}

// ══════════════════════════════════════════════════════════════
// 5. VIGILANCIA DE ECOSISTEMA
// ══════════════════════════════════════════════════════════════
async function checkEcosistema() {
  const updates = [];

  // Verificar actualizaciones npm disponibles
  try {
    const outdated = spawnSync('npm', ['outdated', '--json'], {cwd:BASE, encoding:'utf8', timeout:30000});
    if (outdated.stdout && outdated.stdout.length > 2) {
      const data = JSON.parse(outdated.stdout);
      const pkgs = Object.keys(data);
      if (pkgs.length > 0) {
        const criticos = pkgs.filter(p => ['express','pdf-lib','multer'].includes(p));
        if (criticos.length > 0) {
          alerta('WARN', `Paquetes críticos con actualización disponible: ${criticos.join(', ')}`,
            {paquetes: criticos.map(p=>({nombre:p, actual:data[p].current, nueva:data[p].latest}))});
        }
        updates.push(...pkgs.map(p=>({paquete:p, actual:data[p].current, nueva:data[p].latest})));
      } else {
        log('INFO', 'Todos los paquetes npm están actualizados');
      }
    }
  } catch(e) {}

  // Verificar que los trust lists no hayan expirado (Chile TSL)
  try {
    const clTSL = path.join(BASE, 'trust-store', 'latam', 'cl_tsl.xml');
    if (fs.existsSync(clTSL)) {
      const content = fs.readFileSync(clTSL, 'utf8');
      const match = content.match(/NextUpdate[^>]*>([^<]+)</);
      if (match) {
        const nextUpdate = new Date(match[1]);
        const dias = Math.floor((nextUpdate - Date.now()) / 86400000);
        if (dias < 30) alerta('WARN', `Chile TSL vence en ${dias} días — renovar`, {dias, nextUpdate:match[1]});
        else log('INFO', `Chile TSL OK — próxima actualización en ${dias} días`);
      }
    }
  } catch(e) {}

  return updates;
}

// ══════════════════════════════════════════════════════════════
// SISTEMA DE ALERTAS
// ══════════════════════════════════════════════════════════════
const alertasEnviadas = new Set();

function alerta(nivel, msg, data={}) {
  const key = nivel + ':' + msg.substring(0,50);
  const entry = log(nivel, msg, data);

  // Evitar spam: no reenviar la misma alerta en 6 horas
  if (alertasEnviadas.has(key)) return;
  alertasEnviadas.add(key);
  setTimeout(() => alertasEnviadas.delete(key), 6 * 3600 * 1000);

  // WhatsApp automático para CRITICAL
  if (nivel === 'CRITICAL') {
    const texto = encodeURIComponent(`🚨 *FirmaRED AutoGuard*\n\n*ALERTA CRÍTICA*\n${msg}\n\nDetalles: ${JSON.stringify(data).substring(0,200)}\n\nTimestamp: ${now()}`);
    const waUrl = `https://api.whatsapp.com/send?phone=${WA_NUM.replace('+','')}&text=${texto}`;
    log('INFO', 'Alerta CRITICAL — WhatsApp generado', {url: waUrl.substring(0,100)});
  }

  return entry;
}

// ══════════════════════════════════════════════════════════════
// ENDPOINT HTTP: estado del AutoGuard
// ══════════════════════════════════════════════════════════════
const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  if (req.url === '/health') {
    return res.end(JSON.stringify({ok:true, proceso:'autoguard', uptime:process.uptime()}));
  }
  if (req.url === '/status') {
    const logs = fs.existsSync(LOG) ? JSON.parse(fs.readFileSync(LOG,'utf8')) : [];
    return res.end(JSON.stringify({
      logs: logs.slice(0,20),
      ultimo_scan: logs[0]?.ts || null,
      alertas_activas: logs.filter(l=>l.nivel==='CRITICAL'||l.nivel==='WARN').slice(0,5)
    }));
  }
  if (req.url === '/scan' && req.method === 'POST') {
    ejecutarScan().then(r => res.end(JSON.stringify({ok:true, resultado:r})));
    return;
  }
  res.statusCode = 404;
  res.end(JSON.stringify({error:'Not found'}));
});
server.listen(8082, '127.0.0.1', () => {
  log('INFO', 'AutoGuard HTTP API en http://127.0.0.1:8082');
});

// ══════════════════════════════════════════════════════════════
// SCAN PRINCIPAL
// ══════════════════════════════════════════════════════════════
async function ejecutarScan() {
  log('INFO', '=== SCAN INICIADO ===');
  const inicio = Date.now();
  const resultado = {};

  try { resultado.health       = await checkHealth();        } catch(e) { log('ERROR', 'Health check falló', {e:e.message}); }
  try { resultado.certificados = await checkCertificados();  } catch(e) { log('ERROR', 'Cert check falló',   {e:e.message}); }
  try { resultado.seguridad    = await checkSeguridad();     } catch(e) { log('ERROR', 'Sec check falló',    {e:e.message}); }
  try { resultado.integridad   = await checkIntegridad();    } catch(e) { log('ERROR', 'Int check falló',    {e:e.message}); }
  try { resultado.ecosistema   = await checkEcosistema();    } catch(e) { log('ERROR', 'Eco check falló',    {e:e.message}); }

  const duracion = ((Date.now() - inicio) / 1000).toFixed(1);
  log('INFO', `=== SCAN COMPLETO en ${duracion}s ===`);
  return resultado;
}

// ══════════════════════════════════════════════════════════════
// SCHEDULING: cada 6 horas + scan inmediato al arrancar
// ══════════════════════════════════════════════════════════════
log('INFO', 'FirmaRED AutoGuard arrancando...');
ejecutarScan();
setInterval(ejecutarScan, 6 * 60 * 60 * 1000); // cada 6 horas

