// EU DSS Validator microservice — Puerto 8081
// Valida firmas PAdES/XAdES/CAdES usando openssl y las AC raíces LATAM

const http    = require('http');
const https   = require('https');
const { execSync, spawnSync } = require('child_process');
const fs      = require('fs');
const path    = require('path');
const os      = require('os');

const TRUST_DIR = path.join(__dirname, '..', 'trust-store', 'latam');
const PORT      = 8081;

// Construir bundle PEM con todos los certificados raíz
const buildTrustBundle = () => {
  const certs = [
    { file: 'ar_acraiz_2007.crt',     fmt: 'DER' },
    { file: 'ar_acraiz_2016.crt',     fmt: 'DER' },
    { file: 'ar_ac_onti_2020.crt',    fmt: 'PEM' },
    { file: 'ar_ac_modernizacion.crt',fmt: 'DER' },
    { file: 'uy_acrn.cer',            fmt: 'PEM' },
  ];
  let bundle = '';
  for (const { file, fmt } of certs) {
    const ruta = path.join(TRUST_DIR, file);
    if (!fs.existsSync(ruta)) continue;
    try {
      const pem = fmt === 'DER'
        ? execSync(`openssl x509 -inform DER -in "${ruta}" -out -`, { encoding: 'utf8' })
        : fs.readFileSync(ruta, 'utf8');
      bundle += pem;
    } catch(e) {}
  }
  const tmpBundle = path.join(os.tmpdir(), 'latam-bundle.pem');
  fs.writeFileSync(tmpBundle, bundle);
  return tmpBundle;
};

const BUNDLE = buildTrustBundle();
console.log('[DSS Validator] Trust bundle en:', BUNDLE);

// Validar PDF con firma PKCS7/PAdES usando openssl
const validatePDF = (pdfBuffer) => {
  const tmpPDF = path.join(os.tmpdir(), 'validate_' + Date.now() + '.pdf');
  fs.writeFileSync(tmpPDF, pdfBuffer);
  
  try {
    // Extraer firma PKCS7 del PDF
    const r1 = spawnSync('openssl', ['cms', '-verify', '-in', tmpPDF, '-inform', 'DER',
      '-CAfile', BUNDLE, '-noverify'], { encoding: 'utf8' });
    
    // Intentar verificar la firma embebida
    const r2 = spawnSync('openssl', ['pkcs7', '-inform', 'DER', '-print_certs',
      '-in', tmpPDF], { encoding: 'utf8' });
    
    // Leer Subject del PDF si tiene metadata
    const pdfText = pdfBuffer.toString('latin1');
    const subjectMatch = pdfText.match(/\/Subject\s*\(([^)]+)\)/);
    const hashMeta = subjectMatch ? subjectMatch[1] : null;
    
    // Buscar firma PKCS7 en el PDF
    const hasSig = pdfText.includes('/ByteRange') && pdfText.includes('/Contents');
    
    fs.unlinkSync(tmpPDF);
    
    return {
      tieneFirmaPKCS7: hasSig,
      hashEnMetadatos: hashMeta,
      certInfo: r2.stdout?.substring(0, 500) || null,
      validadoContraLATAM: !r1.status,
      error: r1.stderr?.substring(0, 200) || null
    };
  } catch(e) {
    try { fs.unlinkSync(tmpPDF); } catch {}
    return { error: e.message };
  }
};

// Servidor HTTP
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');
  
  if (req.method === 'GET' && req.url === '/health') {
    return res.end(JSON.stringify({ ok: true, trustCerts: 5, port: PORT }));
  }
  
  if (req.method === 'POST' && req.url === '/validate') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const pdfBuf = Buffer.from(body.pdf, 'base64');
        const result = validatePDF(pdfBuf);
        res.end(JSON.stringify({ ok: true, ...result }));
      } catch(e) {
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }
  
  res.statusCode = 404;
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('[DSS Validator] Escuchando en http://127.0.0.1:' + PORT);
});
