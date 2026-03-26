/**
 * FirmaRED DSS Validator v2 — Puerto 8081
 * Valida firmas PAdES/PKCS7 embebidas en PDFs
 * Soporta: DocuSign Standards-Based, Adobe Sign, ZapSign, FirmaUY, AC ONTI Argentina
 */

const http      = require('http');
const fs        = require('fs');
const path      = require('path');
const os        = require('os');
const crypto    = require('crypto');
const { execSync, spawnSync } = require('child_process');

const TRUST_DIR = path.join(__dirname, '..', 'trust-store', 'latam');
const PORT      = 8081;

// ══════════════════════════════════════════════════════════════
// 1. TRUST BUNDLE — carga TODOS los certs del directorio
// ══════════════════════════════════════════════════════════════
const buildTrustBundle = () => {
  const files = fs.readdirSync(TRUST_DIR).filter(f => f.endsWith('.crt') || f.endsWith('.cer'));
  let bundle = '';
  let count  = 0;
  const cargados = [];

  for (const file of files) {
    const ruta = path.join(TRUST_DIR, file);
    try {
      // Intentar PEM primero, luego DER
      let pem = '';
      const content = fs.readFileSync(ruta);
      if (content.toString('utf8').includes('-----BEGIN CERTIFICATE-----')) {
        pem = content.toString('utf8');
      } else {
        const r = spawnSync('openssl', ['x509', '-inform', 'DER', '-in', ruta, '-out', '-'],
          { encoding: 'utf8' });
        if (r.stdout && r.stdout.includes('BEGIN CERTIFICATE')) pem = r.stdout;
      }
      if (pem) {
        bundle += pem + '\n';
        const subj = spawnSync('openssl', ['x509', '-noout', '-subject'],
          { input: pem, encoding: 'utf8' }).stdout.trim();
        cargados.push({ file, subject: subj });
        count++;
      }
    } catch(e) {
      console.error('[DSS] Error cargando', file, ':', e.message);
    }
  }

  const tmpBundle = path.join(os.tmpdir(), 'firmared-bundle.pem');
  fs.writeFileSync(tmpBundle, bundle);
  console.log(`[DSS] Trust bundle: ${count} certificados cargados`);
  cargados.forEach(c => console.log(`  ✓ ${c.file}: ${c.subject.substring(0,60)}`));
  return { bundle: tmpBundle, count, cargados };
};

let TRUST = buildTrustBundle();

// Recargar bundle cada hora (por si se agregan certs sin reiniciar)
setInterval(() => {
  TRUST = buildTrustBundle();
  console.log('[DSS] Trust bundle recargado:', TRUST.count, 'certs');
}, 3600 * 1000);

// ══════════════════════════════════════════════════════════════
// 2. EXTRACCIÓN DE FIRMA PAdES del PDF
// ══════════════════════════════════════════════════════════════
const extractPAdESSignatures = (pdfBuffer) => {
  const sigs = [];
  const pdfStr = pdfBuffer.toString('latin1');

  // Buscar todos los /ByteRange en el PDF
  const byteRangeRegex = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  const contentsRegex  = /\/Contents\s*<([0-9A-Fa-f]+)>/g;

  let brMatch, ctMatch;
  const byteRanges = [];
  const contents   = [];

  while ((brMatch = byteRangeRegex.exec(pdfStr)) !== null) {
    byteRanges.push([
      parseInt(brMatch[1]), parseInt(brMatch[2]),
      parseInt(brMatch[3]), parseInt(brMatch[4])
    ]);
  }
  while ((ctMatch = contentsRegex.exec(pdfStr)) !== null) {
    contents.push(ctMatch[1]);
  }

  for (let i = 0; i < Math.min(byteRanges.length, contents.length); i++) {
    try {
      const pkcs7Hex = contents[i];
      if (pkcs7Hex.length < 100) continue;
      const pkcs7Buf = Buffer.from(pkcs7Hex, 'hex');
      // Verificar que empieza con secuencia DER (0x30)
      if (pkcs7Buf[0] !== 0x30) continue;
      sigs.push({ byteRange: byteRanges[i], pkcs7: pkcs7Buf, index: i });
    } catch(e) {}
  }

  return sigs;
};

// ══════════════════════════════════════════════════════════════
// 3. VERIFICACIÓN PKCS7 con OpenSSL contra trust store completo
// ══════════════════════════════════════════════════════════════
const verifyPKCS7 = (pkcs7Buffer, pdfBuffer, byteRange) => {
  const tmpSig     = path.join(os.tmpdir(), `sig_${Date.now()}.p7b`);
  const tmpContent = path.join(os.tmpdir(), `content_${Date.now()}.bin`);
  const tmpCerts   = path.join(os.tmpdir(), `certs_${Date.now()}.pem`);

  try {
    // Guardar la firma PKCS7
    fs.writeFileSync(tmpSig, pkcs7Buffer);

    // Extraer el contenido firmado (los bytes cubiertos por ByteRange)
    const [o1, l1, o2, l2] = byteRange;
    const part1 = pdfBuffer.slice(o1, o1 + l1);
    const part2 = pdfBuffer.slice(o2, o2 + l2);
    const signedContent = Buffer.concat([part1, part2]);
    fs.writeFileSync(tmpContent, signedContent);

    // Extraer certificados del PKCS7
    const certExtract = spawnSync('openssl', [
      'pkcs7', '-inform', 'DER', '-in', tmpSig,
      '-print_certs', '-out', tmpCerts
    ], { encoding: 'utf8' });

    // Extraer info del firmante
    let signerInfo = {};
    if (certExtract.status === 0 && fs.existsSync(tmpCerts)) {
      const certsContent = fs.readFileSync(tmpCerts, 'utf8');
      if (certsContent.includes('BEGIN CERTIFICATE')) {
        const subjR = spawnSync('openssl', ['x509', '-noout', '-subject', '-issuer', '-dates', '-serial'],
          { input: certsContent.split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----',
            encoding: 'utf8' });
        const subjText = subjR.stdout || '';
        signerInfo = {
          subject: subjText.match(/subject=(.+)/)?.[1]?.trim() || '',
          issuer:  subjText.match(/issuer=(.+)/)?.[1]?.trim()  || '',
          desde:   subjText.match(/notBefore=(.+)/)?.[1]?.trim() || '',
          hasta:   subjText.match(/notAfter=(.+)/)?.[1]?.trim()  || '',
          serial:  subjText.match(/serial=(.+)/)?.[1]?.trim()    || '',
        };

        // Extraer nombre del firmante del Subject
        const cn = signerInfo.subject.match(/CN\s*=\s*([^,]+)/)?.[1]?.trim();
        const o  = signerInfo.subject.match(/O\s*=\s*([^,]+)/)?.[1]?.trim();
        signerInfo.nombre    = cn || o || 'Desconocido';
        signerInfo.organismo = o  || '';

        // Detectar plataforma por el issuer
        const issuer = signerInfo.issuer || '';
        if (issuer.includes('DigiCert'))   signerInfo.plataforma = 'DocuSign Standards-Based';
        else if (issuer.includes('GlobalSign')) signerInfo.plataforma = 'Adobe Sign / ZapSign';
        else if (issuer.includes('ONTI'))       signerInfo.plataforma = 'AC ONTI Argentina';
        else if (issuer.includes('MODERNIZ'))   signerInfo.plataforma = 'AC Modernización PFDR';
        else if (issuer.includes('AGESIC'))     signerInfo.plataforma = 'FirmaUY Uruguay';
        else if (issuer.includes('ICP-Brasil')) signerInfo.plataforma = 'ICP-Brasil';
        else signerInfo.plataforma = 'Firma Digital PKI';
      }
    }

    // Verificar firma contra trust bundle completo (modo detached: firma + contenido)
    const verify = spawnSync('openssl', [
      'cms', '-verify',
      '-in',       tmpSig,    '-inform', 'DER',
      '-content',  tmpContent,
      '-CAfile',   TRUST.bundle,
      '-purpose',  'any',
    ], { encoding: 'utf8' });

    const validada = verify.status === 0;
    const verError = verify.stderr?.trim() || '';

    // Si falla cadena completa, intentar sin verificar cadena (detects signature integrity)
    let integridadOK = validada;
    if (!validada) {
      const verify2 = spawnSync('openssl', [
        'cms', '-verify',
        '-in',       tmpSig,    '-inform', 'DER',
        '-content',  tmpContent,
        '-CAfile',   TRUST.bundle,
        '-purpose',  'any',
        '-noverify',
      ], { encoding: 'utf8' });
      integridadOK = verify2.status === 0;
    }

    return {
      firmada:         true,
      validaContraCA:  validada,
      integridadOK,
      firmante:        signerInfo,
      error:           validada ? null : verError.substring(0, 300),
    };

  } catch(e) {
    return { firmada: true, validaContraCA: false, integridadOK: false,
      error: e.message };
  } finally {
    [tmpSig, tmpContent, tmpCerts].forEach(f => { try { fs.unlinkSync(f); } catch {} });
  }
};

// ══════════════════════════════════════════════════════════════
// 4. VALIDATE PDF — función principal
// ══════════════════════════════════════════════════════════════
const validatePDF = (pdfBuffer) => {
  // Extraer hash SHA-256 del PDF
  const hashPDF = crypto.createHash('sha256').update(pdfBuffer).digest('hex');

  // Leer metadatos FirmaRED (campo Subject)
  const pdfStr = pdfBuffer.toString('latin1');
  const subjectMatch = pdfStr.match(/\/Subject\s*\(([^)]+)\)/);
  const hashMeta = subjectMatch?.[1] || null;

  // Buscar firmas PAdES
  const firmas = extractPAdESSignatures(pdfBuffer);

  if (firmas.length === 0) {
    return {
      tieneFirmaPKCS7:    false,
      hashEnMetadatos:    hashMeta,
      hashPDF,
      firmas:             [],
      resumen:            'El PDF no contiene firmas digitales PAdES/PKCS7',
    };
  }

  // Verificar cada firma encontrada
  const resultados = firmas.map((sig, idx) => ({
    indice: idx + 1,
    ...verifyPKCS7(sig.pkcs7, pdfBuffer, sig.byteRange),
  }));

  const todasValidas   = resultados.every(r => r.validaContraCA);
  const integridadOK   = resultados.every(r => r.integridadOK);
  const plataformas    = [...new Set(resultados.map(r => r.firmante?.plataforma).filter(Boolean))];
  const firmantes      = resultados.map(r => r.firmante?.nombre).filter(Boolean);

  return {
    tieneFirmaPKCS7:    true,
    cantidadFirmas:     firmas.length,
    validadaContraCA:   todasValidas,
    integridadDocumento: integridadOK,
    hashEnMetadatos:    hashMeta,
    hashPDF,
    plataformas,
    firmantes,
    firmas:             resultados,
    resumen: todasValidas
      ? `Firma válida — ${firmantes.join(', ')} via ${plataformas.join(', ')}`
      : integridadOK
        ? `Firma auténtica pero emisor no en trust store LATAM (${plataformas.join(', ')})`
        : 'Firma inválida o documento alterado',
  };
};

// ══════════════════════════════════════════════════════════════
// 5. SERVIDOR HTTP
// ══════════════════════════════════════════════════════════════
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'GET' && req.url === '/health') {
    return res.end(JSON.stringify({
      ok: true, port: PORT,
      trustCerts: TRUST.count,
      certs: TRUST.cargados.map(c => c.file),
    }));
  }

  if (req.method === 'POST' && req.url === '/validate') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        const body   = JSON.parse(Buffer.concat(chunks).toString());
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
  console.log(`[DSS Validator v2] Puerto ${PORT} — Trust store: ${TRUST.count} certs`);
});
