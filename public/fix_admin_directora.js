#!/usr/bin/env node
// Corregir acceso baccegam — asegurar rol admin, quitar de inspectores si existe
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const FILE        = path.join(__dirname, 'data', 'usuarios.json');
const SALT_SECRET = process.env.SALT_SECRET || 'firmared-pba-2026-salt';

function hashPassword(p) {
  return crypto.pbkdf2Sync(String(p), SALT_SECRET, 10000, 32, 'sha256').toString('hex');
}

const data = JSON.parse(fs.readFileSync(FILE, 'utf8'));

// 1. Quitar de inspectores si existe
const antesInsp = data.inspectores.length;
data.inspectores = data.inspectores.filter(i => i.username !== 'baccegam');
if (data.inspectores.length < antesInsp)
  console.log('🗑  baccegam eliminado de inspectores');

// 2. Quitar de admins si existe (para recrear limpio)
data.admins = data.admins.filter(a => a.username !== 'baccegam');

// 3. Agregar como superusuario admin
data.admins.push({
  id:          'baccegam',
  username:    'baccegam',
  password:    hashPassword('601615'),
  nombre:      'Directora Provincial',
  legajo:      '601615',
  role:        'admin',
  primerLogin: true,
});

fs.writeFileSync(FILE, JSON.stringify(data, null, 2));
console.log('✅ baccegam creado como ADMIN superusuario');
console.log('   Usuario:           baccegam');
console.log('   Contraseña inicial: 601615');
console.log('   Al primer ingreso deberá establecer una contraseña personal.');
