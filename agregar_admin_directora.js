#!/usr/bin/env node
// Agregar Directora Provincial como admin
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const FILE = path.join(__dirname, 'data', 'usuarios.json');
const SALT_SECRET = process.env.SALT_SECRET || 'firmared-pba-2026-salt';

function hashPassword(password) {
  return crypto.pbkdf2Sync(String(password), SALT_SECRET, 10000, 32, 'sha256').toString('hex');
}

const data = JSON.parse(fs.readFileSync(FILE, 'utf8'));

// Verificar que no exista
const yaExiste = data.admins.find(a => a.username === 'baccegam');
if (yaExiste) {
  console.log('⚠️  El usuario baccegam ya existe.');
  process.exit(0);
}

const nuevoAdmin = {
  id:       'baccegam',
  username: 'baccegam',
  password: hashPassword('601615'), // contraseña inicial = legajo
  nombre:   'Directora Provincial',
  legajo:   '601615',
  role:     'admin',
  primerLogin: true, // deberá cambiar la contraseña al primer ingreso
};

data.admins.push(nuevoAdmin);
fs.writeFileSync(FILE, JSON.stringify(data, null, 2));

console.log('✅ Admin creado: baccegam');
console.log('   Contraseña inicial: 601615 (deberá cambiarla al primer login)');
