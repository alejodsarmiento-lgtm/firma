#!/usr/bin/env node
// Script de migración — marcar inspectores existentes con primerLogin: true
// Correr UNA sola vez en producción: node migrar_primer_login.js

const fs   = require('fs');
const path = require('path');
const DATA = path.join(__dirname, 'data', 'usuarios.json');

const data = JSON.parse(fs.readFileSync(DATA, 'utf8'));
let migrados = 0;
let ya_ok    = 0;

data.inspectores = data.inspectores.map(insp => {
  // Solo marcar los que aún no tienen primerLogin definido
  // (los que tienen password hasheada de 64 chars ya cambiaron la clave)
  if (insp.primerLogin === undefined) {
    const tieneHasheada = insp.password && insp.password.length === 64;
    if (!tieneHasheada) {
      // Contraseña en plano = aún no cambió, marcar primerLogin
      insp.primerLogin = true;
      migrados++;
    } else {
      insp.primerLogin = false;
      ya_ok++;
    }
  } else {
    ya_ok++;
  }
  return insp;
});

fs.writeFileSync(DATA, JSON.stringify(data, null, 2));
console.log(`Migración completa:`);
console.log(`  - ${migrados} inspectores marcados con primerLogin: true`);
console.log(`  - ${ya_ok} inspectores ya estaban ok`);
console.log(`  - Total: ${data.inspectores.length}`);
