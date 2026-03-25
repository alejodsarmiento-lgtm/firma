#!/usr/bin/env node
// Inicializar delegados.json con las 46 delegaciones
// Correr UNA vez: node /var/www/firmared/inicializar_delegados.js

const fs   = require('fs');
const path = require('path');
const FILE = path.join(__dirname, 'data', 'delegados.json');

const DELEGACIONES = [
  "9 DE JULIO","ALTE BROWN","AVELLANEDA","AZUL","BAHIA BLANCA",
  "BALCARCE","BARADERO","BRAGADO","CAMPANA","CARMEN DE PATAGONES",
  "CHACABUCO","CHASCOMUS","CHIVILCOY","CORONEL","DOLORES",
  "JOSE C. PAZ","JUNIN","LA MATANZA","LA PLATA","LANUS",
  "LINCOLN","LOBOS","LOMAS DE ZAMORA","LUJAN","MAR DEL PLATA",
  "MERCEDES","MORON","NECOCHEA","OLAVARRIA","PARTIDO DE LA COSTA",
  "PEHUAJO","PERGAMINO","PILAR","QUILMES","SALADILLO",
  "SAN ISIDRO","SAN MARTIN","SAN MIGUEL","SAN NICOLAS","SAN PEDRO",
  "TANDIL","TIGRE","TRENQUE LAUQUEN","TRES ARROYOS","TRES DE FEBRERO",
  "ZARATE"
];

// Leer existente para no perder WhatsApp ya cargados
let existente = [];
try { existente = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch(e) {}

const resultado = DELEGACIONES.map(nombre => {
  const yaExiste = existente.find(d => d.delegacion === nombre);
  return {
    delegacion: nombre,
    whatsapp:   yaExiste?.whatsapp || ''
  };
});

fs.writeFileSync(FILE, JSON.stringify(resultado, null, 2));
console.log(`✅ delegados.json inicializado con ${resultado.length} delegaciones.`);
console.log(`   Con WhatsApp: ${resultado.filter(d=>d.whatsapp).length}`);
console.log(`   Sin WhatsApp: ${resultado.filter(d=>!d.whatsapp).length}`);
