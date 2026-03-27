
// FirmaRED — Panel Inspector (tabs + historial + RGPD)
(function() {
  'use strict';

  function iTab(n) {
    [1,2,3].forEach(i => {
      const t=document.getElementById('itab'+i);
      const b=document.getElementById('it'+i);
      if(t) t.style.display = i===n?'block':'none';
      if(b) b.className = 'itab'+(i===n?' on':'');
    });
    if(n===2) cargarHistorialCompleto();
    if(n===3) cargarDatosRGPD();
  }
  window.iTab = iTab;
  window.irAFirmar = () => iTab(1);

  window.cargarHistorialCompleto = async function() {
    const el=document.getElementById('iHistCompleto');
    const tl=document.getElementById('iTlogInfo');
    if(!el) return;
    el.innerHTML='<div style="text-align:center;padding:20px;color:#aaa">Cargando...</div>';
    try {
      const r=await api('GET','/api/inspector/mis-firmas');
      const firmas=r.firmas||[];
      const badge=document.getElementById('badgeHist');
      if(badge&&firmas.length){badge.textContent=firmas.length;badge.style.display='inline';}
      if(!firmas.length){el.innerHTML='<div style="text-align:center;padding:30px;color:#aaa"><div style="font-size:32px">📭</div><p>Sin firmas registradas</p></div>';return;}
      el.innerHTML=firmas.map(f=>`
        <div style="background:#fff;border:1px solid #D0DCE8;border-radius:12px;padding:14px 16px;margin-bottom:10px">
          <div style="font-weight:700;font-size:14px;color:#003366">📋 Viáticos ${f.periodo}</div>
          <div style="font-size:11px;color:#888;margin:4px 0 8px">${f.fecha||'—'} · ${f.metodo==='biometrica'?'👆 Biométrica':'✍️ Manuscrita'}</div>
          <div style="font-family:monospace;font-size:10px;color:#aaa;background:#f5f7fa;padding:4px 8px;border-radius:6px;margin-bottom:8px">${(f.hash||'').substring(0,32)}...</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">
            <span style="font-size:10px;font-weight:700;padding:3px 8px;border-radius:20px;background:#E8F5E9;color:#2E7D32">✅ Firmada</span>
            <span style="font-size:10px;font-weight:700;padding:3px 8px;border-radius:20px;background:${f.ots?'#E8F5E9':'#FFF8E1'};color:${f.ots?'#2E7D32':'#F57F17'}">${f.ots?'⛓ Bitcoin OTS':'⏳ OTS pendiente'}</span>
          </div>
          <div style="display:flex;gap:8px">
            <button onclick="window.open('/?h=${f.hash}','_blank')" style="flex:1;padding:9px;background:#E8F0F7;color:#003366;border:none;border-radius:9px;font-size:12px;font-weight:700;cursor:pointer">🔍 Verificar</button>
            <button onclick="copiarHash('${f.hash}')" style="flex:1;padding:9px;background:#f0f4f8;color:#555;border:none;border-radius:9px;font-size:12px;font-weight:700;cursor:pointer">📋 Copiar hash</button>
          </div>
        </div>`).join('');
      if(tl&&firmas[0]){
        try{
          const proof=await api('GET','/api/transparency/proof/'+firmas[0].hash);
          tl.innerHTML=proof.incluido
            ?`<div style="font-size:12px;line-height:1.7;color:#555">✅ <strong>En el log público</strong> — índice #${proof.index}<br>📅 ${(proof.timestamp||'').substring(0,19).replace('T',' ')}<br><span style="font-family:monospace;font-size:10px;color:#aaa">Merkle: ${(proof.merkleRoot||'').substring(0,24)}...</span><br><a href="/api/transparency/status" target="_blank" style="font-size:11px;color:#003366">Ver log público →</a></div>`
            :'<div style="font-size:12px;color:#aaa">Sin registro en el log de transparencia aún.</div>';
        }catch(e){}
      }
    }catch(e){el.innerHTML='<div style="color:#e53935;font-size:13px">Error: '+e.message+'</div>';}
  };

  window.copiarHash = function(hash) {
    navigator.clipboard.writeText(hash).then(()=>alert('Hash copiado al portapapeles')).catch(()=>prompt('Hash:',hash));
  };

  window.cargarDatosRGPD = async function() {
    const elP=document.getElementById('iRgpdPerfil');
    const elB=document.getElementById('iRgpdBio');
    if(!elP) return;
    try {
      const r=await api('GET','/api/inspector/mis-firmas');
      const p=r.titular||{};
      elP.innerHTML=`
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f0f0f0;font-size:13px"><span>Nombre</span><strong style="color:#003366">${p.nombre||'—'}</strong></div>
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f0f0f0;font-size:13px"><span>Legajo</span><strong style="color:#003366">${p.legajo||'—'}</strong></div>
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f0f0f0;font-size:13px"><span>Total firmas</span><strong style="color:#003366">${r.total||0}</strong></div>
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f0f0f0;font-size:13px"><span>Base legal</span><strong style="color:#003366">Ley 25.506</strong></div>
        <div style="display:flex;justify-content:space-between;padding:8px 0;font-size:13px"><span>Retención</span><strong style="color:#003366">10 años</strong></div>`;
    }catch(e){if(elP)elP.innerHTML='<div style="font-size:12px;color:#aaa">Error cargando perfil</div>';}
    if(elB){const bio=window.perfilInsp?.tieneBiometrico;elB.innerHTML=bio?'<div style="font-size:13px;color:#2E7D32">✅ Biometría registrada (WebAuthn)</div>':'<div style="font-size:13px;color:#F57F17">⚠️ Sin biometría registrada</div>';}
    initPushUI();
  };

  window.descargarMisDatos = async function() {
    try{const r=await api('GET','/api/inspector/mis-firmas');const b=new Blob([JSON.stringify(r,null,2)],{type:'application/json'});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download='mis-datos-firmared.json';a.click();URL.revokeObjectURL(u);}catch(e){alert('Error: '+e.message);}
  };

  window.solicitarSupresion = function() {
    if(confirm('Solicitar supresion de datos personales segun Ley 25.326?\nEsto enviara un email al responsable.'))
      window.open('mailto:firmared@subsecretaria.gob.ar?subject=Solicitud%20supresion%20datos&body=Solicito%20supresion%20de%20mis%20datos.');
  };

  // Push notifications
  let pushReg=null;
  window.initPushUI = async function() {
    const st=document.getElementById('pushStatus');
    const btn=document.getElementById('pushBtn');
    if(!st||!btn) return;
    if(!('serviceWorker' in navigator)||!('PushManager' in window)){st.textContent='Tu navegador no soporta notificaciones push';return;}
    try{
      const reg=await navigator.serviceWorker.register('/sw.js');
      pushReg=reg;
      const sub=await reg.pushManager.getSubscription();
      if(sub){st.textContent='✅ Notificaciones activas';st.style.color='#2E7D32';btn.textContent='🔕 Desactivar';btn.style.display='block';}
      else{st.textContent='Sin notificaciones activas';btn.textContent='🔔 Activar notificaciones';btn.style.display='block';}
    }catch(e){st.textContent='No disponible';}
  };

  window.togglePush = async function() {
    if(!pushReg) return;
    const sub=await pushReg.pushManager.getSubscription();
    const st=document.getElementById('pushStatus');
    const btn=document.getElementById('pushBtn');
    if(sub){
      await sub.unsubscribe();
      await api('POST','/api/push/unsubscribe',{endpoint:sub.endpoint});
      if(st){st.textContent='Notificaciones desactivadas';st.style.color='#888';}
      if(btn) btn.textContent='🔔 Activar notificaciones';
    } else {
      const perm=await Notification.requestPermission();
      if(perm!=='granted'){if(st)st.textContent='Permiso denegado';return;}
      const vr=await api('GET','/api/push/vapid-key');
      const padding='='.repeat((4-vr.publicKey.length%4)%4);
      const b64=(vr.publicKey+padding).replace(/-/g,'+').replace(/_/g,'/');
      const raw=window.atob(b64);
      const key=Uint8Array.from([...raw].map(c=>c.charCodeAt(0)));
      const newSub=await pushReg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:key});
      await api('POST','/api/push/subscribe',{subscription:newSub.toJSON()});
      if(st){st.textContent='✅ Notificaciones activas';st.style.color='#2E7D32';}
      if(btn) btn.textContent='🔕 Desactivar';
    }
  };
})();
