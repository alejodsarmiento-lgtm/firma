
// FirmaRED — WatchDog Widget (panel admin)
(function() {
  'use strict';
  window.wdES = null;

  window.wdConnect = function() {
    if(window.wdES) window.wdES.close();
    window.wdES = new EventSource('/api/watchdog/stream');
    window.wdES.onmessage = e => { try{ wdRender(JSON.parse(e.data)); }catch(err){} };
    window.wdES.onerror = () => {
      const d=document.getElementById('wdStatusDot'); if(d) d.style.background='#e53935';
      const t=document.getElementById('wdStatusText'); if(t) t.textContent='Reconectando...';
      setTimeout(window.wdConnect, 5000);
    };
  };

  window.wdRender = function(data) {
    if(!data||data.type!=='wd') return;
    const svcs=Object.values(data.services||{});
    const allOk=svcs.every(s=>s.ok);
    const hasCrit=svcs.some(s=>!s.ok&&s.tipo==='interno');
    const dot=document.getElementById('wdStatusDot');
    const txt=document.getElementById('wdStatusText');
    const grid=document.getElementById('wdGrid');
    if(!dot||!txt||!grid) return;
    dot.style.background=allOk?'#00c87a':hasCrit?'#e53935':'#f5c842';
    txt.textContent=allOk?'✓ Todos los sistemas OK':hasCrit?'⚠️ Servicio crítico con problemas':'⚠️ Servicio externo degradado';
    txt.style.color=allOk?'#2E7D32':hasCrit?'#e53935':'#F57F17';
    const int=svcs.filter(s=>s.tipo==='interno');
    const ext=svcs.filter(s=>s.tipo==='externo');
    const card=arr=>arr.map(sv=>`
      <div style="background:${sv.ok?'#F0FFF4':'#FFF5F5'};border:1px solid ${sv.ok?'#C6F6D5':'#FED7D7'};border-radius:8px;padding:8px 10px">
        <div style="display:flex;align-items:center;gap:5px;margin-bottom:3px">
          <div style="width:6px;height:6px;border-radius:50%;background:${sv.ok?'#00c87a':'#e53935'}"></div>
          <span style="font-size:11px;font-weight:700;color:${sv.ok?'#1B5E20':'#C62828'}">${sv.nombre}</span>
        </div>
        <div style="font-size:10px;color:#888;padding-left:11px">${sv.detail||'—'}</div>
        ${sv.latency?`<div style="font-size:9px;color:#aaa;padding-left:11px">${sv.latency}ms</div>`:''}
      </div>`).join('');
    grid.innerHTML=
      '<div style="grid-column:1/-1;font-size:9px;color:#aaa;font-family:monospace;text-transform:uppercase;padding:4px 0">● Internos</div>'+card(int)+
      '<div style="grid-column:1/-1;font-size:9px;color:#aaa;font-family:monospace;text-transform:uppercase;padding:4px 0;margin-top:4px">● Externos</div>'+card(ext);
    const al=document.getElementById('wdAlerts');
    if(al){
      const alerts=data.alerts||[];
      al.innerHTML=alerts.length
        ?alerts.slice(0,5).map(a=>`<div style="font-size:11px;padding:3px 0;border-bottom:1px solid #f5f5f5;display:flex;gap:8px"><span style="font-weight:700;color:${a.nivel==='CRITICAL'?'#e53935':a.nivel==='RECOVERY'?'#2E7D32':'#F57F17'};flex-shrink:0">${a.nivel}</span><span style="color:#555;flex:1">${a.msg}</span><span style="font-size:9px;color:#aaa;white-space:nowrap">${(a.ts||'').substring(11,19)}</span></div>`).join('')
        :'<div style="font-size:11px;color:#aaa;padding:4px 0">Sin alertas activas</div>';
    }
    const ls=document.getElementById('wdLastScan');
    if(ls&&data.lastScan) ls.textContent=`Scan: ${data.lastScan.substring(0,19).replace('T',' ')} · ${data.scanMs||0}ms · ${svcs.length} servicios`;
  };

  window.wdForceScan = async function() {
    const btn=document.getElementById('wdScanBtn');
    if(btn){btn.textContent='⏳';btn.disabled=true;}
    try{ await api('POST','/api/watchdog/scan'); }catch(e){}
    setTimeout(()=>{if(btn){btn.textContent='⚡ Scan';btn.disabled=false;}},2000);
  };
})();
