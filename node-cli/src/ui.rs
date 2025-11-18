pub const UI_HTML: &str = r#"<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Lofswap Node & Wallet</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #0b0f17; color: #e8eefb; }
    header { padding: 16px 20px; background: #0f1522; border-bottom: 1px solid #24304a; }
    h1 { font-size: 20px; margin: 0; }
    .wrap { padding: 18px; display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 18px; }
    section { background: #111827; border: 1px solid #263247; border-radius: 10px; padding: 14px; }
    h2 { font-size: 16px; margin: 0 0 10px; color: #a0b7ff; }
    label { display:block; margin: 8px 0 4px; font-size: 13px; color:#9fb0cd }
    input, button, select, textarea { background:#0b1320; color:#e8eefb; border:1px solid #2a3a58; border-radius:8px; padding:8px 10px; font-size:14px; }
    button { cursor:pointer; }
    button.primary { background:#1b2a4a; border-color:#3a5aa0; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 6px 8px; border-bottom: 1px solid #223150; text-align: left; }
    code { color:#9fe2b4 }
    .row { display:flex; gap:8px; align-items:center; flex-wrap: wrap; }
    .muted { color:#8aa0bf; font-size:12px }
    .kbd { background:#0b1320; border:1px solid #2a3a58; padding: 2px 6px; border-radius:6px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .danger { color:#ff8a8a }
    .ok { color:#9fe2b4 }
    .grid2 { display:grid; grid-template-columns: 1fr 1fr; gap:10px }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:12px }
  </style>
</head>
<body>
  <header><h1>Lofswap: Node + Wallet</h1></header>
  <div class=\"wrap\">
    <section>
      <h2>Node</h2>
      <div class=\"row\">
        <button id=\"refreshNode\">Refresh</button>
        <button id=\"mine\" class=\"primary\">Mine Block</button>
      </div>
      <div class=\"grid2\" style=\"margin-top:8px\">
        <div>
          <div class=\"muted\">Public IP</div>
          <div id=\"pubip\" class=\"mono\">-</div>
        </div>
        <div>
          <div class=\"muted\">Private IP</div>
          <div id=\"privip\" class=\"mono\">-</div>
        </div>
      </div>
      <h3 style=\"margin:14px 0 6px\">Peers</h3>
      <div class=\"row\">
        <input id=\"peerInput\" placeholder=\"ip:port\" />
        <button id=\"addPeer\">Add</button>
        <button id=\"removePeer\">Remove</button>
        <span class=\"muted\" id=\"peerCount\"></span>
      </div>
      <table style=\"margin-top:8px\"> <thead><tr><th>Peer</th><th>Status</th></tr></thead>
        <tbody id=\"peers\"></tbody>
      </table>
      <h3 style=\"margin:14px 0 6px\">Mempool</h3>
      <table> <thead><tr><th>From</th><th>To</th><th>Amount</th></tr></thead>
        <tbody id=\"mempool\"></tbody>
      </table>
      <h3 style=\"margin:14px 0 6px\">Latest Transaction</h3>
      <div id=\"latestTx\" class=\"mono\">-</div>
      <h3 style=\"margin:14px 0 6px\">Chain</h3>
      <div id=\"height\" class=\"muted\"></div>
      <table> <thead><tr><th>#</th><th>Hash</th><th>TXs</th></tr></thead>
        <tbody id=\"chain\"></tbody>
      </table>
    </section>

    <section>
      <h2>Wallet</h2>
      <div class=\"row\" style=\"margin-bottom:8px\">
        <button id=\"createWallet\" class=\"primary\">Create Wallet</button>
        <button id=\"removeWallet\" class=\"danger\">Remove Wallet</button>
        <a id=\"exportDat\" href=\"/wallet/export-dat\" download=\"wallet.dat\"><button>Export .dat</button></a>
      </div>
      <div class=\"row\">
        <input id=\"privhex\" placeholder=\"Private key (hex)\" class=\"mono\" />
        <button id=\"importPriv\">Import Private</button>
      </div>
      <div class=\"row\" style=\"margin-top:8px\">
        <input type=\"file\" id=\"datFile\" />
        <button id=\"importDat\">Import .dat</button>
      </div>
      <div class=\"row\" style=\"margin-top:8px\">
        <button id=\"revealKeys\">Reveal Keys…</button>
        <span class=\"muted\">(confirmation required)</span>
      </div>
      <div id=\"keys\" class=\"mono\"></div>
      <div class=\"grid2\" style=\"margin-top:8px\">
        <div>
          <div class=\"muted\">Address</div>
          <div id=\"address\" class=\"mono\">-</div>
        </div>
        <div>
          <div class=\"muted\">Balance</div>
          <div id=\"balance\" class=\"mono\">-</div>
        </div>
      </div>
      <h3 style=\"margin:14px 0 6px\">Send Transaction</h3>
      <div class=\"row\">
        <input id=\"to\" placeholder=\"To (address)\" class=\"mono\" style=\"width: 60%\" />
        <input id=\"amount\" placeholder=\"Amount\" type=\"number\" />
        <button id=\"send\" class=\"primary\">Send</button>
      </div>
      <div class=\"row\" style=\"margin-top:8px\">
        <button id=\"flush\">Flush Pending</button>
        <span class=\"muted\" id=\"pending\"></span>
      </div>
      <h3 style=\"margin:14px 0 6px\">History</h3>
      <table> <thead><tr><th>Dir</th><th>Peer</th><th>Amount</th></tr></thead>
        <tbody id=\"history\"></tbody>
      </table>
    </section>
  </div>

  <script>
    const ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    function base58(buf){
      let x = [...buf]; let digits = [0];
      for (let i=0;i<x.length;i++){
        let carry = x[i];
        for (let j=0;j<digits.length;j++){
          const v = digits[j]*256 + carry; digits[j] = v % 58; carry = Math.floor(v/58);
        }
        while (carry){ digits.push(carry%58); carry=Math.floor(carry/58); }
      }
      return digits.reverse().map(d=>ALPH[d]).join('') || '1';
    }
    async function sha256(buf){ const d = await crypto.subtle.digest('SHA-256', buf); return new Uint8Array(d); }
    async function getWalletInfo(){ const r = await fetch('/wallet/info'); return r.json(); }
    async function deriveAddress(pubKeyStr){
      const enc = new TextEncoder(); const bytes = enc.encode(pubKeyStr);
      const h = await sha256(bytes); const slice = h.slice(0,20);
      return 'LFS'+base58(slice);
    }
    async function refreshNode(){
      try{
        const ip = await fetch('/node/ip').then(r=>r.json());
        document.getElementById('pubip').textContent = ip.public || '-';
        document.getElementById('privip').textContent = ip.private || '-';
        const peers = await fetch('/peers').then(r=>r.json()).catch(()=>[]);
        const status = await fetch('/peers/status').then(r=>r.json()).catch(()=>({list:[]}));
        document.getElementById('peerCount').textContent = `${peers.length} peers`;
        const tbody = document.getElementById('peers'); tbody.innerHTML = '';
        (status.list||peers.map(p=>({peer:p, online:false}))).forEach(p=>{
          const tr = document.createElement('tr');
          tr.innerHTML = `<td class=\"mono\">${p.peer}</td><td>${p.online?'<span class=ok>online</span>':'<span class=danger>offline</span>'}</td>`;
          tbody.appendChild(tr);
        });
        const mem = await fetch('/mempool').then(r=>r.json()).catch(()=>[]);
        const mbody = document.getElementById('mempool'); mbody.innerHTML='';
        mem.forEach(tx=>{
          const tr=document.createElement('tr');
          tr.innerHTML = `<td class=\"mono\">${tx.from||'(reward)'}</td><td class=\"mono\">${tx.to}</td><td>${tx.amount}</td>`;
          mbody.appendChild(tr);
        });
        const latest = await fetch('/chain/latest-tx').then(r=>r.json()).catch(()=>null);
        document.getElementById('latestTx').textContent = latest? JSON.stringify(latest): '-';
        const h = await fetch('/height').then(r=>r.json()).catch(()=>({height:0}));
        document.getElementById('height').textContent = `Height: ${h.height||0}`;
        const chain = await fetch('/chain').then(r=>r.json()).catch(()=>[]);
        const cbody = document.getElementById('chain'); cbody.innerHTML='';
        chain.slice(-10).reverse().forEach(b=>{
          const tr=document.createElement('tr');
          tr.innerHTML = `<td>${b.index}</td><td class=\"mono\">${b.hash}</td><td>${(b.transactions||[]).length}</td>`;
          cbody.appendChild(tr);
        });
      }catch(e){ console.error(e); }
    }
    async function refreshWallet(){
      const info = await getWalletInfo();
      const addr = info.public_key ? await deriveAddress(info.public_key) : '-';
      document.getElementById('address').textContent = addr;
      if(addr && addr !== '-'){
        const bal = await fetch(`/address/${addr}/balance`).then(r=>r.json().catch(()=>r.text())).catch(()=>'-');
        const v = typeof bal === 'object' ? bal.balance : bal;
        document.getElementById('balance').textContent = v;
        const txs = await fetch(`/address/${addr}/txs`).then(r=>r.json()).catch(()=>[]);
        const h = document.getElementById('history'); h.innerHTML='';
        txs.forEach(tx=>{
          const dir = (tx.to===addr)?'IN':'OUT';
          const tr=document.createElement('tr');
          tr.innerHTML = `<td>${dir}</td><td class=\"mono\">${(dir==='IN'?tx.from:tx.to)||''}</td><td>${tx.amount}</td>`;
          h.appendChild(tr);
        })
      }
      const pendingTxt = await fetch('/wallet/pending-count').then(r=>r.json()).catch(()=>({count:0}));
      document.getElementById('pending').textContent = `${pendingTxt.count} pending`;
    }
    document.getElementById('refreshNode').onclick = ()=>{ refreshNode(); };
    document.getElementById('mine').onclick = async ()=>{ await fetch('/mine', {method:'POST'}); setTimeout(refreshNode, 500); };
    document.getElementById('addPeer').onclick = async ()=>{
      const p = document.getElementById('peerInput').value.trim(); if(!p) return;
      await fetch('/peers/add', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({peer:p})}); refreshNode(); };
    document.getElementById('removePeer').onclick = async ()=>{
      const p = document.getElementById('peerInput').value.trim(); if(!p) return;
      await fetch('/peers/remove', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({peer:p})}); refreshNode(); };
    document.getElementById('createWallet').onclick = async ()=>{ await fetch('/wallet/create', {method:'POST'}); await refreshWallet(); };
    document.getElementById('removeWallet').onclick = async ()=>{ if(confirm('Remove default wallet?')){ await fetch('/wallet', {method:'DELETE'}); await refreshWallet(); }};
    document.getElementById('importPriv').onclick = async ()=>{
      const v = document.getElementById('privhex').value.trim(); if(!v) return;
      await fetch('/wallet/import-priv', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({priv_hex:v})}); await refreshWallet(); };
    document.getElementById('importDat').onclick = async ()=>{
      const f = document.getElementById('datFile').files[0]; if(!f) return; const ab = await f.arrayBuffer();
      const hex = [...new Uint8Array(ab)].map(b=>b.toString(16).padStart(2,'0')).join('');
      await fetch('/wallet/import-dat', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({dat_hex:hex})}); await refreshWallet(); };
    document.getElementById('revealKeys').onclick = async ()=>{
      if(!confirm('Show private key?')) return; const k = await fetch('/wallet/keys?confirm=true').then(r=>r.json());
      document.getElementById('keys').textContent = `Public: ${k.public_key || '-'}\nPrivate: ${k.private_key || '-'}`;
    };
    document.getElementById('send').onclick = async ()=>{
      const to = document.getElementById('to').value.trim(); const amount = parseInt(document.getElementById('amount').value,10)||0;
      if(!to || amount<=0) return; const res = await fetch('/wallet/send', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({to, amount, min_peers:2})}).then(r=>r.json());
      alert(res.message||'Sent'); await refreshWallet(); };
    document.getElementById('flush').onclick = async ()=>{ await fetch('/wallet/flush', {method:'POST'}); await refreshWallet(); };
    (async function(){ await refreshNode(); await refreshWallet(); })();
  </script>
</body>
</html>"#;