pub const UI_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Lofswap Explorer</title>
  <style>
    :root {
      --bg: #05060b;
      --panel: #0b0f19;
      --border: #1a2336;
      --text: #d8e2ff;
      --muted: #7d8bad;
      --accent: #6b8bff;
      --accent2: #24e3b5;
      --danger: #ff8a8a;
      --glow: 0 0 30px rgba(107,139,255,0.25);
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: radial-gradient(circle at 20% 20%, rgba(107,139,255,0.12), transparent 28%), radial-gradient(circle at 80% 0%, rgba(36,227,181,0.12), transparent 28%), var(--bg); color: var(--text); font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif; min-height: 100vh; }
    .topbar { display:flex; justify-content: space-between; align-items:center; padding: 18px 24px; border-bottom:1px solid var(--border); background: linear-gradient(90deg, rgba(9,12,20,0.9), rgba(9,12,20,0.6)); position: sticky; top:0; z-index: 10; }
    .brand { display:flex; align-items:center; gap:10px; font-weight:700; letter-spacing:0.2px; }
    .pill { padding:6px 10px; border-radius:999px; border:1px solid var(--border); color: var(--muted); font-size:12px; }
    .container { max-width: 1220px; margin: 0 auto; padding: 20px; display: grid; gap: 16px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
    .card { background: var(--panel); border:1px solid var(--border); border-radius: 12px; padding: 14px; box-shadow: var(--glow); }
    .stat-label { color: var(--muted); font-size:12px; text-transform: uppercase; letter-spacing:0.5px; }
    .stat-value { font-size:20px; font-weight:700; margin-top:6px; }
    .stat-sub { color: var(--muted); font-size:12px; margin-top:4px; }
    .grid { display:grid; grid-template-columns: 1fr; gap: 16px; }
    .section { background: var(--panel); border:1px solid var(--border); border-radius:12px; padding:14px 16px; box-shadow: 0 0 18px rgba(0,0,0,0.4); }
    h2 { margin:0 0 10px; font-size:15px; letter-spacing:0.1px; color: var(--text); }
    .row { display:flex; gap:8px; align-items:center; flex-wrap: wrap; }
    button { background:#0a0f1a; color:var(--text); border:1px solid var(--border); border-radius:10px; padding:8px 10px; font-size:13px; cursor:pointer; transition: all 0.15s ease; }
    button.primary { background: linear-gradient(120deg, var(--accent), var(--accent2)); border:none; color:#010308; font-weight:700; box-shadow: 0 0 18px rgba(107,139,255,0.35); }
    button:hover { transform: translateY(-1px); }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; }
    th { color: var(--muted); font-weight:600; font-size:12px; }
    .muted { color: var(--muted); font-size:12px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:12px; }
    .ok { color: var(--accent2); }
    .danger { color: var(--danger); }
    .flex-between { display:flex; justify-content: space-between; align-items:center; gap:10px; }
    .cols-2 { display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:12px; }
    @media (max-width: 980px){ .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="brand">
      <div style="width:12px; height:12px; border-radius:50%; background:linear-gradient(120deg,var(--accent),var(--accent2)); box-shadow:0 0 12px rgba(107,139,255,0.7);"></div>
      <div>Lofswap Explorer</div>
    </div>
    <div class="pill" id="networkTag">Online</div>
  </div>
  <div class="container">
    <div class="stats">
      <div class="card">
        <div class="stat-label">Height</div>
        <div class="stat-value" id="summaryHeight">-</div>
        <div class="stat-sub" id="latestHash">-</div>
      </div>
      <div class="card">
        <div class="stat-label">Peers Online</div>
        <div class="stat-value" id="summaryPeers">-</div>
        <div class="stat-sub" id="peerCount">-</div>
      </div>
      <div class="card">
        <div class="stat-label">Mempool</div>
        <div class="stat-value" id="summaryMempool">-</div>
        <div class="stat-sub">Pending transactions</div>
      </div>
      <div class="card">
        <div class="stat-label">Latest TX</div>
        <div class="stat-value" id="summaryLatestTx">-</div>
        <div class="stat-sub" id="summaryLatestDetail"></div>
      </div>
    </div>

    <div class="grid">
      <div class="section">
        <div class="flex-between">
          <h2>Network</h2>
          <div class="row">
            <button id="refreshNode" class="primary">Refresh</button>
          </div>
        </div>
        <div class="cols-2" style="margin: 8px 0 14px">
          <div class="card" style="box-shadow:none; border:1px solid var(--border); background:#090c14;">
            <div class="stat-label">Public IP</div>
            <div id="pubip" class="mono">-</div>
          </div>
          <div class="card" style="box-shadow:none; border:1px solid var(--border); background:#090c14;">
            <div class="stat-label">Private IP</div>
            <div id="privip" class="mono">-</div>
          </div>
        </div>

        <div class="cols-2">
          <div class="card" style="background:#0c101b;">
            <div class="flex-between" style="margin-bottom:8px"><h2 style="margin:0">Peers</h2></div>
            <table> <thead><tr><th>Peer</th><th>Status</th></tr></thead>
              <tbody id="peers"></tbody>
            </table>
          </div>
          <div class="card" style="background:#0c101b;">
            <div class="flex-between" style="margin-bottom:8px"><h2 style="margin:0">Online</h2></div>
            <table> <thead><tr><th>Peer</th></tr></thead>
              <tbody id="peersOnline"></tbody>
            </table>
          </div>
        </div>

        <div class="card" style="margin-top:12px; background:#0c101b;">
          <div class="flex-between" style="margin-bottom:8px"><h2 style="margin:0">Latest Blocks</h2></div>
          <div id="height" class="muted" style="margin-bottom:6px"></div>
          <table> <thead><tr><th>#</th><th>Hash</th><th>TXs</th></tr></thead>
            <tbody id="chain"></tbody>
          </table>
        </div>

        <div class="card" style="margin-top:12px; background:#0c101b;">
          <div class="flex-between" style="margin-bottom:8px"><h2 style="margin:0">Recent Transactions</h2></div>
          <table> <thead><tr><th>From</th><th>To</th><th>Amount</th><th>Block</th></tr></thead>
            <tbody id="recentTx"></tbody>
          </table>
        </div>

        <div class="card" style="margin-top:12px; background:#0c101b;">
          <div class="flex-between" style="margin-bottom:8px"><h2 style="margin:0">Mempool</h2></div>
          <table> <thead><tr><th>From</th><th>To</th><th>Amount</th></tr></thead>
            <tbody id="mempool"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <script>
    const shorten = (s, n=10) => s ? (s.length>n ? `${s.slice(0,n)}…${s.slice(-4)}` : s) : '-';

    async function refreshNode(){
      try{
        const ip = await fetch('/node/ip').then(r=>r.json());
        document.getElementById('pubip').textContent = ip.public || '-';
        document.getElementById('privip').textContent = ip.private || '-';

        const peers = await fetch('/peers').then(r=>r.json()).catch(()=>[]);
        const status = await fetch('/peers/status').then(r=>r.json()).catch(()=>({list:[]}));
        const online = (status.list||[]).filter(p=>p.online);
        document.getElementById('peerCount').textContent = `${peers.length} peers`;
        document.getElementById('summaryPeers').textContent = `${online.length}/${peers.length||0}`;

        const tbody = document.getElementById('peers'); tbody.innerHTML = '';
        (status.list||peers.map(p=>({peer:p, online:false}))).forEach(p=>{
          const tr = document.createElement('tr');
          tr.innerHTML = `<td class="mono">${p.peer}</td><td>${p.online?'<span class=ok>online</span>':'<span class=danger>offline</span>'}</td>`;
          tbody.appendChild(tr);
        });
        const onlineBody = document.getElementById('peersOnline'); onlineBody.innerHTML='';
        online.forEach(p=>{
          const tr=document.createElement('tr');
          tr.innerHTML = `<td class="mono">${p.peer}</td>`;
          onlineBody.appendChild(tr);
        });

        const mem = await fetch('/mempool').then(r=>r.json()).catch(()=>[]);
        document.getElementById('summaryMempool').textContent = mem.length;
        const mbody = document.getElementById('mempool'); mbody.innerHTML='';
        mem.forEach(tx=>{
          const tr=document.createElement('tr');
          tr.innerHTML = `<td class="mono">${tx.from||'(reward)'}</td><td class="mono">${tx.to}</td><td>${tx.amount}</td>`;
          mbody.appendChild(tr);
        });

        const latest = await fetch('/chain/latest-tx').then(r=>r.json()).catch(()=>null);
        document.getElementById('summaryLatestTx').textContent = latest ? `${latest.amount || ''}` : '-';
        document.getElementById('summaryLatestDetail').textContent = latest ? `${shorten(latest.from||'(reward)',12)} → ${shorten(latest.to||'',12)}` : '';

        const h = await fetch('/height').then(r=>r.json()).catch(()=>({height:0}));
        const chain = await fetch('/chain').then(r=>r.json()).catch(()=>[]);
        const heightVal = h.height || chain.length || 0;
        document.getElementById('summaryHeight').textContent = heightVal;
        const latestBlock = chain[chain.length-1];
        document.getElementById('latestHash').textContent = latestBlock ? shorten(latestBlock.hash, 22) : '-';
        document.getElementById('height').textContent = `Height: ${heightVal}`;

        const cbody = document.getElementById('chain'); cbody.innerHTML='';
        chain.slice(-10).reverse().forEach(b=>{
          const tr=document.createElement('tr');
          tr.innerHTML = `<td>${b.index}</td><td class="mono">${shorten(b.hash, 28)}</td><td>${(b.transactions||[]).length}</td>`;
          cbody.appendChild(tr);
        });

        const txBody = document.getElementById('recentTx'); txBody.innerHTML='';
        const recentTxs = [];
        chain.slice(-10).forEach(b=>{
          (b.transactions||[]).forEach(tx=>{
            recentTxs.push({...tx, block: b.index});
          });
        });
        recentTxs.slice(-15).reverse().forEach(tx=>{
          const tr=document.createElement('tr');
          tr.innerHTML = `<td class="mono">${shorten(tx.from||'(reward)',14)}</td><td class="mono">${shorten(tx.to,14)}</td><td>${tx.amount}</td><td>#${tx.block}</td>`;
          txBody.appendChild(tr);
        });
      }catch(e){ console.error(e); }
    }

    document.getElementById('refreshNode').onclick = ()=>{ refreshNode(); };
    (async function(){ await refreshNode(); })();
  </script>
</body>
</html>"#;
