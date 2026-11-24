// ---------- Evaluation table ----------
(function renderMetrics() {
  const table = document.getElementById("metrics");
  const pct = (v) => (v == null ? '<span class="pending">pending</span>' : (v * 100).toFixed(2) + "%");
  const ms = (v) => (v == null ? '<span class="pending">pending</span>' : v + " ms");
  (window.NIDS_RESULTS || []).forEach((r) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${r.model}</td><td class="num">${pct(r.accuracy)}</td><td class="num">${pct(r.precision)}</td>` +
      `<td class="num">${pct(r.recall)}</td><td class="num">${pct(r.f1)}</td><td class="num">${pct(r.fpr)}</td>` +
      `<td class="num">${ms(r.inferenceMs)}</td>`;
    table.appendChild(tr);
  });
})();

// ---------- Live detection simulation ----------
(function demo() {
  const canvas = document.getElementById("chart");
  const ctx = canvas.getContext("2d");
  const logEl = document.getElementById("log");
  const $ = (id) => document.getElementById(id);

  const HISTORY = 60;
  const benignHist = Array(HISTORY).fill(0);
  const malHist = Array(HISTORY).fill(0);
  let running = true, flows = 0, alerts = 0, tick = 0;
  let active = null; // { type, ticksLeft, src }
  let firstLog = true;

  const rand = (a, b) => Math.floor(a + Math.random() * (b - a));
  const ip = (net) => `${net}.${rand(1, 254)}`;

  const ATTACKS = {
    ddos:   { duration: 10, label: "DDoS Attack",       sev: "hi", technique: "T1498" },
    scan:   { duration: 8,  label: "Port Scan",         sev: "md", technique: "T1046" },
    brute:  { duration: 9,  label: "SSH Brute Force",   sev: "hi", technique: "T1110.001" },
    exfil:  { duration: 10, label: "Data Exfiltration", sev: "hi", technique: "T1041" },
    botnet: { duration: 12, label: "Botnet Beaconing",  sev: "hi", technique: "T1071" }
  };

  // Generate synthetic flows for one tick (one second).
  function generate() {
    const out = [];
    const n = rand(18, 30);
    for (let i = 0; i < n; i++) {
      const fwd = rand(400, 6000);
      out.push({ src: ip("192.168.1"), dport: [80, 443, 53, 443, 8080][rand(0, 5)],
                 pkts: rand(4, 30), fwd, bwd: Math.round(fwd * (0.6 + Math.random() * 1.8)), mal: false });
    }
    if (active) {
      const s = active.src;
      switch (active.type) {
        case "ddos":
          for (let i = 0; i < 60; i++) out.push({ src: ip("45.33." + rand(1, 250)), dport: 80, pkts: rand(40, 90), fwd: rand(4000, 9000), bwd: 0, mal: true });
          break;
        case "scan":
          for (let i = 0; i < 40; i++) out.push({ src: s, dport: rand(1, 65535), pkts: 1, fwd: 60, bwd: 0, mal: true });
          break;
        case "brute":
          for (let i = 0; i < 25; i++) out.push({ src: s, dport: 22, pkts: rand(10, 18), fwd: rand(900, 1500), bwd: rand(700, 1100), mal: true });
          break;
        case "exfil":
          for (let i = 0; i < 6; i++) out.push({ src: "192.168.1.37", dst: s, dport: 443, pkts: rand(200, 400), fwd: rand(250000, 600000), bwd: rand(200, 900), mal: true });
          break;
        case "botnet":
          if (tick % 2 === 0) out.push({ src: "192.168.1.52", dst: s, dport: 8443, pkts: 3, fwd: 210, bwd: 0, mal: true, beacon: true });
          break;
      }
    }
    return out;
  }

  // Behavioural checks — same feature logic as the real flow analyser.
  function analyse(batch) {
    const bySrc = {};
    batch.forEach((f) => {
      const k = f.src;
      bySrc[k] = bySrc[k] || { ports: new Set(), ssh: 0, pkts: 0, fwd: 0, bwd: 0, beacon: 0 };
      const s = bySrc[k];
      s.ports.add(f.dport); s.pkts += f.pkts; s.fwd += f.fwd; s.bwd += f.bwd;
      if (f.dport === 22) s.ssh++;
      if (f.beacon) s.beacon++;
    });
    const srcs = Object.keys(bySrc);
    const totalPkts = batch.reduce((a, f) => a + f.pkts, 0);
    const oneWaySrcs = batch.filter((f) => f.bwd === 0 && f.dport === 80).length;

    if (totalPkts > 2500 && oneWaySrcs > 30)
      return { type: "ddos", evidence: `${oneWaySrcs} sources sending ${totalPkts.toLocaleString()} pkts/s to port 80 with zero return traffic` };
    for (const k of srcs) {
      const s = bySrc[k];
      if (s.ports.size > 25) return { type: "scan", src: k, evidence: `${k} touched ${s.ports.size} distinct ports in 1 s using single-packet, one-way SYN flows` };
      if (s.ssh > 15) return { type: "brute", src: k, evidence: `${k} opened ${s.ssh} short SSH sessions to port 22 in 1 s` };
      if (s.fwd > 1000000 && s.fwd / Math.max(s.bwd, 1) > 200) return { type: "exfil", src: k, evidence: `${k} sent ${(s.fwd / 1e6).toFixed(1)} MB outbound with a ${Math.round(s.fwd / Math.max(s.bwd, 1))}:1 out/in byte ratio` };
      if (s.beacon) return { type: "botnet", src: k, evidence: `${k} sends small fixed-size (210 B) outbound packets to port 8443 at a regular 2 s interval with no reply` };
    }
    return null;
  }

  const ADVICE = {
    ddos: "Enable upstream rate-limiting / scrubbing and block the top offending subnets at the firewall.",
    scan: "Block the source IP, review which ports responded, and close any services that should not be exposed.",
    brute: "Block the source, enforce key-based SSH login, and check auth logs for any successful login.",
    exfil: "Isolate the internal host immediately, preserve evidence, and identify what data left the network.",
    botnet: "Quarantine the host, scan it for malware, and block the C2 address across the network."
  };

  function raise(det) {
    const a = ATTACKS[det.type];
    alerts++;
    if (firstLog) { logEl.innerHTML = ""; firstLog = false; }
    const conf = (0.91 + Math.random() * 0.08).toFixed(2);
    const div = document.createElement("div");
    div.className = "alert " + a.sev;
    div.innerHTML =
      `<div><span class="t">${new Date().toLocaleTimeString()}</span> <b style="color:${a.sev === "hi" ? "var(--bad)" : "var(--warn)"}">${a.label}</b> · conf ${conf} · ${a.technique}</div>` +
      `<div class="why"><b>Why:</b> ${det.evidence}.</div>` +
      `<div class="why"><b>Recommended:</b> ${ADVICE[det.type]}</div>`;
    logEl.prepend(div);
  }

  function draw() {
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const max = Math.max(1000, ...benignHist.map((b, i) => b + malHist[i])) * 1.1;
    ctx.strokeStyle = "#233042"; ctx.lineWidth = 1;
    for (let y = 0; y <= 4; y++) { ctx.beginPath(); ctx.moveTo(0, (H / 4) * y); ctx.lineTo(W, (H / 4) * y); ctx.stroke(); }
    const plot = (data, color, base) => {
      ctx.beginPath();
      data.forEach((v, i) => {
        const x = (i / (HISTORY - 1)) * W;
        const y = H - ((v + (base ? base[i] : 0)) / max) * H;
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      });
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();
      ctx.lineTo(W, H); ctx.lineTo(0, H); ctx.closePath();
      ctx.fillStyle = color + "22"; ctx.fill();
    };
    plot(malHist, "#ff5d6c", benignHist);
    plot(benignHist, "#3ddc97");
  }

  let lastAlertType = null;
  function step() {
    if (!running) return;
    tick++;
    const batch = generate();
    flows += batch.length;
    benignHist.push(batch.filter((f) => !f.mal).reduce((a, f) => a + f.pkts, 0)); benignHist.shift();
    malHist.push(batch.filter((f) => f.mal).reduce((a, f) => a + f.pkts, 0)); malHist.shift();

    const det = analyse(batch);
    if (det && det.type !== lastAlertType) raise(det);
    lastAlertType = det ? det.type : null;

    if (active && --active.ticksLeft <= 0) active = null;

    $("s-flows").textContent = flows.toLocaleString();
    $("s-rate").textContent = (benignHist[HISTORY - 1] + malHist[HISTORY - 1]).toLocaleString();
    $("s-alerts").textContent = alerts;
    const st = $("s-status");
    st.textContent = det ? "ATTACK" : "SAFE";
    st.style.color = det ? "var(--bad)" : "var(--accent)";
    draw();
  }

  document.querySelectorAll("[data-attack]").forEach((b) =>
    b.addEventListener("click", () => {
      const type = b.dataset.attack;
      active = { type, ticksLeft: ATTACKS[type].duration, src: ip("103.21." + rand(1, 250)) };
      lastAlertType = null;
      if (!running) { running = true; $("toggle").textContent = "Pause"; }
    })
  );
  $("toggle").addEventListener("click", () => {
    running = !running;
    $("toggle").textContent = running ? "Pause" : "Resume";
  });

  draw();
  setInterval(step, 1000);
})();
