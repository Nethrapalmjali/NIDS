// Real-time in-browser analyser.
// Streams held-out CIC-IDS2017 flows (never seen in training) and classifies each one with the
// exported LightGBM model (assets/data/model.json). Explanations use Saabas path attribution:
// every split on a flow's decision path credits its feature with the change in node value.
(async function live() {
  const $ = (id) => document.getElementById(id);
  const status = $("lv-loading");
  let M, D;
  try {
    [M, D] = await Promise.all([
      fetch("assets/data/model.json").then((r) => r.json()),
      fetch("assets/data/flows.json").then((r) => r.json()),
    ]);
  } catch (e) {
    status.textContent = "Could not load the model. Open this page over http(s), e.g. on GitHub Pages, not as a local file.";
    return;
  }
  status.remove();
  $("lv-app").classList.remove("hidden");

  const K = M.numClass, F = M.features.length, BENIGN = M.classes.indexOf("Benign");
  const byClass = M.classes.map(() => []);
  D.y.forEach((k, i) => byClass[k].push(i));

  // ---------- model ----------
  function score(x, explainClass) {
    const raw = new Float64Array(K);
    const contrib = explainClass == null ? null : new Float64Array(F);
    for (let t = 0; t < M.trees.length; t++) {
      const tr = M.trees[t], k = t % K;
      let n = 0;
      while (tr.f[n] >= 0) {
        const next = x[tr.f[n]] <= tr.t[n] ? tr.l[n] : tr.r[n];
        if (contrib && k === explainClass) contrib[tr.f[n]] += tr.v[next] - tr.v[n];
        n = next;
      }
      raw[k] += tr.v[n];
    }
    const mx = Math.max(...raw);
    const e = raw.map((v) => Math.exp(v - mx));
    const s = e.reduce((a, b) => a + b, 0);
    return { proba: e.map((v) => v / s), contrib };
  }

  // ---------- state ----------
  const HISTORY = 60;
  const series = Array.from({ length: HISTORY }, () => [0, 0]);
  let bucket = [0, 0];
  let flows = 0, correct = 0, alerts = 0, benchUs = null;
  let running = true, rate = 12, autoMix = false;
  const queue = [];
  const incidents = new Map();          // label -> incident (grouped within 15 s)
  const perClass = M.classes.map(() => ({ sent: 0, flagged: 0, right: 0 }));

  const pickFlow = (k) => byClass[k][Math.floor(Math.random() * byClass[k].length)];
  const ip = (a) => `${a}.${1 + Math.floor(Math.random() * 253)}`;

  function inject(k, n = 30) {
    const attacker = ip("203.0.113");
    for (let i = 0; i < n; i++) {
      queue.push({ idx: pickFlow(k), src: M.classes[k] === "DDoS" ? ip("198.51.100") : attacker, at: performance.now() + i * (3000 / n) });
    }
  }

  function analyse(item) {
    const x = D.x[item.idx], truth = D.y[item.idx];
    const { proba } = score(x);
    let pred = 0;
    for (let k = 1; k < K; k++) if (proba[k] > proba[pred]) pred = k;
    flows++;
    if (pred === truth) correct++;
    perClass[truth].sent++;
    if (truth !== BENIGN && pred !== BENIGN) perClass[truth].flagged++;
    if (pred === truth) perClass[truth].right++;
    const malicious = pred !== BENIGN && proba[pred] >= 0.6;
    bucket[malicious ? 1 : 0]++;
    if (malicious) raise(item, x, pred, truth, proba[pred]);
  }

  function explain(x, pred) {
    const { contrib } = score(x, pred);
    const top = [...contrib.keys()].sort((a, b) => contrib[b] - contrib[a]).slice(0, 3).filter((i) => contrib[i] > 0);
    return top.map((i) => {
      const v = x[i], med = M.benignMedian[i], name = M.features[i];
      const fmt = (n) => Math.round(n).toLocaleString("en-US");
      if (name === "Destination Port") return `targets port ${v}`;
      if (med > 0 && v > med * 2) return `${name} = ${fmt(v)} (${v / med < 1000 ? "~" + fmt(v / med) + "× " : "far above "}normal median ${fmt(med)})`;
      if (v < med / 2) return `${name} = ${fmt(v)} (normal median ${fmt(med)})`;
      return `${name} = ${fmt(v)}`;
    });
  }

  function raise(item, x, pred, truth, conf) {
    const label = M.classes[pred];
    const now = Date.now();
    const key = label + "|" + (label === "DDoS" ? "*" : item.src);
    const inc = incidents.get(key);
    if (inc && now - inc.last < 15000) {
      inc.flows++; inc.last = now; inc.conf = Math.max(inc.conf, conf); inc.truths[M.classes[truth]] = (inc.truths[M.classes[truth]] || 0) + 1;
      return;
    }
    alerts++;
    incidents.set(key, { label, src: label === "DDoS" ? "many sources" : item.src, port: x[0], conf, flows: 1, first: now, last: now,
      truths: { [M.classes[truth]]: 1 }, why: explain(x, pred) });
  }

  // ---------- rendering ----------
  const canvas = $("lv-chart"), ctx = canvas.getContext("2d");
  function draw() {
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const max = Math.max(20, ...series.map((p) => p[0] + p[1])) * 1.15;
    ctx.strokeStyle = "#233042"; ctx.lineWidth = 1;
    for (let y = 1; y < 4; y++) { ctx.beginPath(); ctx.moveTo(0, (H / 4) * y); ctx.lineTo(W, (H / 4) * y); ctx.stroke(); }
    ctx.fillStyle = "#8a9bb0"; ctx.font = "12px Consolas, monospace";
    ctx.fillText(`${Math.round(max)} flows/s`, 6, 14);
    const bw = W / HISTORY;
    series.forEach(([b, m], i) => {
      const hb = (b / max) * H, hm = (m / max) * H;
      ctx.fillStyle = "rgba(61,220,151,.75)"; ctx.fillRect(i * bw + 1, H - hb, bw - 2, hb);
      ctx.fillStyle = "rgba(255,93,108,.9)"; ctx.fillRect(i * bw + 1, H - hb - hm, bw - 2, hm);
    });
  }

  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  function renderIncidents() {
    const list = [...incidents.values()].sort((a, b) => b.last - a.last).slice(0, 25);
    if (!list.length) return;
    $("lv-log").innerHTML = list.map((i) => {
      const th = M.threats[i.label] || { technique: "-", severity: "medium", action: "Investigate." };
      const truthTxt = Object.entries(i.truths).map(([k, v]) => `${k}${v > 1 ? " ×" + v : ""}`).join(", ");
      const ok = Object.keys(i.truths).length === 1 && i.truths[i.label];
      return `<div class="alert ${th.severity === "high" ? "" : "md"}">
        <div><b class="${th.severity === "high" ? "sev-hi" : "sev-md"}">${esc(i.label)}</b> · ${(i.conf * 100).toFixed(1)}% · ${th.technique}
          <span class="t">· ${new Date(i.last).toLocaleTimeString()} · ${i.flows} flow${i.flows > 1 ? "s" : ""}</span></div>
        <div class="why">${esc(i.src)} → 10.0.0.10:${i.port}</div>
        <div class="why"><b>Why:</b> ${esc(i.why.join("; ") || "overall flow profile")}.</div>
        <div class="why"><b>Action:</b> ${esc(th.action)}</div>
        <div class="why ${ok ? "truth-ok" : "truth-bad"}">Ground truth: ${esc(truthTxt)} ${ok ? "✓" : "✗"}</div>
      </div>`;
    }).join("");
  }

  function renderTable() {
    $("lv-table").innerHTML = "<tr><th>Class</th><th class='num'>Flows</th><th class='num'>Correct</th><th class='num'>Detected as attack</th></tr>" +
      M.classes.map((c, k) => {
        const p = perClass[k];
        if (!p.sent) return "";
        const det = k === BENIGN ? "—" : ((p.flagged / p.sent) * 100).toFixed(0) + "%";
        return `<tr><td>${c}</td><td class="num">${p.sent}</td><td class="num">${((p.right / p.sent) * 100).toFixed(0)}%</td><td class="num">${det}</td></tr>`;
      }).join("");
  }

  function tick() {
    if (!running) return;
    series.push(bucket); series.shift(); bucket = [0, 0];
    const last = series[HISTORY - 1];
    $("lv-flows").textContent = flows.toLocaleString("en-US");
    $("lv-rate").textContent = last[0] + last[1];
    $("lv-alerts").textContent = alerts;
    $("lv-acc").textContent = flows ? ((correct / flows) * 100).toFixed(2) + "%" : "–";
    $("lv-lat").textContent = benchUs == null ? "–" : benchUs.toFixed(0) + " µs";
    const st = $("lv-status");
    st.textContent = last[1] ? "UNDER ATTACK" : "NORMAL";
    st.className = last[1] ? "bad" : "ok";
    draw(); renderIncidents(); renderTable();
    if (autoMix && Math.random() < 0.12) {
      const attacks = M.classes.map((_, k) => k).filter((k) => k !== BENIGN);
      inject(attacks[Math.floor(Math.random() * attacks.length)], 20);
    }
  }

  function pump() {
    if (running) {
      const now = performance.now();
      while (queue.length && queue[0].at <= now) analyse(queue.shift());
      if (Math.random() < rate / 20) analyse({ idx: pickFlow(BENIGN), src: ip("10.0.1") });
    }
  }

  // ---------- controls ----------
  $("lv-buttons").innerHTML = M.classes.map((c, k) => k === BENIGN ? "" :
    `<button class="btn attack" data-k="${k}">${c}</button>`).join("");
  $("lv-buttons").addEventListener("click", (e) => {
    const b = e.target.closest("[data-k]");
    if (b) { inject(+b.dataset.k); queue.sort((a, b2) => a.at - b2.at); }
  });
  $("lv-toggle").addEventListener("click", (e) => { running = !running; e.target.textContent = running ? "Pause" : "Resume"; });
  $("lv-mix").addEventListener("change", (e) => { autoMix = e.target.checked; });
  $("lv-rate-in").addEventListener("input", (e) => { rate = +e.target.value; $("lv-rate-val").textContent = rate; });

  const m = M.metrics;
  $("lv-model").textContent = `${M.trees.length.toLocaleString("en-US")} trees · ${F} features · ${K} classes · test accuracy ${(m.accuracy * 100).toFixed(2)}% · macro F1 ${(m.f1 * 100).toFixed(1)}% on ${m.testRows.toLocaleString("en-US")} held-out flows`;
  // ?autodemo starts a random attack mix immediately (handy for presentations)
  if (new URLSearchParams(location.search).has("autodemo")) {
    autoMix = true; $("lv-mix").checked = true;
    ["DDoS", "SSH Brute Force", "Port Scan"].forEach((c) => inject(M.classes.indexOf(c), 25));
    queue.sort((a, b) => a.at - b.at);
  }

  // Benchmark: time 300 flows in one batch (browsers coarsen timers, so per-flow timing is unreliable).
  setTimeout(() => {
    const t0 = performance.now();
    for (let i = 0; i < 300; i++) score(D.x[i % D.x.length]);
    const el = performance.now() - t0;
    if (el > 0) benchUs = (el / 300) * 1000;
  }, 300);

  draw();
  setInterval(pump, 50);
  setInterval(tick, 1000);
})();
