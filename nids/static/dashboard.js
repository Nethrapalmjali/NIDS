(() => {
  const csrf = document.querySelector('meta[name="csrf"]').content;
  const canAct = document.currentScript.dataset.canAct === "1";
  const $ = (id) => document.getElementById(id);
  const post = (url, body) => fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify(body || {}),
  });
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  Chart.defaults.color = "#8a9bb0";
  Chart.defaults.borderColor = "#233042";
  const traffic = new Chart($("traffic"), {
    type: "line",
    data: { labels: [], datasets: [
      { label: "Benign flows/s", data: [], borderColor: "#3ddc97", backgroundColor: "rgba(61,220,151,.12)", fill: true, tension: .3, pointRadius: 0 },
      { label: "Malicious flows/s", data: [], borderColor: "#ff5d6c", backgroundColor: "rgba(255,93,108,.15)", fill: true, tension: .3, pointRadius: 0 },
      { label: "Host kB/s", data: [], borderColor: "#4aa8ff", borderDash: [4, 4], tension: .3, pointRadius: 0, yAxisID: "y2" },
    ] },
    options: { animation: false, maintainAspectRatio: false, interaction: { mode: "index", intersect: false },
      scales: { y: { beginAtZero: true, title: { display: true, text: "flows/s" } },
                y2: { position: "right", beginAtZero: true, grid: { display: false }, title: { display: true, text: "kB/s" } } } },
  });
  const classes = new Chart($("classes"), {
    type: "bar",
    data: { labels: [], datasets: [{ data: [], backgroundColor: "#ff5d6c" }] },
    options: { animation: false, maintainAspectRatio: false, indexAxis: "y", plugins: { legend: { display: false } } },
  });

  async function refreshStats() {
    const s = await (await fetch("/api/stats")).json();
    $("source").textContent = s.sourceNote ? "· " + s.sourceNote : "";
    const h = $("health");
    const healthy = s.heartbeatAge < 5;
    h.textContent = `engine ${healthy ? "healthy" : "stalled"} · queue ${s.queue} · dropped ${s.dropped}`;
    h.className = "pill-health " + (healthy && !s.dropped ? "ok" : "warn");
    $("k-flows").textContent = s.flows.toLocaleString();
    const last = s.series[s.series.length - 1] || [0, 0, 0, 0];
    $("k-rate").textContent = last[1] + last[2];
    $("k-net").textContent = last[3].toLocaleString();
    $("k-acc").textContent = s.replayAccuracy == null ? "n/a" : (s.replayAccuracy * 100).toFixed(2) + "%";
    traffic.data.labels = s.series.map((p) => new Date(p[0] * 1000).toLocaleTimeString());
    traffic.data.datasets[0].data = s.series.map((p) => p[1]);
    traffic.data.datasets[1].data = s.series.map((p) => p[2]);
    traffic.data.datasets[2].data = s.series.map((p) => p[3]);
    traffic.update();
    const attacks = Object.entries(s.classCounts).filter(([k]) => k !== "Benign");
    classes.data.labels = attacks.map((a) => a[0]);
    classes.data.datasets[0].data = attacks.map((a) => a[1]);
    classes.update();
  }

  function filters() {
    const p = new URLSearchParams();
    for (const [id, key] of [["f-status", "status"], ["f-severity", "severity"], ["f-label", "label"]]) {
      if ($(id).value) p.set(key, $(id).value);
    }
    return p;
  }

  async function refreshIncidents() {
    const p = filters();
    if ($("export")) $("export").href = "/api/incidents.csv?" + p.toString() + "&limit=10000";
    p.set("limit", "200");
    const [rows, open] = await Promise.all([
      fetch("/api/incidents?" + p).then((r) => r.json()),
      fetch("/api/incidents?status=open&limit=10000").then((r) => r.json()),
    ]);
    $("k-open").textContent = open.length;
    $("inc").innerHTML = rows.map((r) => `
      <tr>
        <td class="mono">${new Date(r.last_ts * 1000).toLocaleTimeString()}</td>
        <td><b>${esc(r.label)}</b> <span class="note">${esc(r.technique)}</span>
            <div class="explain">${esc(r.explanation)}</div>
            ${r.truth ? `<div class="note">Ground truth: ${esc(r.truth)}</div>` : ""}</td>
        <td><span class="sev ${esc(r.severity)}">${esc(r.severity)}</span></td>
        <td class="mono">${esc(r.src)} → ${esc(r.dst)}:${esc(r.dport)}</td>
        <td class="mono">${r.flows}</td>
        <td class="mono">${(r.confidence * 100).toFixed(1)}%</td>
        <td>${r.status === "open" && canAct ? `<button data-ack="${r.id}">Acknowledge</button>` : esc(r.status) + (r.ack_by ? " by " + esc(r.ack_by) : "")}</td>
      </tr>`).join("");
  }

  document.addEventListener("click", async (e) => {
    const sim = e.target.closest("[data-label]");
    if (sim) { await post("/api/simulate", { label: sim.dataset.label }); }
    const ack = e.target.closest("[data-ack]");
    if (ack) {
      const note = prompt("Analyst note (optional):") || "";
      const r = await post(`/api/incidents/${ack.dataset.ack}/ack`, { note });
      if (!r.ok) alert((await r.json()).error || "Could not acknowledge");
      refreshIncidents();
    }
  });

  ["f-status", "f-severity", "f-label"].forEach((id) => $(id).addEventListener("change", refreshIncidents));
  refreshStats(); refreshIncidents();
  setInterval(refreshStats, 1000);
  setInterval(refreshIncidents, 2000);
})();
