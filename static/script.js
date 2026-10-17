const $ = (id) => document.getElementById(id);
let cachedEvents = [];

function toast(message, isError = false) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("error", isError);
  el.classList.add("show");
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => el.classList.remove("show"), 3500);
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const data = await response.json();
  if (!response.ok || data.ok === false) throw new Error(data.error || "Request failed.");
  return data;
}
function setStatus(running, port) {
  $("statusDot").className = "dot " + (running ? "online" : "offline");
  $("statusText").textContent = running ? "Sensor online" : "Sensor offline";
  $("sensorStat").textContent = running ? "Online" : "Offline";
  $("sensorStat").style.color = running ? "var(--green)" : "var(--muted)";
  $("startBtn").disabled = running;
  $("stopBtn").disabled = !running;
  $("listenerAddress").textContent = `127.0.0.1:${port}`;
  $("portInput").value = port;
}
function renderIps(items) {
  const root = $("ipList");
  if (!items || !items.length) {
    root.innerHTML = '<div class="empty-state">No connections recorded yet.</div>';
    return;
  }
  const max = Math.max(...items.map(x => x.count), 1);
  root.replaceChildren();
  items.forEach(item => {
    const row = document.createElement("div"); row.className = "ip-row";
    const ip = document.createElement("div"); ip.className = "ip-address"; ip.textContent = item.ip;
    const track = document.createElement("div"); track.className = "ip-track";
    const fill = document.createElement("div"); fill.className = "ip-fill"; fill.style.width = `${item.count / max * 100}%`; track.append(fill);
    const count = document.createElement("div"); count.className = "ip-count"; count.textContent = item.count;
    row.append(ip, track, count); root.append(row);
  });
}
function renderChart(items) {
  const root = $("hourChart");
  root.replaceChildren();
  if (!items || !items.length) {
    root.innerHTML = '<div class="empty-state">Waiting for timestamped events…</div>';
    return;
  }
  const max = Math.max(...items.map(x => x.count), 1);
  items.forEach(item => {
    const col = document.createElement("div"); col.className = "bar-item";
    const val = document.createElement("span"); val.className = "bar-value"; val.textContent = item.count;
    const bar = document.createElement("div"); bar.className = "bar"; bar.style.height = `${Math.max(3, item.count / max * 100)}%`;
    bar.title = `${item.hour}: ${item.count} events`;
    const label = document.createElement("span"); label.className = "bar-label"; label.textContent = item.hour;
    col.append(val, bar, label); root.append(col);
  });
}
function renderEvents() {
  const root = $("eventRows");
  const query = $("eventFilter").value.trim().toLowerCase();
  const rows = cachedEvents.filter(e => `${e.ip} ${e.event} ${e.timestamp}`.toLowerCase().includes(query));
  root.replaceChildren();
  if (!rows.length) {
    const tr = document.createElement("tr"); const td = document.createElement("td");
    td.colSpan = 4; td.className = "empty-state"; td.textContent = query ? "No matching events." : "No events logged yet.";
    tr.append(td); root.append(tr);
  } else {
    rows.forEach(e => {
      const tr = document.createElement("tr");
      [e.timestamp, e.ip, e.event, `${e.bytes} B`].forEach((value, i) => {
        const td = document.createElement("td");
        if (i === 1) td.className = "ip-cell";
        if (i === 2) { const badge = document.createElement("span"); badge.className = "event-badge"; badge.textContent = value; td.append(badge); }
        else td.textContent = value;
        tr.append(td);
      });
      root.append(tr);
    });
  }
  $("eventCount").textContent = `${rows.length} event${rows.length === 1 ? "" : "s"} shown`;
}
async function refresh() {
  try {
    const data = await api("/api/dashboard");
    setStatus(data.running, data.port);
    $("totalEvents").textContent = data.stats.total_events;
    $("totalConnections").textContent = data.stats.total_connections;
    $("uniqueIps").textContent = data.stats.unique_ips;
    cachedEvents = data.events || [];
    renderEvents(); renderIps(data.stats.top_ips); renderChart(data.stats.hourly);
  } catch (err) {
    $("statusText").textContent = "Dashboard API unavailable";
    console.error(err);
  }
}
$("startBtn").addEventListener("click", async () => {
  try { const d = await api("/api/start", {method:"POST"}); toast(d.message); await refresh(); }
  catch (e) { toast(e.message, true); }
});
$("stopBtn").addEventListener("click", async () => {
  try { const d = await api("/api/stop", {method:"POST"}); toast(d.message); await refresh(); }
  catch (e) { toast(e.message, true); }
});
$("savePortBtn").addEventListener("click", async () => {
  try {
    const d = await api("/api/config", {method:"POST", body:JSON.stringify({port:$("portInput").value})});
    toast(d.message); await refresh();
  } catch (e) { toast(e.message, true); }
});
$("refreshBtn").addEventListener("click", refresh);
$("eventFilter").addEventListener("input", renderEvents);
$("analyzeBtn").addEventListener("click", async () => {
  $("analyzeBtn").disabled = true; $("analyzerOutput").textContent = "Running analyzer.exe…";
  try {
    const d = await api("/api/analyze", {method:"POST"});
    $("analyzerOutput").textContent = d.output || "Analysis complete.";
    if (!d.ok) toast("Analyzer exited with an error.", true);
  } catch (e) { $("analyzerOutput").textContent = e.message; toast(e.message, true); }
  finally { $("analyzeBtn").disabled = false; }
});
refresh();
window.setInterval(refresh, 5000);
