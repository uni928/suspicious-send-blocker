const $ = (id) => document.getElementById(id);

async function render() {
  const { history } = await chrome.storage.local.get({ history: [] });
  const list = $("list");
  list.innerHTML = "";
  for (const h of history.slice(0, 20)) {
    const d = document.createElement("div");
    d.className = "item";
    d.innerHTML = `
      <div><b>${h.kind}</b> / ${h.method} / reason: <b>${h.reason}</b></div>
      <div class="small">url: ${h.url}</div>
      <div class="small">page: ${h.page}</div>
      <div class="small">time: ${new Date(h.ts).toLocaleString()}</div>
    `;
    list.appendChild(d);
  }
}

$("add").onclick = async () => {
  const host = $("allowHost").value.trim();
  if (!host) return;

  const { config } = await chrome.storage.sync.get({ config: null });
  const cfg = config || {};
  const allowHosts = Array.isArray(cfg.allowHosts) ? cfg.allowHosts : [];
  if (!allowHosts.includes(host)) allowHosts.push(host);

  await chrome.storage.sync.set({ config: { ...cfg, allowHosts } });
  $("allowHost").value = "";
};

$("clear").onclick = async () => {
  await chrome.storage.local.set({ history: [] });
  render();
};

render();
