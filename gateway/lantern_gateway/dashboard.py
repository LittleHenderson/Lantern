"""The owner's dashboard for the gateway: one self-contained page, no outside requests.

It asks for the admin secret once (kept in this tab's memory only, never stored), then draws the numbers
from /v1/admin/stats: who is using the free allowance and how much it costs, plus the opt-in usage counts
from the app. Everything shown is an aggregate; the gateway holds no code, no file names, no prompts.
"""

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lantern · owner dashboard</title>
<style>
:root{--bg:#F5F5F2;--surface:#fff;--ink:#161618;--ink2:#46464C;--muted:#62626A;--line:rgba(22,22,24,.09);--accent:#0F7B74;--accent-soft:rgba(15,123,116,.10);--warn:#8A5A00;--warn-soft:rgba(250,178,25,.17);--crit:#B02A2A;--crit-soft:rgba(208,59,59,.11);--mono:ui-monospace,Menlo,Consolas,monospace}
@media(prefers-color-scheme:dark){:root{--bg:#0E0E10;--surface:#161618;--ink:#F3F3F1;--ink2:#BEBEC3;--muted:#9A9AA0;--line:rgba(255,255,255,.08);--accent:#4FC3BA;--accent-soft:rgba(79,195,186,.14);--warn:#FAC55A;--crit:#FF8A8A}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:26px 0 10px;color:var(--ink2)}
.lede{color:var(--muted);margin:0 0 18px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.tile .n{font-size:26px;font-weight:650;letter-spacing:-.02em}.tile .l{font-size:12px;color:var(--muted)}
.tile.warn{background:var(--warn-soft)}.tile.crit{background:var(--crit-soft)}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600;font-size:12px}
td.num,th.num{text-align:right;font-family:var(--mono)}
.bars{display:flex;align-items:flex-end;gap:3px;height:110px;margin-top:8px}
.bars div{flex:1;background:var(--accent);opacity:.85;border-radius:3px 3px 0 0;min-height:2px;position:relative}
.bars div:hover::after{content:attr(title);position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:var(--ink);color:var(--bg);font:11px var(--mono);padding:2px 6px;border-radius:4px;white-space:nowrap}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
input{font:14px var(--mono);padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);width:min(420px,100%)}
button{font:600 14px system-ui;padding:9px 14px;border-radius:8px;border:1px solid var(--line);background:var(--ink);color:var(--bg);cursor:pointer;margin-left:8px}
.err{color:var(--crit);margin-top:8px}.small{font-size:12px;color:var(--muted)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
</style></head><body><main>
<h1>Lantern · owner dashboard</h1>
<p class="lede">The free allowance and the app's opt-in usage counts. Aggregates only: this server holds no code, file names or prompts.</p>
<div id="login" class="card"><label for="secret">Admin secret (kept in this tab only)</label>
<div class="row"><input id="secret" type="password" autocomplete="off"><button id="go">Show</button><span class="small">Days: <select id="days"><option>7</option><option selected>30</option><option>90</option></select></span></div><div id="err" class="err"></div></div>
<div id="out" hidden></div>
</main>
<script>
const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const num = v => typeof v === 'number' ? v.toLocaleString() : esc(v);
let SECRET = '';
async function load() {
  SECRET = $('#secret').value.trim(); $('#err').textContent = '';
  const r = await fetch('/v1/admin/stats?days=' + encodeURIComponent($('#days').value), {headers: {authorization: 'Bearer ' + SECRET}});
  if (!r.ok) { $('#err').textContent = r.status === 403 ? 'That secret was not accepted.' : 'HTTP ' + r.status; return; }
  draw(await r.json());
}
function tile(n, l, cls = '') { return `<div class="tile ${cls}"><div class="n">${num(n)}</div><div class="l">${esc(l)}</div></div>`; }
function bars(rows, key, fmt) {
  const max = Math.max(1, ...rows.map(r => r[key]));
  return `<div class="bars">${rows.map(r => `<div style="height:${Math.round(100 * r[key] / max)}%" title="${esc(r.day)}: ${esc(fmt(r[key]))}"></div>`).join('')}</div>`;
}
function draw(d) {
  const a = d.allowance, p = d.app;
  const usdDay = a.usd_today, paused = usdDay >= (d.global_daily_usd || Infinity);
  $('#out').hidden = false;
  $('#out').innerHTML = `
  <h2>Free allowance · last ${esc(d.days)} days (today ${esc(d.today)} UTC)</h2>
  <div class="grid">${tile(a.users_active_today, 'people used it today')}${tile(a.users_active_7d, 'people in the last 7 days')}${tile(a.users_active_30d, 'people in the last ' + d.days + ' days')}
  ${tile(a.requests_today, 'explanations today')}${tile(a.requests_30d, 'explanations, ' + d.days + ' days')}
  ${tile('$' + a.usd_today.toFixed(2), 'spent today', paused ? 'crit' : '')}${tile('$' + a.usd_30d.toFixed(2), 'spent, ' + d.days + ' days')}
  ${tile(a.tokens_issued, 'tokens issued')}${tile(a.accounts ?? 0, 'signed-in accounts')}${tile(a.accounts_github ?? 0, 'via GitHub')}${tile(a.accounts_google ?? 0, 'via Google')}${tile(a.users_ever_used, 'ever used it')}${tile(a.users_exhausted, 'used up the free allowance', a.users_exhausted ? 'warn' : '')}${tile(a.disabled, 'disabled')}</div>
  <div class="card" style="margin-top:10px"><b>Explanations per day</b>${bars(a.daily, 'requests', v => v + ' explanations')}
  <b style="display:block;margin-top:14px">Spend per day</b>${bars(a.daily, 'usd', v => '$' + v.toFixed(2))}</div>
  <h2>Which model answered</h2>
  <div class="card"><table><tr><th>Model</th><th class="num">Explanations</th><th class="num">Spend</th></tr>
  ${(a.by_model || []).map(m => `<tr><td>${esc(m.model)}</td><td class="num">${num(m.requests)}</td><td class="num">$${m.usd.toFixed(2)}</td></tr>`).join('') || '<tr><td colspan=3 class="small">No model calls yet.</td></tr>'}</table>
  <p class="small">DeepSeek answers first. If DeepSeek has no balance, is rate-limited or down, the fallback model answers the same request so nobody waits.</p></div>
  <h2>Heaviest users (by label; labels are what you typed when minting the token)</h2>
  <div class="card"><table><tr><th>Label</th><th class="num">Explanations</th><th class="num">Tokens</th></tr>
  ${a.top_users.map(u => `<tr><td>${esc(u.label)}</td><td class="num">${num(u.requests)}</td><td class="num">${num(u.tokens)}</td></tr>`).join('') || '<tr><td colspan=3 class="small">No usage yet.</td></tr>'}</table></div>
  <h2>Give someone a free allowance by hand</h2>
  <p class="small">People can also sign in themselves at <code>/v1/login</code> (GitHub or Google) when those are configured; each sign-in gets its own token, earlier ones keep working, and they all share one count per account.</p>
  <div class="card"><label for="label">Label (who it's for, e.g. a GitHub name; only you see it)</label>
  <div class="row"><input id="label" placeholder="github:octocat"><button id="mint">Create token</button></div>
  <div id="minted" class="small" style="margin-top:8px"></div>
  <p class="small">The token is shown once; only its hash is kept. They run <code>lantern login --token lt_…</code>. Limits: ${num(d.limits.requests)} explanations, ${num(d.limits.per_day)} per day.</p></div>
  <h2>The app · opt-in usage counts</h2>
  <p class="small">Only from people who turned on "Share anonymous usage counts" in Settings. One random id per install, the app version and operating system, and how many times each feature was used per day. Nothing else is accepted.</p>
  <div class="grid">${tile(p.installs_total, 'installs that ever reported')}${tile(p.installs_active_7d, 'active in the last 7 days')}${tile(p.installs_active_30d, 'active in the last ' + d.days + ' days')}</div>
  <div class="card" style="margin-top:10px"><b>Active installs per day</b>${bars(p.daily_installs, 'installs', v => v + ' installs')}</div>
  <div class="card" style="margin-top:10px"><table><tr><th>Feature</th><th class="num">Uses, ${esc(d.days)} days</th><th class="num">Installs using it</th></tr>
  ${p.features_30d.map(f => `<tr><td>${esc(f.feature)}</td><td class="num">${num(f.count)}</td><td class="num">${num(f.installs)}</td></tr>`).join('') || '<tr><td colspan=3 class="small">No usage pings yet.</td></tr>'}</table></div>
  <div class="row" style="margin-top:10px"><div class="card" style="flex:1"><b>Versions</b><table>${p.versions.map(v => `<tr><td>${esc(v.version || '?')}</td><td class="num">${num(v.installs)}</td></tr>`).join('')}</table></div>
  <div class="card" style="flex:1"><b>Operating systems</b><table>${p.os.map(v => `<tr><td>${esc(v.os || '?')}</td><td class="num">${num(v.installs)}</td></tr>`).join('')}</table></div></div>
  <p class="small">Numbers come from this server's own counters. Explanations count model calls through the allowance; spend is computed from token counts at the configured prices, so it can differ slightly from the provider's invoice.</p>`;
}
document.addEventListener('click', async e => {
  if (e.target.id !== 'mint') return;
  const label = $('#label').value.trim(); const out = $('#minted');
  const r = await fetch('/v1/tokens', {method: 'POST', headers: {authorization: 'Bearer ' + SECRET, 'content-type': 'application/json'}, body: JSON.stringify({label})});
  if (!r.ok) { out.textContent = 'Could not create a token (HTTP ' + r.status + ').'; return; }
  const j = await r.json();
  out.innerHTML = `Token for <b>${esc(label || '(no label)')}</b>, shown once: <code style="user-select:all">${esc(j.token)}</code>`;
  $('#label').value = '';
});
$('#go').onclick = load; $('#secret').addEventListener('keydown', e => { if (e.key === 'Enter') load(); }); $('#days').onchange = () => { if (SECRET) load(); };
</script></body></html>"""
