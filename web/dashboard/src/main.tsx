import { render } from "preact";
import { useCallback, useEffect, useState } from "preact/hooks";
import {
  api, ApiError, fmt, login, logout, me, pct,
  type Event, type LabResult, type ListEntry, type ModelStatus, type Rule, type Site, type Stats,
} from "./api";
import { OutcomeChart, RankBars, RiskHistogram } from "./charts";

// ---------------- routing ----------------

function useRoute(): string[] {
  const parse = () => (location.hash.replace(/^#\/?/, "") || "sites").split("/").filter(Boolean);
  const [r, setR] = useState(parse());
  useEffect(() => {
    const on = () => setR(parse());
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);
  return r;
}

function useLoad<T>(fn: () => Promise<T>, deps: unknown[]): [T | null, string, () => void] {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState("");
  const [n, setN] = useState(0);
  useEffect(() => {
    let live = true;
    setErr("");
    fn().then((d) => live && setData(d), (e) => live && setErr(String(e.message || e)));
    return () => { live = false; };
  }, [...deps, n]);
  return [data, err, useCallback(() => setN((x) => x + 1), [])];
}

const Logo = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="2" width="14" height="20" rx="2" fill="currentColor" /><circle cx="15" cy="12" r="1.6" fill="#fff" /></svg>
);

function Outcome({ o }: { o: string }) {
  const icon = o === "allow" ? "✓" : o === "block" ? "✕" : "!";
  const label = o === "allow" ? "Allowed" : o === "block" ? "Blocked" : "Challenged";
  return <span class={`badge ${o}`}><span aria-hidden="true">{icon}</span>{label}</span>;
}

function Err({ msg }: { msg: string }) {
  return msg ? <div class="notice err" role="alert">{msg}</div> : null;
}

// ---------------- login ----------------

function Login({ onDone }: { onDone: () => void }) {
  const [user, setUser] = useState("");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: SubmitEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await login(user, pw);
      onDone();
    } catch (x) {
      setErr(x instanceof ApiError && x.status === 429 ? "Too many attempts. Wait 15 minutes and try again." : "Wrong user or password.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <main class="login">
      <div class="brand"><Logo />doorkeep</div>
      <form class="card grid" onSubmit={submit}>
        <h1>Sign in</h1>
        <label class="field">User<input value={user} onInput={(e) => setUser(e.currentTarget.value)} autocomplete="username" required /></label>
        <label class="field">Password<input type="password" value={pw} onInput={(e) => setPw(e.currentTarget.value)} autocomplete="current-password" required /></label>
        <Err msg={err} />
        <button class="primary" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        <p class="muted" style={{ margin: 0, fontSize: "12.5px" }}>No account yet? Run <code>doorkeep admin create --user NAME</code> on the server.</p>
      </form>
    </main>
  );
}

// ---------------- shell ----------------

function Shell({ actor, route, sites, children, onLogout }: { actor: string; route: string[]; sites: Site[]; children: any; onLogout: () => void }) {
  const cur = (h: string) => ("#/" + route.join("/")).startsWith(h) ? "page" : undefined;
  const toggleTheme = () => {
    const d = document.documentElement;
    const dark = d.dataset.theme ? d.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    d.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("dk-theme", d.dataset.theme); } catch {}
  };
  return (
    <div class="shell">
      <nav class="side" aria-label="Main">
        <div class="brand"><Logo />doorkeep</div>
        <div class="nav">
          <a href="#/sites" aria-current={route.length === 1 && route[0] === "sites" ? "page" : undefined}>All sites</a>
        </div>
        {sites.length > 0 && <div class="nav-label">Sites</div>}
        <div class="nav">
          {sites.map((s) => <a key={s.id} href={`#/sites/${s.id}/overview`} aria-current={cur(`#/sites/${s.id}`)}>{s.name}</a>)}
        </div>
        <div class="nav-label">Instance</div>
        <div class="nav">
          <a href="#/privacy" aria-current={cur("#/privacy")}>Privacy</a>
          <a href="#/tokens" aria-current={cur("#/tokens")}>API tokens</a>
          <a href="#/audit" aria-current={cur("#/audit")}>Audit log</a>
        </div>
        <div class="side-foot">
          <span title={actor}>{actor.replace(/^user:/, "")}</span>
          <span class="row" style={{ gap: "4px" }}>
            <button class="small" onClick={toggleTheme}>Theme</button>
            <button class="small" onClick={onLogout}>Sign out</button>
          </span>
        </div>
      </nav>
      <main>{children}</main>
    </div>
  );
}

// ---------------- sites ----------------

function SiteList({ sites, reload }: { sites: Site[]; reload: () => void }) {
  const [name, setName] = useState("");
  const [origin, setOrigin] = useState("");
  const [created, setCreated] = useState<{ site: Site; secret: string } | null>(null);
  const [err, setErr] = useState("");
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    setErr("");
    try {
      const r = await api<{ site: Site; secret: string }>("POST", "/sites", { name, origins: origin.split(/[\s,]+/).filter(Boolean) });
      setCreated(r);
      setName("");
      setOrigin("");
      reload();
    } catch (x: any) {
      setErr(x.message);
    }
  };
  return (
    <>
      <div class="head"><h1>Sites</h1></div>
      {created && <SecretNotice site={created.site} secret={created.secret} onClose={() => setCreated(null)} />}
      <div class="card" style={{ marginBottom: "16px" }}>
        {sites.length === 0 ? <div class="empty">No sites yet. Create one below.</div> : (
          <table>
            <thead><tr><th>Name</th><th>Site key</th><th>Origins</th><th>Mode</th></tr></thead>
            <tbody>
              {sites.map((s) => (
                <tr key={s.id} class="click" onClick={() => (location.hash = `#/sites/${s.id}/overview`)}>
                  <td><a href={`#/sites/${s.id}/overview`}>{s.name}</a></td>
                  <td><code>{s.site_key}</code></td>
                  <td>{s.origins.join(", ")}</td>
                  <td>{s.mode}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <form class="card grid" onSubmit={create} style={{ maxWidth: "620px" }}>
        <h2>Add a site</h2>
        <label class="field">Name<input value={name} onInput={(e) => setName(e.currentTarget.value)} required /></label>
        <label class="field">Allowed origins (space or comma separated)<input value={origin} onInput={(e) => setOrigin(e.currentTarget.value)} placeholder="https://example.com" required /></label>
        <Err msg={err} />
        <div><button class="primary">Create site</button></div>
      </form>
    </>
  );
}

function SecretNotice({ site, secret, onClose }: { site: Site; secret: string; onClose: () => void }) {
  return (
    <div class="notice ok grid" style={{ marginBottom: "16px" }} role="status">
      <h2 style={{ margin: 0 }}>{site.name}: copy the secret now</h2>
      <p style={{ margin: 0 }}>The secret is shown once. It goes in your backend only, never in HTML.</p>
      <div class="secret">{secret}</div>
      <h3 style={{ margin: "8px 0 0" }}>Add to your page</h3>
      <pre class="code">{`<script src="/_dk/v1/dk.js" data-sitekey="${site.site_key}" async defer></script>
<div class="doorkeep" data-action="signup"></div>   <!-- inside your form -->`}</pre>
      <h3 style={{ margin: "8px 0 0" }}>Verify on your server</h3>
      <pre class="code">{`POST /v1/siteverify  secret=<secret>&response=<dk-response>&expected_action=signup`}</pre>
      <div><button onClick={onClose}>Done</button></div>
    </div>
  );
}

const TABS = [["overview", "Overview"], ["events", "Events"], ["rules", "Rules"], ["lists", "Lists"], ["model", "Model"], ["settings", "Settings"]];

function SitePage({ site, tab, sub, reloadSites }: { site: Site; tab: string; sub?: string; reloadSites: () => void }) {
  return (
    <>
      <div class="head">
        <div><h1>{site.name}</h1><div class="muted">{site.origins.join(", ")} · <code>{site.site_key}</code></div></div>
        {site.mode !== "enforce" && <span class="badge challenge">{site.mode === "monitor" ? "Monitor mode: nothing is blocked" : "Challenge-only mode"}</span>}
      </div>
      <nav class="tabs" aria-label="Site">
        {TABS.map(([k, l]) => <a key={k} href={`#/sites/${site.id}/${k}`} aria-current={tab === k ? "page" : undefined}>{l}</a>)}
      </nav>
      {tab === "overview" && <Overview site={site} />}
      {tab === "events" && <Events site={site} openId={sub} />}
      {tab === "rules" && <Rules site={site} />}
      {tab === "lists" && <Lists site={site} />}
      {tab === "model" && <Model site={site} />}
      {tab === "settings" && <Settings site={site} onSaved={reloadSites} />}
    </>
  );
}

// ---------------- overview ----------------

const RANGES = [["24h", "24 hours"], ["168h", "7 days"], ["720h", "30 days"]];

function Overview({ site }: { site: Site }) {
  const [range, setRange] = useState("24h");
  const [st, err] = useLoad(() => api<Stats>("GET", `/sites/${site.id}/stats?range=${range}`), [site.id, range]);
  const t = st?.totals || {};
  const total = st?.total || 0;
  return (
    <div class="grid">
      <div class="row" style={{ justifyContent: "space-between" }}>
        <div class="seg" role="group" aria-label="Time range">
          {RANGES.map(([k, l]) => <button key={k} aria-pressed={range === k} onClick={() => setRange(k)}>{l}</button>)}
        </div>
        <a href={`#/sites/${site.id}/events`}>View events →</a>
      </div>
      <Err msg={err} />
      {st && (
        <>
          <div class="grid g4">
            <div class="card tile"><div class="label">Requests scored</div><div class="value">{fmt(total)}</div><div class="sub">{fmt(st.verified)} verified by your backend</div></div>
            <div class="card tile"><div class="label"><i class="dot" style={{ background: "var(--good)" }} />Allowed</div><div class="value">{fmt(t.allow || 0)}</div><div class="sub">{pct(t.allow || 0, total)}</div></div>
            <div class="card tile"><div class="label"><i class="dot" style={{ background: "var(--warning)" }} />Challenged</div><div class="value">{fmt(t.challenge || 0)}</div><div class="sub">{fmt((st.challenge.pow_ok || 0) + (st.challenge.visual_ok || 0))} solved</div></div>
            <div class="card tile"><div class="label"><i class="dot" style={{ background: "var(--critical)" }} />Blocked</div><div class="value">{fmt(t.block || 0)}</div><div class="sub">{pct(t.block || 0, total)}</div></div>
          </div>
          <div class="card"><h2>Requests per hour</h2><OutcomeChart series={st.series} /></div>
          <div class="grid g3">
            <div class="card">
              <h2>Top reasons</h2>
              <RankBars items={st.reasons} total={total} render={(k) => <a href={`#/sites/${site.id}/events?reason=${k}`}><code>{k}</code></a>} />
            </div>
            <div class="card">
              <h2>Risk distribution</h2>
              <RiskHistogram hist={st.risk_hist} challenge={site.thresholds.t_challenge || 35} block={site.thresholds.t_block || 75} />
            </div>
          </div>
          <div class="grid g3">
            <div class="card"><h2>Browsers</h2><RankBars items={st.browsers} total={total} /></div>
            <div class="card"><h2>Networks</h2><RankBars items={st.asn_class} total={total} /><h3 style={{ marginTop: "16px" }}>Countries</h3><RankBars items={st.countries} total={total} render={(k) => k.toUpperCase()} /></div>
          </div>
        </>
      )}
    </div>
  );
}

// ---------------- events ----------------

function Events({ site, openId }: { site: Site; openId?: string }) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const [outcome, setOutcome] = useState(q.get("outcome") || "");
  const [reason, setReason] = useState(q.get("reason") || "");
  const [fp, setFp] = useState(q.get("fp") || "");
  const [ip, setIp] = useState("");
  const [open, setOpen] = useState<string | null>(openId || null);
  const params = new URLSearchParams({ limit: "200", ...(outcome && { outcome }), ...(reason && { reason }), ...(fp && { fp }), ...(ip && { ip }) });
  const [evs, err, reload] = useLoad(() => api<Event[]>("GET", `/sites/${site.id}/events?${params}`), [site.id, outcome, reason, fp, ip]);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [note, setNote] = useState("");
  useEffect(() => setSel(new Set()), [site.id, outcome, reason, fp, ip]);
  const toggle = (id: string) => setSel((cur) => { const n = new Set(cur); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const allShown = !!evs && evs.length > 0 && evs.every((e) => sel.has(e.id));
  const bulk = async (label: string, byFilter: boolean) => {
    const what = label ? `as ${label}` : "as unlabelled";
    if (byFilter && !confirm(`Label every event matching this filter (up to 1000) ${what}? This trains the site's model.`)) return;
    try {
      const body = byFilter ? { label, filter: { outcome, reason, fp } } : { label, ids: [...sel] };
      const r = await api<{ labelled: number }>("POST", `/sites/${site.id}/labels`, body);
      setNote(`Labelled ${r.labelled} event${r.labelled === 1 ? "" : "s"} ${what}.`);
      setSel(new Set());
      reload();
    } catch (x: any) {
      setNote(x.message);
    }
  };
  const filtered = !!(outcome || reason || fp);
  return (
    <div class="grid">
      <div class="row card">
        <select value={outcome} onChange={(e) => setOutcome(e.currentTarget.value)} aria-label="Outcome">
          <option value="">All outcomes</option><option value="allow">Allowed</option><option value="challenge">Challenged</option><option value="block">Blocked</option>
        </select>
        <input placeholder="Reason code" value={reason} onChange={(e) => setReason(e.currentTarget.value.trim().toUpperCase())} aria-label="Reason code" />
        <input placeholder="Fingerprint prefix" value={fp} onChange={(e) => setFp(e.currentTarget.value.trim())} aria-label="Fingerprint prefix" />
        <input placeholder="IP (today only)" value={ip} onChange={(e) => setIp(e.currentTarget.value.trim())} aria-label="IP address, today only" title="IP hashes rotate daily, so lookups work for today only" />
        {(outcome || reason || fp || ip) && <button onClick={() => { setOutcome(""); setReason(""); setFp(""); setIp(""); }}>Clear</button>}
      </div>
      <Err msg={err} />
      {(sel.size > 0 || filtered) && (
        <div class="row card" role="toolbar" aria-label="Label events">
          {sel.size > 0 && <>
            <span><b>{sel.size}</b> selected</span>
            <button class="small" onClick={() => bulk("bot", false)}>Label bot</button>
            <button class="small" onClick={() => bulk("human", false)}>Label human</button>
            <button class="small" onClick={() => bulk("", false)}>Clear label</button>
          </>}
          {filtered && sel.size === 0 && <>
            <span class="secondary">All events matching this filter:</span>
            <button class="small" onClick={() => bulk("bot", true)}>Label bot</button>
            <button class="small" onClick={() => bulk("human", true)}>Label human</button>
          </>}
        </div>
      )}
      {note && <div class="notice ok" role="status">{note}</div>}
      <div class="card" style={{ padding: "4px 8px", overflowX: "auto" }}>
        {evs && evs.length === 0 && <div class="empty">No events match.</div>}
        {evs && evs.length > 0 && (
          <table>
            <thead><tr><th><input type="checkbox" aria-label="Select all shown events" checked={allShown}
              onChange={() => setSel(allShown ? new Set() : new Set(evs.map((e) => e.id)))} /></th><th>Time</th><th>Action</th><th>Outcome</th><th class="num">Risk</th><th>Reasons</th><th>Browser</th><th>Network</th><th>Device</th><th>Label</th></tr></thead>
            <tbody>
              {evs.map((e) => (
                <tr key={e.id} class="click" onClick={() => setOpen(e.id)} tabIndex={0} onKeyDown={(k) => k.key === "Enter" && setOpen(e.id)}>
                  <td onClick={(ev) => ev.stopPropagation()}><input type="checkbox" aria-label={`Select event ${e.id}`} checked={sel.has(e.id)} onChange={() => toggle(e.id)} /></td>
                  <td class="secondary" style={{ whiteSpace: "nowrap" }}>{new Date(e.ts).toLocaleString()}</td>
                  <td>{e.action}</td>
                  <td><Outcome o={e.outcome} />{e.challenge_kind && <span class="muted"> · {e.challenge_kind}{e.challenge_ok === false ? " failed" : ""}</span>}</td>
                  <td class="num"><b>{e.risk}</b></td>
                  <td>{(e.reasons || []).filter((r) => r.w !== 0).slice(0, 3).map((r) => <span class="chip" key={r.code}>{r.code}</span>)}</td>
                  <td>{e.ua_family} {e.ua_major || ""}<div class="muted">{e.os_family}</div></td>
                  <td>{e.asn_class}{e.country && <div class="muted">{e.country.toUpperCase()}{e.asn ? ` · AS${e.asn}` : ""}</div>}</td>
                  <td><code>{e.fp}</code></td>
                  <td>{e.label && <span class="badge">{e.label}</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {open && <EventDrawer site={site} id={open} onClose={() => { setOpen(null); reload(); }} />}
    </div>
  );
}

function EventDrawer({ site, id, onClose }: { site: Site; id: string; onClose: () => void }) {
  const [e, err, reload] = useLoad(() => api<Event>("GET", `/sites/${site.id}/events/${id}`), [id]);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const k = (ev: KeyboardEvent) => ev.key === "Escape" && onClose();
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, []);
  const label = async (l: string) => {
    setBusy(true);
    await api("POST", `/sites/${site.id}/events/${id}/label`, { label: l }).catch(() => {});
    setBusy(false);
    reload();
  };
  const del = async () => {
    if (!confirm("Delete this event permanently? Use this for data subject requests.")) return;
    await api("DELETE", `/sites/${site.id}/events/${id}`);
    onClose();
  };
  return (
    <>
      <div class="drawer-back" onClick={onClose} />
      <aside class="drawer" role="dialog" aria-modal="true" aria-label="Event detail">
        <div class="head"><h2 style={{ margin: 0 }}>Event</h2><button onClick={onClose} aria-label="Close">✕</button></div>
        <Err msg={err} />
        {e && (
          <div class="grid">
            <dl class="kv">
              <dt>Outcome</dt><dd><Outcome o={e.outcome} />{e.would_be !== e.outcome && <span class="muted"> (would be {e.would_be})</span>}</dd>
              <dt>Risk</dt><dd><b>{e.risk}</b></dd>
              <dt>Time</dt><dd>{new Date(e.ts).toLocaleString()}</dd>
              <dt>Action</dt><dd>{e.action}</dd>
              <dt>Challenge</dt><dd>{e.challenge_kind || "none"}{e.challenge_ok !== undefined && (e.challenge_ok ? " (solved)" : " (failed)")}</dd>
              <dt>Verified by backend</dt><dd>{e.verified_at ? new Date(e.verified_at).toLocaleString() : "no"}</dd>
              <dt>Browser</dt><dd>{e.ua_family} {e.ua_major} on {e.os_family}</dd>
              <dt>Network</dt><dd>{e.asn_class}{e.asn ? ` · AS${e.asn}` : ""} {e.country && `· ${e.country.toUpperCase()}`}</dd>
              <dt>Device fingerprint</dt><dd><a href={`#/sites/${site.id}/events?fp=${e.fp}`} onClick={onClose}><code>{e.fp}</code></a> <span class="muted">(this site, this month)</span></dd>
              <dt>ID</dt><dd><code>{e.id}</code></dd>
            </dl>
            <div>
              <h3>Reasons</h3>
              {(e.reasons || []).length === 0 && <div class="muted">None</div>}
              {(e.reasons || []).map((r) => <div class="feat" key={r.code}><code>{r.code}</code><span class="num">{r.w > 0 ? "+" : ""}{r.w || ""}</span></div>)}
              {(e.shadow || []).length > 0 && (
                <>
                  <h3 style={{ marginTop: "12px" }}>Shadow (not enforced)</h3>
                  {e.shadow!.map((r) => <div class="feat" key={r.code}><code>{r.code}</code><span class="num muted">{r.w > 0 ? "+" : ""}{r.w}</span></div>)}
                </>
              )}
            </div>
            <div>
              <h3>Label <span class="muted" style={{ fontWeight: 400 }}>(trains the supervised model)</span></h3>
              <div class="row">
                <button disabled={busy} aria-pressed={e.label === "human"} onClick={() => label("human")}>Human</button>
                <button disabled={busy} aria-pressed={e.label === "bot"} onClick={() => label("bot")}>Bot</button>
                {e.label && <button disabled={busy} onClick={() => label("")}>Clear</button>}
              </div>
            </div>
            <div>
              <h3>Signals</h3>
              {Object.entries(e.feature_groups || {}).map(([g, fs]) => (
                <details key={g} open={g === "auto" || g === "net"}>
                  <summary style={{ cursor: "pointer", padding: "4px 0" }}><b>{{ prof: "Privacy profile", auto: "Automation", fp: "Consistency", beh: "Behaviour", env: "Environment", t: "Timing", net: "Network", vel: "Velocity" }[g] || g}</b> <span class="muted">({fs.length})</span></summary>
                  {fs.map((f) => <div class="feat" key={f.key} title={f.desc}><code>{f.key}</code><span class="num">{typeof f.value === "number" ? Math.round(f.value * 1000) / 1000 : f.value}</span></div>)}
                </details>
              ))}
            </div>
            <div><button class="danger" onClick={del}>Delete event</button></div>
          </div>
        )}
      </aside>
    </>
  );
}

// ---------------- rules ----------------

function Rules({ site }: { site: Site }) {
  const [rules, err, reload] = useLoad(() => api<Rule[]>("GET", `/sites/${site.id}/rules`), [site.id]);
  const [filter, setFilter] = useState("");
  const [lab, setLab] = useState<{ rule: string; res?: LabResult; err?: string } | null>(null);
  const [custom, setCustom] = useState({ id: "", when: "", weight: "20" });
  const [msg, setMsg] = useState("");
  const put = async (id: string, body: any) => {
    setMsg("");
    try { await api("PUT", `/sites/${site.id}/rules/${id}`, body); reload(); } catch (x: any) { setMsg(x.message); }
  };
  const reset = async (id: string) => { await api("DELETE", `/sites/${site.id}/rules/${id}`); reload(); };
  const runLab = async (rule: string, override: any) => {
    setLab({ rule });
    scrollTo({ top: 0, behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
    try { setLab({ rule, res: await api<LabResult>("POST", `/sites/${site.id}/rules-lab`, { rule, override, days: 7 }) }); }
    catch (x: any) { setLab({ rule, err: x.message }); }
  };
  const shown = (rules || []).filter((r) => !filter || r.id.includes(filter.toUpperCase()) || (r.description || "").toLowerCase().includes(filter.toLowerCase()));
  return (
    <div class="grid">
      <div class="notice">Rules add their weight to a 0 to 100 risk score. <b>Shadow</b> evaluates a rule and records what it would have done without changing any decision. Use the lab to replay a change over the last 7 days before enforcing it.</div>
      <Err msg={err || msg} />
      {lab && (
        <div class="card" role="status">
          <div class="head" style={{ marginBottom: "8px" }}><h2 style={{ margin: 0 }}>Lab: <code>{lab.rule}</code> over 7 days</h2><button class="small" onClick={() => setLab(null)}>Close</button></div>
          {!lab.res && !lab.err && <div class="muted">Replaying stored events…</div>}
          <Err msg={lab.err || ""} />
          {lab.res && (
            <div class="grid g4">
              <div class="tile"><div class="label">Events replayed</div><div class="value">{fmt(lab.res.events)}</div></div>
              <div class="tile"><div class="label">Rule fires</div><div class="value">{fmt(lab.res.fired)}</div><div class="sub">{pct(lab.res.fired, lab.res.events)}</div></div>
              <div class="tile"><div class="label">Outcomes that change</div><div class="value">{fmt(lab.res.changed)}</div><div class="sub">{Object.entries(lab.res.transitions).map(([k, v]) => `${k} ${v}`).join(", ") || "none"}</div></div>
              <div class="tile"><div class="label">On labelled events</div><div class="value" style={{ fontSize: "16px" }}>{lab.res.labelled.bots_fired}/{lab.res.labelled.bots_total} bots</div><div class="sub">{lab.res.labelled.humans_fired}/{lab.res.labelled.humans_total} humans hit</div></div>
            </div>
          )}
        </div>
      )}
      <div class="card" style={{ padding: "8px", overflowX: "auto" }}>
        <div class="row" style={{ padding: "4px 4px 8px" }}><input placeholder="Filter rules" value={filter} onInput={(e) => setFilter(e.currentTarget.value)} aria-label="Filter rules" /></div>
        <table>
          <thead><tr><th>Rule</th><th class="num">Weight</th><th>Mode</th><th></th></tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.id}>
                <td>
                  <code>{r.id}</code>{r.floor && <span class="chip" title="Proof: risk never drops below this weight">floor</span>}{!r.builtin && <span class="chip">custom</span>}{r.overridden && <span class="chip">changed</span>}
                  <div class="secondary" style={{ fontSize: "12.5px" }}>{r.description}</div>
                  <details><summary class="muted" style={{ fontSize: "12px", cursor: "pointer" }}>expression</summary><code style={{ fontSize: "11.5px" }}>{r.when}{r.unless ? `  unless ${r.unless}` : ""}</code></details>
                </td>
                <td class="num">
                  <input type="number" min={-100} max={100} value={r.weight} style={{ width: "72px" }} aria-label={`Weight for ${r.id}`}
                    onChange={(e) => put(r.id, r.builtin ? { weight: Number(e.currentTarget.value), mode: r.mode } : { custom: true, when: r.when, unless: r.unless, weight: Number(e.currentTarget.value), mode: r.mode })} />
                </td>
                <td>
                  <select value={r.mode} aria-label={`Mode for ${r.id}`} onChange={(e) => put(r.id, r.builtin ? { mode: e.currentTarget.value, weight: r.weight } : { custom: true, when: r.when, unless: r.unless, weight: r.weight, mode: e.currentTarget.value })}>
                    <option value="enforce">enforce</option><option value="shadow">shadow</option><option value="off">off</option>
                  </select>
                </td>
                <td style={{ whiteSpace: "nowrap" }}>
                  <button class="small" onClick={() => runLab(r.id, r.builtin ? { weight: r.weight } : { custom: true, when: r.when, unless: r.unless, weight: r.weight })}>Lab</button>
                  {r.overridden && <button class="small" onClick={() => reset(r.id)}>{r.builtin ? "Reset" : "Delete"}</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <form class="card grid" onSubmit={(e) => { e.preventDefault(); put(custom.id, { custom: true, when: custom.when, weight: Number(custom.weight), mode: "shadow" }); }}>
        <h2>Add a custom rule <span class="muted" style={{ fontWeight: 400 }}>(starts in shadow)</span></h2>
        <div class="grid g3">
          <label class="field">Rule id (UPPER_SNAKE)<input value={custom.id} onInput={(e) => setCustom({ ...custom, id: e.currentTarget.value.toUpperCase() })} placeholder="MY_RULE" required /></label>
          <label class="field">Weight<input type="number" min={-100} max={100} value={custom.weight} onInput={(e) => setCustom({ ...custom, weight: e.currentTarget.value })} /></label>
        </div>
        <label class="field">Expression<textarea value={custom.when} onInput={(e) => setCustom({ ...custom, when: e.currentTarget.value })} placeholder={`net.asn_class == "hosting" && action == "signup"`} required /></label>
        <div class="row">
          <button class="primary">Add in shadow</button>
          <button type="button" onClick={() => runLab(custom.id || "DRAFT_RULE", { custom: true, when: custom.when, weight: Number(custom.weight) })}>Try in lab first</button>
        </div>
      </form>
    </div>
  );
}

// ---------------- lists ----------------

function Lists({ site }: { site: Site }) {
  const [list, err, reload] = useLoad(() => api<ListEntry[]>("GET", `/sites/${site.id}/lists`), [site.id]);
  const [f, setF] = useState({ kind: "cidr", value: "", action: "allow", note: "" });
  const [msg, setMsg] = useState("");
  const add = async (e: SubmitEvent) => {
    e.preventDefault();
    setMsg("");
    try { await api("POST", `/sites/${site.id}/lists`, f); setF({ ...f, value: "", note: "" }); reload(); } catch (x: any) { setMsg(x.message); }
  };
  return (
    <div class="grid">
      <div class="notice">Lists are checked before rules. <b>Allow</b> wins over everything, then <b>deny</b>, then <b>always challenge</b>.</div>
      <Err msg={err || msg} />
      <div class="card" style={{ padding: "8px" }}>
        {list && list.length === 0 && <div class="empty">No entries.</div>}
        {list && list.length > 0 && (
          <table>
            <thead><tr><th>Action</th><th>Match</th><th>Value</th><th>Note</th><th></th></tr></thead>
            <tbody>{list.map((l) => (
              <tr key={l.id}><td>{l.action.replace("_", " ")}</td><td>{l.kind}</td><td><code>{l.value}</code></td><td class="secondary">{l.note}</td>
                <td><button class="small" onClick={async () => { await api("DELETE", `/sites/${site.id}/lists/${l.id}`); reload(); }}>Remove</button></td></tr>
            ))}</tbody>
          </table>
        )}
      </div>
      <form class="card row" onSubmit={add}>
        <select value={f.action} onChange={(e) => setF({ ...f, action: e.currentTarget.value })} aria-label="Action"><option value="allow">Allow</option><option value="deny">Deny</option><option value="always_challenge">Always challenge</option></select>
        <select value={f.kind} onChange={(e) => setF({ ...f, kind: e.currentTarget.value })} aria-label="Match on">
          {["cidr", "ip", "asn", "country", "fp", "ua_regex", "crawler", "tor"].map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
        <input placeholder={{ cidr: "203.0.113.0/24", ip: "203.0.113.7", asn: "AS16509", country: "in", fp: "fingerprint prefix", ua_regex: "^MyMonitor/", crawler: "googlebot or *", tor: "*" }[f.kind]} value={f.value} onInput={(e) => setF({ ...f, value: e.currentTarget.value })} aria-label="Value" required />
        <input placeholder="Note" value={f.note} onInput={(e) => setF({ ...f, note: e.currentTarget.value })} aria-label="Note" />
        <button class="primary">Add</button>
      </form>
    </div>
  );
}

// ---------------- model ----------------

function Model({ site }: { site: Site }) {
  const [m, err, reload] = useLoad(() => api<ModelStatus>("GET", `/sites/${site.id}/model`), [site.id]);
  const [msg, setMsg] = useState("");
  const promote = async (on: boolean) => {
    setMsg("");
    try { await api("POST", `/sites/${site.id}/model/promote`, { on }); reload(); } catch (x: any) { setMsg(x.message); }
  };
  if (!m) return <Err msg={err} />;
  const s = m.supervised;
  return (
    <div class="grid g2">
      <div class="card">
        <h2>Anomaly model</h2>
        <p class="secondary">Learns what normal visitors to this site look like from traffic allowed at low risk, and flags vectors unlike them. Adds at most 30 points and can never block on its own.</p>
        <div class="tile"><div class="label">Observations</div><div class="value">{fmt(m.hbos_observations)}</div>
          <div class="sub">{m.hbos_active ? "Active" : `Needs ${fmt(200 - m.hbos_observations)} more before it gives an opinion`}</div></div>
      </div>
      <div class="card">
        <h2>Supervised model</h2>
        <p class="secondary">Learns from labels you give on the Events page, labels your backend reports to <code>/v1/report</code>, and weak labels from visual challenges. Each label is scored before it trains, so precision and recall are honest.</p>
        <div class="grid g2">
          <div class="tile"><div class="label">Labels</div><div class="value">{fmt(s.labels)}</div><div class="sub">{s.bots} bots, {s.humans} humans</div></div>
          <div class="tile"><div class="label">Precision / recall</div><div class="value" style={{ fontSize: "20px" }}>{s.labels ? `${Math.round(s.precision * 100)}% / ${Math.round(s.recall * 100)}%` : "–"}</div></div>
        </div>
        <Err msg={msg} />
        <div class="row" style={{ marginTop: "12px" }}>
          {s.promoted ? <button onClick={() => promote(false)}>Return to shadow</button>
            : <button class="primary" disabled={!s.ready} onClick={() => promote(true)}>Enforce supervised model</button>}
          {!s.ready && !s.promoted && <span class="muted">Needs 200 labels with at least 50 of each.</span>}
        </div>
      </div>
    </div>
  );
}

// ---------------- settings ----------------

function Settings({ site, onSaved }: { site: Site; onSaved: () => void }) {
  const [f, setF] = useState({
    name: site.name, origins: site.origins.join("\n"), mode: site.mode,
    tc: String(site.thresholds.t_challenge || 35), tb: String(site.thresholds.t_block || 75),
    acc: site.accessibility_url || "", strict: site.strict_ip,
  });
  const [msg, setMsg] = useState<{ ok: boolean; t: string } | null>(null);
  const [secret, setSecret] = useState("");
  const save = async (e: SubmitEvent) => {
    e.preventDefault();
    try {
      await api("PATCH", `/sites/${site.id}`, {
        name: f.name, origins: f.origins.split(/\s+/).filter(Boolean), mode: f.mode,
        thresholds: { t_challenge: Number(f.tc), t_block: Number(f.tb) }, accessibility_url: f.acc, strict_ip: f.strict,
      });
      setMsg({ ok: true, t: "Saved." });
      onSaved();
    } catch (x: any) { setMsg({ ok: false, t: x.message }); }
  };
  const rotate = async () => {
    if (!confirm("Rotate the secret? Your backend must switch to the new one; the old one stops working immediately.")) return;
    const r = await api<{ secret: string }>("POST", `/sites/${site.id}/rotate-secret`);
    setSecret(r.secret);
  };
  return (
    <div class="grid g2">
      <form class="card grid" onSubmit={save}>
        <h2>Site</h2>
        <label class="field">Name<input value={f.name} onInput={(e) => setF({ ...f, name: e.currentTarget.value })} /></label>
        <label class="field">Allowed origins (one per line)<textarea value={f.origins} onInput={(e) => setF({ ...f, origins: e.currentTarget.value })} /></label>
        <label class="field">Mode
          <select value={f.mode} onChange={(e) => setF({ ...f, mode: e.currentTarget.value as Site["mode"] })}>
            <option value="enforce">Enforce: challenge and block</option>
            <option value="monitor">Monitor: always allow, record what would happen</option>
            <option value="challenge_only">Challenge only: never block</option>
          </select>
        </label>
        <div class="grid g2">
          <label class="field">Challenge at risk ≥<input type="number" min={1} max={99} value={f.tc} onInput={(e) => setF({ ...f, tc: e.currentTarget.value })} /></label>
          <label class="field">Block at risk ≥<input type="number" min={2} max={100} value={f.tb} onInput={(e) => setF({ ...f, tb: e.currentTarget.value })} /></label>
        </div>
        <label class="field">Accessibility link shown in challenges (optional)<input value={f.acc} placeholder="https://example.com/contact" onInput={(e) => setF({ ...f, acc: e.currentTarget.value })} /></label>
        <label class="row"><input type="checkbox" checked={f.strict} onChange={(e) => setF({ ...f, strict: e.currentTarget.checked })} /> Reject tokens verified with a different <code>remoteip</code> /24</label>
        {msg && <div class={`notice ${msg.ok ? "ok" : "err"}`}>{msg.t}</div>}
        <div><button class="primary">Save</button></div>
      </form>
      <div class="card grid" style={{ alignContent: "start" }}>
        <h2>Keys</h2>
        <dl class="kv"><dt>Site key (public)</dt><dd><code>{site.site_key}</code></dd><dt>Site id</dt><dd><code>{site.id}</code></dd></dl>
        {secret ? <div class="notice ok"><b>New secret, shown once:</b><div class="secret" style={{ marginTop: "6px" }}>{secret}</div></div>
          : <div><button class="danger" onClick={rotate}>Rotate secret</button></div>}
      </div>
    </div>
  );
}

// ---------------- privacy & audit ----------------

function Privacy() {
  const [p, err] = useLoad(() => api<any>("GET", "/privacy"), []);
  const [ipd] = useLoad(() => api<any>("GET", "/ipdata"), []);
  if (!p) return <Err msg={err} />;
  return (
    <div class="grid">
      <div class="head"><h1>Privacy and data map</h1></div>
      <div class="card">
        <p>doorkeep stores no raw signals. Events are kept <b>{p.event_retention_days} days</b>; hourly totals are kept 13 months for charts.</p>
        <dl class="kv"><dt>Fingerprints</dt><dd>{p.pseudonymisation.fingerprint}</dd><dt>IP addresses</dt><dd>{p.pseudonymisation.ip}</dd><dt>Never collected</dt><dd>{p.never_collected.join(", ")}</dd></dl>
      </div>
      <div class="card" style={{ overflowX: "auto" }}>
        <table>
          <thead><tr><th>Data</th><th>Stored as</th><th>Purpose</th><th>Retention</th><th>GDPR</th><th>DPDP Act (India)</th></tr></thead>
          <tbody>{p.data_map.map((r: any) => <tr key={r.item}><td><b>{r.item}</b></td><td>{r.at_rest}</td><td>{r.purpose}</td><td>{r.retention}</td><td class="secondary">{r.gdpr}</td><td class="secondary">{r.dpdp}</td></tr>)}</tbody>
        </table>
      </div>
      {ipd && (
        <div class="card"><h2>IP intelligence</h2>
          <p class="secondary">{ipd.counts.v4 ? `${fmt(ipd.counts.v4)} IPv4 and ${fmt(ipd.counts.v6)} IPv6 ranges, ${fmt(ipd.counts.tor)} Tor exits, ${fmt(ipd.counts.drop)} DROP prefixes.` : "Not loaded. Run doorkeep ipdata update."}</p>
          {ipd.sources?.length > 0 && <p class="muted">Sources: {ipd.sources.join("; ")}</p>}
        </div>
      )}
    </div>
  );
}

function Audit() {
  const [a, err] = useLoad(() => api<any[]>("GET", "/audit"), []);
  return (
    <div class="grid">
      <div class="head"><h1>Audit log</h1></div>
      <Err msg={err} />
      <div class="card" style={{ padding: "8px", overflowX: "auto" }}>
        {a && a.length === 0 && <div class="empty">No changes recorded yet.</div>}
        {a && a.length > 0 && (
          <table>
            <thead><tr><th>Time</th><th>Who</th><th>Action</th><th>Target</th></tr></thead>
            <tbody>{a.map((e) => <tr key={e.id}><td class="secondary">{new Date(e.ts).toLocaleString()}</td><td>{e.actor}</td><td><code>{e.action}</code></td><td><code>{e.target}</code></td></tr>)}</tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------------- API tokens ----------------

interface AdminToken { id: string; name: string; created_at: string; expires_at?: string; last_used_at?: string }

function Tokens() {
  const [toks, err, reload] = useLoad(() => api<AdminToken[]>("GET", "/tokens"), []);
  const [name, setName] = useState("");
  const [days, setDays] = useState("90");
  const [created, setCreated] = useState<string | null>(null);
  const [formErr, setFormErr] = useState("");
  const when = (t?: string) => (t ? new Date(t).toLocaleString() : "");
  const create = async (e: SubmitEvent) => {
    e.preventDefault();
    setFormErr("");
    try {
      const r = await api<{ token: string }>("POST", "/tokens", { name, ttl_days: Number(days) });
      setCreated(r.token);
      setName("");
      reload();
    } catch (x: any) {
      setFormErr(x.message);
    }
  };
  const revoke = async (t: AdminToken) => {
    if (!confirm(`Revoke the token "${t.name}"? Anything using it stops working immediately.`)) return;
    try {
      await api("DELETE", "/tokens/" + t.id);
      reload();
    } catch (x: any) {
      setFormErr(x.message);
    }
  };
  return (
    <div class="grid">
      <div class="head"><h1>API tokens</h1></div>
      <p class="secondary" style={{ margin: 0 }}>Bearer tokens for automation against <code>/admin/v1</code> (Terraform, scripts). They act with full admin rights; give each use its own token so you can revoke it alone.</p>
      {created && (
        <div class="notice ok grid" role="status">
          <h2 style={{ margin: 0 }}>Copy the token now</h2>
          <p style={{ margin: 0 }}>It is shown once. Send it as <code>Authorization: Bearer …</code>.</p>
          <div class="secret">{created}</div>
          <div><button onClick={() => setCreated(null)}>Done</button></div>
        </div>
      )}
      <Err msg={err} />
      <div class="card" style={{ padding: "8px", overflowX: "auto" }}>
        {toks && toks.length === 0 && <div class="empty">No tokens.</div>}
        {toks && toks.length > 0 && (
          <table>
            <thead><tr><th>Name</th><th>ID</th><th>Created</th><th>Expires</th><th>Last used</th><th></th></tr></thead>
            <tbody>{toks.map((t) => {
              const expired = t.expires_at && new Date(t.expires_at) < new Date();
              return (
                <tr key={t.id}>
                  <td><b>{t.name}</b></td>
                  <td><code>{t.id}</code></td>
                  <td class="secondary">{when(t.created_at)}</td>
                  <td class="secondary">{t.expires_at ? (expired ? <span class="badge block">expired</span> : when(t.expires_at)) : "never"}</td>
                  <td class="secondary">{when(t.last_used_at) || "never"}</td>
                  <td><button class="small danger" onClick={() => revoke(t)} aria-label={`Revoke ${t.name}`}>Revoke</button></td>
                </tr>
              );
            })}</tbody>
          </table>
        )}
      </div>
      <form class="card grid" onSubmit={create} style={{ maxWidth: "620px" }}>
        <h2>New token</h2>
        <label class="field">Name<input value={name} onInput={(e) => setName(e.currentTarget.value)} placeholder="terraform" maxLength={64} required /></label>
        <label class="field">Expires after
          <select value={days} onChange={(e) => setDays(e.currentTarget.value)}>
            <option value="30">30 days</option><option value="90">90 days</option><option value="365">1 year</option><option value="0">never</option>
          </select>
        </label>
        <Err msg={formErr} />
        <div><button class="primary">Create token</button></div>
      </form>
    </div>
  );
}

// ---------------- app ----------------

function App() {
  const [actor, setActor] = useState<string | null | undefined>(undefined);
  const route = useRoute();
  const [sites, , reloadSites] = useLoad(() => (actor ? api<Site[]>("GET", "/sites") : Promise.resolve([] as Site[])), [actor]);
  useEffect(() => { me().then(setActor); }, []);
  if (actor === undefined) return null;
  if (!actor) return <Login onDone={() => me().then(setActor)} />;
  const list = sites || [];
  let body: any;
  if (route[0] === "privacy") body = <Privacy />;
  else if (route[0] === "audit") body = <Audit />;
  else if (route[0] === "tokens") body = <Tokens />;
  else if (route[0] === "sites" && route[1]) {
    const s = list.find((x) => x.id === route[1]);
    const tab = (route[2] || "overview").split("?")[0];
    body = s ? <SitePage key={s.id + tab} site={s} tab={tab} sub={route[3]} reloadSites={reloadSites} /> : sites ? <div class="empty">Unknown site.</div> : null;
  } else body = <SiteList sites={list} reload={reloadSites} />;
  return <Shell actor={actor} route={route} sites={list} onLogout={() => logout().then(() => setActor(null))}>{body}</Shell>;
}

try {
  const t = localStorage.getItem("dk-theme");
  if (t) document.documentElement.dataset.theme = t;
} catch {}
render(<App />, document.getElementById("app")!);
