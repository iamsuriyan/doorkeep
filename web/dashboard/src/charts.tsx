// Small SVG charts following the dataviz method: outcomes are states and use
// the status palette (always beside text labels and a legend); magnitudes use
// a single series hue; 2px surface gaps between stacked segments; hairline
// grid; hover tooltips; one axis.
import { useState } from "preact/hooks";
import { fmt } from "./api";

const OUTCOMES = [
  { key: "allow", label: "Allowed", color: "var(--good)" },
  { key: "challenge", label: "Challenged", color: "var(--warning)" },
  { key: "block", label: "Blocked", color: "var(--critical)" },
] as const;

export function OutcomeLegend() {
  return (
    <div class="legend" aria-hidden="true">
      {OUTCOMES.map((o) => (
        <span key={o.key}><i class="dot" style={{ background: o.color }} />{o.label}</span>
      ))}
    </div>
  );
}

function niceMax(v: number): number {
  if (v <= 4) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
}

interface Point { hour: string; allow: number; challenge: number; block: number }

/** Stacked hourly outcome bars with a per-column hover tooltip. */
export function OutcomeChart({ series }: { series: Point[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 760, H = 220, L = 40, R = 8, T = 8, B = 24;
  const max = niceMax(Math.max(1, ...series.map((p) => p.allow + p.challenge + p.block)));
  const n = series.length;
  const step = (W - L - R) / Math.max(1, n);
  const bw = Math.max(2, step - 2); // 2px surface gap between adjacent bars
  const y = (v: number) => T + (H - T - B) * (1 - v / max);
  const ticks = [0, max / 2, max];
  const label = (iso: string) => {
    const d = new Date(iso);
    return n > 48 ? `${d.getMonth() + 1}/${d.getDate()}` : `${String(d.getHours()).padStart(2, "0")}:00`;
  };
  const every = Math.ceil(n / 8);
  const hp = hover !== null ? series[hover] : null;
  return (
    <div class="chart" onMouseLeave={() => setHover(null)}>
      <OutcomeLegend />
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Requests per hour by outcome">
        {ticks.map((t) => (
          <g key={t} class="axis">
            <line class="gridline" x1={L} x2={W - R} y1={y(t)} y2={y(t)} />
            <text x={L - 6} y={y(t) + 4} text-anchor="end">{fmt(Math.round(t))}</text>
          </g>
        ))}
        {series.map((p, i) => {
          const x = L + i * step + (step - bw) / 2;
          let acc = 0;
          const segs = OUTCOMES.map((o) => {
            const v = p[o.key];
            if (!v) return null;
            const y0 = y(acc), y1 = y(acc + v);
            acc += v;
            const h = Math.max(1, y0 - y1 - 2); // 2px gap above each segment
            return <rect key={o.key} class="bar-seg" x={x} y={y1} width={bw} height={h} rx={bw > 6 ? 2 : 0} fill={o.color} />;
          });
          return (
            <g key={p.hour} onMouseEnter={() => setHover(i)}>
              <rect x={L + i * step} y={T} width={step} height={H - T - B} fill="transparent" />
              {hover === i && <rect x={L + i * step} y={T} width={step} height={H - T - B} fill="var(--surface-2)" />}
              {segs}
              {i % every === 0 && <text class="axis" x={x + bw / 2} y={H - 6} text-anchor="middle">{label(p.hour)}</text>}
            </g>
          );
        })}
      </svg>
      {hp && (
        <div class="tip" style={{ left: `${((L + (hover! + 0.5) * step) / W) * 100}%`, top: "28px", transform: "translateX(-50%)" }}>
          <div class="t">{new Date(hp.hour).toLocaleString()}</div>
          {OUTCOMES.map((o) => (
            <div key={o.key} class="row" style={{ gap: "6px" }}><i class="dot" style={{ background: o.color }} />{o.label}: <b>{fmt(hp[o.key])}</b></div>
          ))}
        </div>
      )}
      <table class="sr-only">
        <caption>Requests per hour by outcome</caption>
        <thead><tr><th>Hour</th><th>Allowed</th><th>Challenged</th><th>Blocked</th></tr></thead>
        <tbody>{series.filter((p) => p.allow + p.challenge + p.block > 0).map((p) => <tr key={p.hour}><td>{p.hour}</td><td>{p.allow}</td><td>{p.challenge}</td><td>{p.block}</td></tr>)}</tbody>
      </table>
    </div>
  );
}

/** Risk score distribution: 20 buckets of 5 points, single hue, with the
 * site's thresholds marked. */
export function RiskHistogram({ hist, challenge, block }: { hist: number[]; challenge: number; block: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 360, H = 160, L = 8, R = 8, T = 18, B = 22;
  const max = Math.max(1, ...hist);
  const step = (W - L - R) / 20;
  const bw = step - 2;
  const x = (risk: number) => L + (risk / 100) * (W - L - R);
  return (
    <div class="chart" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Distribution of risk scores">
        <line class="gridline" x1={L} x2={W - R} y1={H - B} y2={H - B} />
        {hist.map((v, i) => {
          const h = ((H - T - B) * v) / max;
          return (
            <g key={i} onMouseEnter={() => setHover(i)}>
              <rect x={L + i * step} y={T} width={step} height={H - T - B} fill="transparent" />
              {v > 0 && <rect x={L + i * step + 1} y={H - B - h} width={bw} height={Math.max(1, h)} rx={2} fill="var(--series-1)" opacity={hover === null || hover === i ? 1 : 0.55} />}
            </g>
          );
        })}
        {[{ v: challenge, t: "challenge" }, { v: block, t: "block" }].map((m) => (
          <g key={m.t}>
            <line x1={x(m.v)} x2={x(m.v)} y1={T - 4} y2={H - B} stroke="var(--text-muted)" stroke-width="1" />
            <text class="axis" x={x(m.v) + 3} y={T - 6}>{m.t} {m.v}</text>
          </g>
        ))}
        {[0, 25, 50, 75, 100].map((t) => <text key={t} class="axis" x={x(t)} y={H - 6} text-anchor="middle">{t}</text>)}
      </svg>
      {hover !== null && (
        <div class="tip" style={{ left: `${((L + (hover + 0.5) * step) / W) * 100}%`, top: "4px", transform: "translateX(-50%)" }}>
          <div class="t">Risk {hover * 5} to {hover * 5 + 4}</div>
          <b>{fmt(hist[hover])}</b> events
        </div>
      )}
    </div>
  );
}

/** Ranked horizontal bars with the value as text (single series). */
export function RankBars({ items, total, render }: { items: Array<{ key: string; count: number }>; total?: number; render?: (k: string) => any }) {
  if (!items.length) return <div class="empty">No data in this range</div>;
  const max = Math.max(...items.map((i) => i.count));
  return (
    <div>
      {items.map((i) => (
        <div class="hbar" key={i.key} title={`${i.key}: ${fmt(i.count)}${total ? ` (${Math.round((i.count / total) * 100)}%)` : ""}`}>
          <span class="name">{render ? render(i.key) : i.key}</span>
          <span><span class="bar" style={{ display: "block", width: `${(i.count / max) * 100}%` }} /></span>
          <span class="num secondary">{fmt(i.count)}</span>
        </div>
      ))}
    </div>
  );
}
