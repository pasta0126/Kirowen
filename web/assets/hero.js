// Animated illustration of the log on the landing page (canvas 2D, no
// dependencies). It shows the mechanism, not real data:
// - events are appended to one sequence and hashed into a Merkle tree;
// - each new leaf lights up its inclusion proof (its path and siblings);
// - a checkpoint leaf takes its own position after every EVERY events
//   (1,000 in the real log);
// - signed tree heads travel to witnesses, which cosign them;
// - full blocks of leaves are kept as tiles.
"use strict";

(() => {
  const canvas = document.getElementById("logviz");
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext("2d");
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");

  const SLOTS = 16;          // leaves per drawn tree (a tile has 256)
  const LEVELS = 4;          // log2(SLOTS)
  const EVERY = 8;           // events per checkpoint (1,000 in the real log)
  const STEP = 1100;         // ms between leaves (~1 s batching)
  const STH_EVERY = 3;       // leaves between published tree heads
  const N_WITNESS = 3;

  let W = 0, H = 0;
  const C = {};
  let leaves = [], nodes = new Map(), seq = 0, events = 0, tiles = 0;
  let highlight = null, collapse = null, lastAdd = -Infinity;
  let sth = { size: 0, t: -Infinity };
  let particles = [], timers = [];
  const witnesses = Array.from({ length: N_WITNESS }, () => ({ t: -Infinity }));
  let ticker = "";
  let running = false, raf = 0;

  // --- helpers ---
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const easeOut = p => 1 - Math.pow(1 - clamp(p, 0, 1), 3);
  const easeBack = p => { p = clamp(p, 0, 1); const c = 1.7; return 1 + (c + 1) * Math.pow(p - 1, 3) + c * Math.pow(p - 1, 2); };
  const randHex = n => Array.from(crypto.getRandomValues(new Uint8Array(n)), b => b.toString(16).padStart(2, "0")).join("");

  function readColors() {
    const cs = getComputedStyle(document.documentElement);
    for (const k of ["text", "muted", "line", "surface", "hash", "checkpoint", "witness", "ok"]) {
      C[k] = cs.getPropertyValue("--" + k).trim() || "#888";
    }
  }

  function resize() {
    const r = canvas.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = r.width; H = r.height;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function rrect(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  // --- layout ---
  function layout() {
    const wide = W >= 620;
    const pad = 16;
    const side = wide ? 96 : 0;
    const x0 = pad + side, x1 = W - pad - side;
    const top = wide ? 70 : 78, leafY = H - 58;
    const slotW = (x1 - x0) / SLOTS;
    return {
      wide, pad, side, x0, x1, top, leafY, slotW,
      leafS: clamp(slotW * 0.6, 8, 20),
      levelY: l => leafY - l * ((leafY - top) / LEVELS),
      nodeX: (l, j) => x0 + (j * (1 << l) + (1 << l) / 2) * slotW,
      badge: wide ? { x: (x0 + x1) / 2, y: 28 } : { x: pad + 92, y: 28 },
      witness: k => wide
        ? { x: W - pad - side / 2, y: top + 10 + k * ((leafY - top - 20) / (N_WITNESS - 1)) }
        : { x: W - pad - 12 - (N_WITNESS - 1 - k) * 30, y: 28 },
      tileSlot: k => ({ x: pad + side / 2, y: leafY - 6 - k * 30 }),
    };
  }

  // --- simulation ---
  function at(t, fn) { timers.push({ t, fn }); }

  function addLeaf(now) {
    let kind = "event";
    if (events === EVERY) { kind = "checkpoint"; events = 0; } else { events++; }
    const i = leaves.length;
    const hash = randHex(32);
    leaves.push({ kind, born: now });
    for (let l = 1; l <= LEVELS; l++) {
      if ((i + 1) % (1 << l) === 0) nodes.set(l + ":" + (i >> l), now + l * 110);
    }
    highlight = { i, t: now };
    ticker = "leaf " + seq + " · " + (kind === "checkpoint" ? "checkpoint" : "event") + " · " + hash.slice(0, 10) + "…" + hash.slice(-6);
    seq++;
    if (seq % STH_EVERY === 0) at(now + 450, t => publish(t));
    if (leaves.length === SLOTS) collapse = { t: now + 1300 };
    lastAdd = now;
  }

  function publish(now) {
    sth = { size: seq, t: now };
    const L = layout();
    for (let k = 0; k < N_WITNESS; k++) {
      const dur = 650 + k * 120;
      particles.push({ from: L.badge, k, t: now, dur });
      at(now + dur, t => { witnesses[k].t = t; });
    }
  }

  function step(now) {
    timers = timers.filter(x => (x.t <= now ? (x.fn(x.t), false) : true));
    if (collapse && now >= collapse.t + 900) {
      tiles++; leaves = []; nodes.clear(); highlight = null; collapse = null; lastAdd = now;
    }
    if (!collapse && now - lastAdd >= STEP) addLeaf(now);
    particles = particles.filter(p => now - p.t < p.dur);
  }

  // --- drawing ---
  function onPath(l, j) {
    return highlight && (highlight.i >> l) === j;
  }

  function draw(now) {
    const L = layout();
    ctx.clearRect(0, 0, W, H);
    const fade = collapse ? 1 - easeOut((now - collapse.t) / 700) : 1;
    const hl = highlight ? clamp(1 - (now - highlight.t) / 1600, 0, 1) : 0;

    // Empty slots.
    ctx.save();
    ctx.globalAlpha = 0.5;
    ctx.strokeStyle = C.line;
    ctx.setLineDash([3, 3]);
    for (let i = 0; i < SLOTS; i++) {
      const x = L.nodeX(0, i) - L.leafS / 2;
      rrect(x, L.leafY - L.leafS / 2, L.leafS, L.leafS, 4);
      ctx.stroke();
    }
    ctx.restore();

    ctx.save();
    ctx.globalAlpha = fade;

    // Edges.
    for (const [key, born] of nodes) {
      if (now < born) continue;
      const [l, j] = key.split(":").map(Number);
      const p = easeOut((now - born) / 350);
      const x = L.nodeX(l, j), y = L.levelY(l);
      for (const c of [2 * j, 2 * j + 1]) {
        const cx = L.nodeX(l - 1, c), cy = L.levelY(l - 1) - (l === 1 ? L.leafS / 2 : 0);
        const lit = hl > 0 && onPath(l, j) && onPath(l - 1, c);
        ctx.strokeStyle = lit ? C.ok : C.line;
        ctx.globalAlpha = fade * (lit ? 0.35 + 0.65 * hl : 0.9);
        ctx.lineWidth = lit ? 2 : 1;
        ctx.beginPath();
        ctx.moveTo(x, y);
        ctx.lineTo(x + (cx - x) * p, y + (cy - y) * p);
        ctx.stroke();
      }
    }

    // Nodes.
    for (const [key, born] of nodes) {
      if (now < born) continue;
      const [l, j] = key.split(":").map(Number);
      const s = easeBack((now - born) / 380);
      const x = L.nodeX(l, j), y = L.levelY(l), r = (3.5 + l * 1.3) * s;
      const lit = hl > 0 && onPath(l, j);
      const sib = hl > 0 && highlight && ((highlight.i >> l) ^ 1) === j;
      ctx.globalAlpha = fade;
      ctx.fillStyle = C.surface;
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
      ctx.lineWidth = lit || sib ? 2 : 1.25;
      ctx.strokeStyle = lit ? C.ok : sib ? C.hash : C.muted;
      if (lit) { ctx.shadowColor = C.ok; ctx.shadowBlur = 12 * hl; }
      ctx.stroke();
      ctx.shadowBlur = 0;
      if (l === LEVELS) {
        ctx.fillStyle = C.ok; ctx.globalAlpha = fade * 0.9;
        ctx.beginPath(); ctx.arc(x, y, r * 0.45, 0, Math.PI * 2); ctx.fill();
      }
    }

    // Leaves.
    leaves.forEach((lf, i) => {
      const p = easeBack((now - lf.born) / 480);
      const s = L.leafS, x = L.nodeX(0, i) - s / 2;
      const y = L.leafY - s / 2 - (1 - p) * 34;
      const color = lf.kind === "checkpoint" ? C.checkpoint : C.hash;
      const isNew = highlight && highlight.i === i && hl > 0;
      const isSib = highlight && hl > 0 && (highlight.i ^ 1) === i;
      ctx.globalAlpha = fade * clamp(p * 1.4, 0, 1);
      ctx.fillStyle = color;
      if (isNew) { ctx.shadowColor = color; ctx.shadowBlur = 18 * hl; }
      rrect(x, y, s, s, 4); ctx.fill();
      ctx.shadowBlur = 0;
      if (isSib) {
        ctx.strokeStyle = C.hash; ctx.lineWidth = 2; ctx.globalAlpha = fade * hl;
        rrect(x - 3, y - 3, s + 6, s + 6, 6); ctx.stroke();
      }
    });
    ctx.restore();

    // Tile flying to the archive.
    if (collapse && now >= collapse.t) {
      const p = easeOut((now - collapse.t) / 900);
      const from = { x: L.nodeX(LEVELS, 0), y: L.levelY(LEVELS) };
      const to = L.wide ? L.tileSlot(Math.min(tiles, 3)) : { x: from.x, y: from.y - 40 };
      const x = from.x + (to.x - from.x) * p, y = from.y + (to.y - from.y) * p;
      ctx.save();
      ctx.globalAlpha = L.wide ? 1 : 1 - p;
      ctx.fillStyle = C.ok; ctx.shadowColor = C.ok; ctx.shadowBlur = 14;
      rrect(x - 11, y - 11, 22, 22, 5); ctx.fill();
      ctx.restore();
    }

    // Tile archive.
    if (L.wide) {
      ctx.save();
      ctx.font = "600 10px ui-monospace, SFMono-Regular, Menlo, monospace";
      ctx.textAlign = "center";
      ctx.fillStyle = C.muted;
      ctx.fillText("TILES", L.pad + L.side / 2, L.top - 10);
      const shown = Math.min(tiles, 4);
      for (let k = 0; k < shown; k++) {
        const s = L.tileSlot(k);
        ctx.globalAlpha = 1 - k * 0.18;
        ctx.strokeStyle = C.ok; ctx.lineWidth = 1.5;
        rrect(s.x - 11, s.y - 11, 22, 22, 5); ctx.stroke();
        ctx.globalAlpha *= 0.25; ctx.fillStyle = C.ok; ctx.fill();
      }
      ctx.globalAlpha = 1;
      ctx.fillStyle = C.text;
      ctx.fillText(String(tiles), L.pad + L.side / 2, L.top + 6);
      ctx.restore();
    }

    // Signed tree head badge.
    {
      const b = L.badge, age = now - sth.t, pulse = clamp(1 - age / 900, 0, 1);
      const label = "signed tree head · size " + sth.size;
      ctx.save();
      ctx.font = "600 11px ui-monospace, SFMono-Regular, Menlo, monospace";
      const w = ctx.measureText(label).width + 26;
      ctx.fillStyle = C.surface;
      ctx.strokeStyle = pulse > 0 ? C.witness : C.line;
      ctx.lineWidth = 1 + pulse;
      if (pulse > 0) { ctx.shadowColor = C.witness; ctx.shadowBlur = 16 * pulse; }
      rrect(b.x - w / 2, b.y - 13, w, 26, 13); ctx.fill(); ctx.stroke();
      ctx.shadowBlur = 0;
      ctx.fillStyle = C.text; ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.fillText(label, b.x, b.y + 0.5);
      ctx.restore();
    }

    // Tree heads travelling to witnesses.
    for (const p of particles) {
      const w = L.witness(p.k), q = easeOut((now - p.t) / p.dur);
      const mx = (p.from.x + w.x) / 2, my = Math.min(p.from.y, w.y) - 30;
      const x = (1 - q) * (1 - q) * p.from.x + 2 * (1 - q) * q * mx + q * q * w.x;
      const y = (1 - q) * (1 - q) * p.from.y + 2 * (1 - q) * q * my + q * q * w.y;
      ctx.save();
      ctx.fillStyle = C.witness; ctx.shadowColor = C.witness; ctx.shadowBlur = 10;
      ctx.beginPath(); ctx.arc(x, y, 3.2, 0, Math.PI * 2); ctx.fill();
      ctx.restore();
    }

    // Witnesses.
    for (let k = 0; k < N_WITNESS; k++) {
      const w = L.witness(k), age = now - witnesses[k].t, f = clamp(1 - age / 1200, 0, 1);
      const r = L.wide ? 13 : 10;
      ctx.save();
      if (f > 0) {
        ctx.strokeStyle = C.witness; ctx.globalAlpha = f * 0.6; ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.arc(w.x, w.y, r + (1 - f) * 16, 0, Math.PI * 2); ctx.stroke();
      }
      ctx.globalAlpha = 1;
      ctx.fillStyle = C.surface; ctx.strokeStyle = f > 0 ? C.witness : C.line; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(w.x, w.y, r, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
      // Cosignature tick.
      ctx.strokeStyle = C.witness; ctx.globalAlpha = 0.35 + 0.65 * f; ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(w.x - r * 0.38, w.y + 0.5);
      ctx.lineTo(w.x - r * 0.08, w.y + r * 0.32);
      ctx.lineTo(w.x + r * 0.42, w.y - r * 0.3);
      ctx.stroke();
      ctx.restore();
    }
    if (L.wide) {
      ctx.save();
      ctx.font = "600 10px ui-monospace, SFMono-Regular, Menlo, monospace";
      ctx.textAlign = "center"; ctx.fillStyle = C.muted;
      ctx.fillText("WITNESSES", W - L.pad - L.side / 2, L.top - 10);
      ctx.restore();
    }

    // Ticker.
    ctx.save();
    ctx.font = "12px ui-monospace, SFMono-Regular, Menlo, monospace";
    ctx.fillStyle = C.muted; ctx.textAlign = "center";
    ctx.fillText(ticker, (L.x0 + L.x1) / 2, H - 20);
    ctx.restore();
  }

  // --- loop ---
  function frame(now) {
    step(now);
    draw(now);
    if (running) raf = requestAnimationFrame(frame);
  }

  function start() {
    if (running || reduce.matches) return;
    running = true;
    const now = performance.now();
    lastAdd = Math.max(lastAdd, now - STEP + 300);
    raf = requestAnimationFrame(frame);
  }

  function stop() {
    running = false;
    cancelAnimationFrame(raf);
  }

  // Static picture for reduced motion: a tree part-way through, settled.
  function still() {
    stop();
    leaves = []; nodes.clear(); seq = 0; events = 0; tiles = 2; timers = []; particles = [];
    for (let i = 0; i < 11; i++) addLeaf(-1e6 + i);
    timers = []; highlight = { i: 10, t: -1e6 }; sth = { size: seq, t: -1e6 };
    draw(0);
  }

  let visible = true;
  const sync = () => {
    if (reduce.matches) { still(); return; }
    if (visible && !document.hidden) start(); else stop();
  };

  readColors();
  resize();
  new ResizeObserver(() => { resize(); if (!running) (reduce.matches ? still() : draw(performance.now())); }).observe(canvas);
  new IntersectionObserver(es => { visible = es[0].isIntersecting; sync(); }).observe(canvas);
  document.addEventListener("visibilitychange", sync);
  reduce.addEventListener("change", sync);
  const recolor = () => { readColors(); if (!running) (reduce.matches ? still() : draw(performance.now())); };
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", recolor);
  new MutationObserver(recolor).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  sync();
})();
