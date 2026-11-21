// Landing page: scroll reveal and the live state of the public log.
"use strict";

document.documentElement.classList.add("js");

document.addEventListener("DOMContentLoaded", () => {
  // Reveal sections as they scroll into view.
  const items = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(es => {
      for (const e of es) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
    }, { rootMargin: "0px 0px -8% 0px" });
    items.forEach(el => io.observe(el));
  } else {
    items.forEach(el => el.classList.add("in"));
  }

  // Live checkpoint: tree size and root hash, read from the public log.
  const bar = document.getElementById("live");
  if (!bar) return;
  const sizeEl = document.getElementById("live-size");
  const rootEl = document.getElementById("live-root");
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let shown = 0;

  function countTo(n) {
    if (reduce || shown === 0) { shown = n; sizeEl.textContent = n.toLocaleString("en"); return; }
    const from = shown, t0 = performance.now();
    const tick = t => {
      const p = Math.min(1, (t - t0) / 700);
      sizeEl.textContent = Math.round(from + (n - from) * (1 - Math.pow(1 - p, 3))).toLocaleString("en");
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
    shown = n;
  }

  // Latest leaves: the last LATEST leaves, read from the public tiles
  // (docs/explorer-v0.md §2). Display only; the explorer verifies.
  const LATEST = 5;
  const strip = document.getElementById("latest");
  const list = document.getElementById("latest-list");
  const cards = new Map(); // leaf index -> <li>
  let latestSize = -1;

  function card(i, l) {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = "/explorer/?leaf=" + i;
    a.className = "leafcard " + (l ? l.type : "unknown");
    const top = document.createElement("span");
    top.className = "lc-type";
    const sw = document.createElement("i");
    sw.className = "sw " + (l && l.type === "checkpoint" ? "checkpoint" : "hash");
    top.append(sw, l ? l.type : "unreadable");
    const pos = document.createElement("strong");
    pos.textContent = "#" + i.toLocaleString("en");
    const detail = document.createElement("code");
    if (l && l.type === "event") {
      detail.textContent = l.envelopeHash.slice(0, 10) + "…" + l.envelopeHash.slice(-6);
      detail.title = "envelope hash " + l.envelopeHash;
    } else if (l) {
      detail.textContent = "certifies size " + l.size.toLocaleString("en");
    }
    a.append(top, pos, detail);
    a.setAttribute("aria-label", "Leaf " + i + ", " + (l ? l.type : "unreadable") + ". Open in the explorer.");
    li.append(a);
    return li;
  }

  async function updateLatest(size) {
    if (!strip || size === latestSize) return;
    const from = Math.max(0, size - LATEST);
    const raw = size > from ? await KLog.leaves(from, size, size) : [];
    if (size < latestSize) { cards.forEach(li => li.remove()); cards.clear(); } // the log was reset
    const first = latestSize < 0;
    latestSize = size;
    strip.hidden = false;
    strip.classList.toggle("empty", size === 0);
    for (let k = 0; k < raw.length; k++) {
      const i = from + k;
      if (cards.has(i)) continue;
      let l = null;
      try { l = KLog.parseLeaf(raw[k]); } catch (_) { /* shown as unreadable */ }
      const li = card(i, l);
      if (!first && !reduce) li.classList.add("enter");
      list.prepend(li);
      cards.set(i, li);
    }
    for (const [i, li] of cards) {
      if (i >= from) continue;
      cards.delete(i);
      if (reduce) { li.remove(); continue; }
      li.classList.add("leave");
      li.addEventListener("animationend", () => li.remove(), { once: true });
      setTimeout(() => li.remove(), 800);
    }
  }

  async function refresh() {
    let size;
    try {
      const cp = await KLog.checkpoint();
      if (cp.origin !== KLog.ORIGIN) throw new Error("bad origin");
      size = Number(cp.size);
      const root = KLog.hex(cp.root);
      if (size !== shown && shown !== 0) { bar.classList.remove("bump"); void bar.offsetWidth; bar.classList.add("bump"); }
      countTo(size);
      rootEl.textContent = root.slice(0, 16) + "…";
      rootEl.title = root;
      bar.hidden = false;
    } catch (_) {
      bar.hidden = true;
      if (strip) strip.hidden = true;
      return;
    }
    try {
      await updateLatest(size);
    } catch (_) {
      if (strip) strip.hidden = true;
      latestSize = -1;
    }
  }

  refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 15000);
});
