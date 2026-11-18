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

  async function refresh() {
    try {
      const res = await fetch("/log/v0/checkpoint", { cache: "no-store" });
      if (!res.ok) throw new Error(res.status);
      const lines = (await res.text()).split("\n");
      const size = parseInt(lines[1], 10);
      const root = Array.from(atob(lines[2]), c => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
      if (!Number.isFinite(size) || root.length !== 64) throw new Error("bad checkpoint");
      if (size !== shown && shown !== 0) { bar.classList.remove("bump"); void bar.offsetWidth; bar.classList.add("bump"); }
      countTo(size);
      rootEl.textContent = root.slice(0, 16) + "…";
      rootEl.title = root;
      bar.hidden = false;
    } catch (_) {
      bar.hidden = true;
    }
  }

  refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 15000);
});
