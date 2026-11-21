// Explorer: look up one leaf and verify it in the browser (docs/explorer-v0.md §3).
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const $ = id => document.getElementById(id);
  const fmt = n => BigInt(n).toLocaleString("en");
  let current = null; // index shown
  let size = null;    // tree size from the last checkpoint read
  let seq = 0;        // discards stale lookups

  function status(msg, isError) {
    $("ex-status").textContent = msg;
    $("ex-status").classList.toggle("error", !!isError);
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function field(dl, name, value, opts = {}) {
    const dd = el("dd");
    if (opts.href) {
      const a = el("a", "", value);
      a.href = opts.href;
      dd.append(a);
    } else if (opts.code) {
      dd.append(el("code", "", value));
    } else {
      dd.textContent = value;
    }
    dl.append(el("dt", "", name), dd);
  }

  // result: true (passed), false (failed) or null (not checked).
  function check(name, result, why) {
    const li = el("li", result === true ? "pass" : result === false ? "fail" : "skip");
    li.append(el("span", "mark", result === true ? "✓" : result === false ? "✗" : "–"), el("strong", "", name));
    if (why) li.append(el("span", "why", why));
    $("ex-checks").append(li);
    return result;
  }

  function sigWhy(v) {
    if (v.ok === null) return "this browser cannot verify Ed25519 signatures";
    return v.ok ? "signed by the published log key" : "no valid signature from the log key";
  }

  function updateNav() {
    $("ex-prev").disabled = current === null || current === 0;
    $("ex-next").disabled = current === null || size === null || current + 1 >= size;
  }

  function setURL(params, push) {
    const q = new URLSearchParams(params).toString();
    const url = location.pathname + (q ? "?" + q : "");
    if (push) history.pushState(params, "", url); else history.replaceState(params, "", url);
  }

  // show looks up {leaf: n}, {hash: hex} or {} (latest).
  async function show(target) {
    const my = ++seq;
    status("Loading…");
    try {
      const cp = await KLog.checkpoint();
      if (my !== seq) return;
      size = Number(cp.size);

      let index;
      if (target.hash !== undefined) {
        let ev;
        try {
          ev = await KLog.api("/v0/events/" + target.hash);
        } catch (e) {
          if (e.status === 404) throw new Error("No event with this envelope hash is known to the registry.");
          if (e.status === 409) throw new Error("This event is still being sequenced. Try again in a second.");
          throw e;
        }
        index = ev.leaf_index;
      } else if (target.leaf !== undefined) {
        index = target.leaf;
      } else {
        if (size === 0) { status("The log is empty."); $("ex-result").hidden = true; current = null; updateNav(); return; }
        index = size - 1;
      }
      if (index >= size) {
        throw new Error("No leaf " + fmt(index) + " yet: the published tree has " + fmt(size) + " leaves.");
      }
      if (my !== seq) return;
      await render(index, target.hash, my);
    } catch (e) {
      if (my !== seq) return;
      status(e.message || String(e), true);
    }
  }

  async function render(index, wantHash, my) {
    const [raw] = await KLog.leaves(index, index + 1, size);
    let fromAPI = null, apiErr = null;
    try { fromAPI = await KLog.api("/v0/leaves/" + index); } catch (e) { apiErr = e; }
    if (my !== seq) return;

    current = index;
    updateNav();
    for (const id of ["ex-fields", "ex-checks", "ex-proof", "ex-path"]) $(id).replaceChildren();
    $("ex-treehead").textContent = "";
    $("ex-index").textContent = "#" + fmt(index);
    $("ex-q").value = wantHash || String(index);

    const fields = $("ex-fields");
    field(fields, "Position", fmt(index));

    // Leaf format.
    let leaf = null;
    try { leaf = KLog.parseLeaf(raw); } catch (e) { /* reported below */ }
    const chip = $("ex-chip");
    chip.className = "chip " + (leaf ? leaf.type : "unknown");
    chip.textContent = leaf ? leaf.type : "unreadable";
    field(fields, "Type", leaf ? (leaf.type === "event" ? "event (ordinary)" : "checkpoint (not ordinary)") : "unreadable");
    const lh = await KLog.leafHash(raw);
    if (leaf && leaf.type === "event") {
      field(fields, "Envelope hash", leaf.envelopeHash, { code: true });
    }
    if (leaf && leaf.type === "checkpoint") {
      field(fields, "Certifies tree size", fmt(leaf.size));
      field(fields, "Certified root", leaf.root, { code: true });
      if (leaf.prevSize > 0n) {
        field(fields, "Previous checkpoint", "leaf #" + fmt(leaf.prevSize) + " (size " + fmt(leaf.prevSize) + ")", { href: "?leaf=" + leaf.prevSize });
      } else {
        field(fields, "Previous checkpoint", "none (this is the first)");
      }
    }
    field(fields, "Leaf hash", KLog.hex(lh), { code: true });
    $("ex-private").hidden = !(leaf && leaf.type === "event");

    // Checks against the tree head from the API.
    if (fromAPI) {
      let th = null;
      try { th = KLog.parseCheckpoint(fromAPI.tree_head); } catch (_) { /* reported below */ }
      if (th) {
        const v = await KLog.verifyNote(th);
        check("Tree head signature", v.ok, sigWhy(v));
        check("Tree head origin", th.origin === KLog.ORIGIN, th.origin);
      } else {
        check("Tree head signature", false, "the tree head is not a valid checkpoint");
      }
      const apiLeaf = KLog.fromB64(fromAPI.leaf);
      check("Same leaf", KLog.equal(apiLeaf, raw), KLog.equal(apiLeaf, raw) ?
        "the API returned the same bytes as the public tiles" : "the API and the public tiles disagree");
      if (th) {
        const proof = fromAPI.inclusion_proof.map(KLog.fromB64);
        const ok = await KLog.verifyInclusion(index, th.size, lh, proof, th.root);
        check("Inclusion", ok, ok ? "the proof leads from this leaf to the root of a tree of " + fmt(th.size) + " leaves"
          : "the proof does not reproduce the tree head root");
        field($("ex-proof"), "Tree size", fmt(th.size));
        field($("ex-proof"), "Root", KLog.hex(th.root), { code: true });
        field($("ex-proof"), "Proof length", proof.length + " hashes");
        $("ex-treehead").textContent = fromAPI.tree_head;
        for (const p of proof) $("ex-path").append(el("li", "", KLog.hex(p)));
      }
    } else {
      check("Tree head and inclusion", null, "the API did not answer (" + (apiErr && apiErr.message) + ")");
    }

    check("Leaf format", !!leaf, leaf ? "decodes as [1, type, body] with a valid body" : "the leaf does not decode");
    if (wantHash !== undefined) {
      const ok = !!leaf && leaf.type === "event" && leaf.envelopeHash === wantHash;
      check("Envelope hash", ok, ok ? "this leaf holds the hash you looked up" : "this leaf does not hold the hash you looked up");
    }

    // Checkpoint leaf: the body and its embedded note agree, and the note is signed.
    $("ex-note-box").hidden = true;
    if (leaf && leaf.type === "checkpoint") {
      check("Checkpoint position", leaf.size === BigInt(index),
        "certifies the " + fmt(leaf.size) + " leaves before it");
      $("ex-note").textContent = leaf.note;
      $("ex-note-box").hidden = false;
      let n = null;
      try { n = KLog.parseCheckpoint(leaf.note); } catch (_) { /* reported below */ }
      if (!n) {
        check("Checkpoint note", false, "the embedded note is not a valid checkpoint");
      } else {
        const v = await KLog.verifyNote(n);
        check("Checkpoint note signature", v.ok, sigWhy(v));
        const agrees = n.origin === KLog.ORIGIN && n.size === leaf.size && KLog.hex(n.root) === leaf.root;
        check("Checkpoint note matches", agrees, agrees ? "same origin, size and root as the leaf body" : "the note and the leaf body disagree");
        if (v.others.length) check("Other signers", null, v.others.join(", ") + " (not verified)");
      }
    }

    $("ex-result").hidden = false;
    status("");
  }

  function parseQuery(q) {
    q = q.trim();
    if (/^\d+$/.test(q)) return { leaf: Number(q) };
    if (/^[0-9a-fA-F]{64}$/.test(q)) return { hash: q.toLowerCase() };
    return null;
  }

  function go(target, push = true) {
    const params = target.leaf !== undefined ? { leaf: String(target.leaf) } : target.hash !== undefined ? { hash: target.hash } : {};
    setURL(params, push);
    show(target);
  }

  $("ex-form").addEventListener("submit", e => {
    e.preventDefault();
    const t = parseQuery($("ex-q").value);
    if (!t) { status("Enter a leaf position (a number) or an envelope hash (64 hex digits).", true); return; }
    go(t);
  });
  $("ex-prev").addEventListener("click", () => { if (current > 0) go({ leaf: current - 1 }); });
  $("ex-next").addEventListener("click", () => { if (current !== null) go({ leaf: current + 1 }); });
  $("ex-latest").addEventListener("click", () => go({}));
  window.addEventListener("popstate", () => fromURL());

  function fromURL() {
    const p = new URLSearchParams(location.search);
    const t = p.has("leaf") ? parseQuery(p.get("leaf")) : p.has("hash") ? parseQuery(p.get("hash")) : {};
    if (!t || (p.has("leaf") && t.leaf === undefined) || (p.has("hash") && t.hash === undefined)) {
      status("The link does not name a valid leaf position or envelope hash.", true);
      return;
    }
    show(t);
  }

  updateNav();
  fromURL();
});
