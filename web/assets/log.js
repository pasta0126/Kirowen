// Reading and verifying the public log in the browser (docs/explorer-v0.md §5):
// checkpoints, signed notes, C2SP tiles, leaves (deterministic CBOR) and
// RFC 9162 inclusion proofs. No dependencies; WebCrypto for SHA-256 and Ed25519.
"use strict";

window.KLog = (() => {
  const ORIGIN = "kirowen.northernarchive.com/log/v0";
  // The published log key (keys-public/kirowen.northernarchive.com-log-v0.pub).
  const VKEY = "kirowen.northernarchive.com/log/v0+17c4e654+AaDWeAoySrOyLKK4lZEvGxHMe/WpGWvb4ECEtqIjR+qj";
  const LOG = "/log/v0";
  const API = document.documentElement.dataset.api || "https://kirowen-api.northernarchive.com";

  const enc = new TextEncoder();
  const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  const unhex = s => new Uint8Array(s.match(/../g).map(x => parseInt(x, 16)));
  const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  const sha256 = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

  // --- signed notes and checkpoints (C2SP signed-note, tlog-checkpoint) ---

  // parseNote splits a signed note into its text and signature lines.
  function parseNote(raw) {
    const sep = raw.indexOf("\n\n");
    if (sep < 0) throw new Error("not a signed note");
    const text = raw.slice(0, sep + 1);
    const sigs = [];
    for (const line of raw.slice(sep + 2).split("\n")) {
      if (!line) continue;
      const m = /^— (\S+) (\S+)$/.exec(line);
      if (!m) throw new Error("bad signature line");
      const b = fromB64(m[2]);
      if (b.length < 5) throw new Error("bad signature line");
      sigs.push({ name: m[1], keyHash: hex(b.slice(0, 4)), sig: b.slice(4) });
    }
    return { text, sigs };
  }

  // parseCheckpoint reads origin, size and root from a checkpoint note's text.
  function parseCheckpoint(raw) {
    const { text, sigs } = parseNote(raw);
    const lines = text.split("\n");
    if (lines.length < 4 || !/^\d+$/.test(lines[1])) throw new Error("bad checkpoint");
    const root = fromB64(lines[2]);
    if (root.length !== 32) throw new Error("bad checkpoint");
    return { origin: lines[0], size: BigInt(lines[1]), root, text, sigs, raw };
  }

  // The verifier key is name+keyhash+base64(0x01 ‖ pub); the base64 part may contain "+".
  const [KEY_NAME, KEY_HASH] = VKEY.split("+", 2);
  const KEY_B64 = VKEY.slice(KEY_NAME.length + KEY_HASH.length + 2);
  let logKey = null;
  async function key() {
    if (logKey) return logKey;
    const b = fromB64(KEY_B64);
    if (b.length !== 33 || b[0] !== 1) throw new Error("bad log key");
    logKey = await crypto.subtle.importKey("raw", b.slice(1), { name: "Ed25519" }, false, ["verify"]);
    return logKey;
  }

  // verifyNote checks the log's signature on a note. It returns true or
  // false, or null if this browser cannot verify Ed25519. It also lists
  // the other signers (e.g. witnesses), which are not verified.
  async function verifyNote(n) {
    const isLog = s => s.name === KEY_NAME && s.keyHash === KEY_HASH;
    const others = n.sigs.filter(s => !isLog(s)).map(s => s.name + " " + s.keyHash);
    const mine = n.sigs.find(isLog);
    if (!mine) return { ok: false, others };
    let k;
    try { k = await key(); } catch (_) { return { ok: null, others }; }
    const ok = mine.sig.length === 64 && await crypto.subtle.verify("Ed25519", k, mine.sig, enc.encode(n.text));
    return { ok, others };
  }

  async function checkpoint() {
    const res = await fetch(LOG + "/checkpoint", { cache: "no-store" });
    if (!res.ok) throw new Error("checkpoint: HTTP " + res.status);
    return parseCheckpoint(await res.text());
  }

  // --- tiles (C2SP tlog-tiles) ---

  function tilePath(n) {
    const parts = [];
    do { parts.unshift(String(n % 1000).padStart(3, "0")); n = Math.floor(n / 1000); } while (n > 0);
    return parts.map((p, i) => (i < parts.length - 1 ? "x" : "") + p).join("/");
  }

  async function bundle(n, size) {
    const w = Math.min(256, size - n * 256);
    const url = LOG + "/tile/entries/" + tilePath(n) + (w < 256 ? ".p/" + w : "");
    const res = await fetch(url);
    if (!res.ok) throw new Error("entry bundle: HTTP " + res.status);
    const b = new Uint8Array(await res.arrayBuffer());
    const out = [];
    for (let o = 0; o < b.length;) {
      const len = (b[o] << 8) | b[o + 1];
      out.push(b.slice(o + 2, o + 2 + len));
      o += 2 + len;
    }
    return out;
  }

  // leaves returns the raw bytes of leaves [from, to) of a tree of the given size.
  async function leaves(from, to, size) {
    const out = [];
    for (let n = Math.floor(from / 256); n * 256 < to; n++) {
      const b = await bundle(n, size);
      for (let i = Math.max(from, n * 256); i < Math.min(to, n * 256 + 256); i++) out.push(b[i - n * 256]);
    }
    return out;
  }

  // --- leaves (docs/envelope-v0.md §4, §5.1) ---

  // A minimal CBOR decoder: unsigned ints, byte and text strings, arrays, maps.
  function cbor(b) {
    let o = 0;
    function arg(info) {
      if (info < 24) return BigInt(info);
      const n = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
      if (!n || o + n > b.length) throw new Error("bad CBOR");
      let v = 0n;
      for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(b[o++]);
      return v;
    }
    function item() {
      if (o >= b.length) throw new Error("bad CBOR");
      const ib = b[o++], major = ib >> 5, v = arg(ib & 31);
      const len = () => { if (v > BigInt(b.length)) throw new Error("bad CBOR"); return Number(v); };
      switch (major) {
        case 0: return v;
        case 2: case 3: {
          const n = len();
          if (o + n > b.length) throw new Error("bad CBOR");
          const s = b.slice(o, o + n); o += n;
          return major === 2 ? s : new TextDecoder("utf-8", { fatal: true }).decode(s);
        }
        case 4: return Array.from({ length: len() }, item);
        case 5: { const m = new Map(); for (let n = len(); n > 0; n--) m.set(item(), item()); return m; }
        default: throw new Error("unsupported CBOR");
      }
    }
    const v = item();
    if (o !== b.length) throw new Error("trailing bytes");
    return v;
  }

  // parseLeaf returns {type: "event", envelopeHash} or
  // {type: "checkpoint", size, root, prevSize, prevRoot, note}.
  function parseLeaf(b) {
    const v = cbor(b);
    if (!Array.isArray(v) || v.length !== 3 || v[0] !== 1n) throw new Error("not a v1 leaf");
    if (v[1] === 1n) {
      if (!(v[2] instanceof Uint8Array) || v[2].length !== 32) throw new Error("bad event body");
      return { type: "event", envelopeHash: hex(v[2]) };
    }
    if (v[1] === 2n) {
      const m = v[2];
      if (!(m instanceof Map)) throw new Error("bad checkpoint body");
      const size = m.get(1n), root = m.get(2n), prevSize = m.get(3n), prevRoot = m.get(4n), note = m.get(5n);
      if (typeof size !== "bigint" || !(root instanceof Uint8Array) || root.length !== 32 ||
          typeof prevSize !== "bigint" || size <= prevSize || !(note instanceof Uint8Array) || !note.length ||
          (prevSize > 0n) !== (prevRoot instanceof Uint8Array && prevRoot.length === 32)) {
        throw new Error("bad checkpoint body");
      }
      return { type: "checkpoint", size, root: hex(root), prevSize, prevRoot: prevRoot ? hex(prevRoot) : null,
               note: new TextDecoder().decode(note) };
    }
    throw new Error("unknown leaf type");
  }

  // --- Merkle proofs (RFC 9162 §2.1.3.2) ---

  const leafHash = b => sha256(concat(new Uint8Array([0]), b));
  const nodeHash = (l, r) => sha256(concat(new Uint8Array([1]), l, r));

  async function verifyInclusion(index, size, lh, proof, root) {
    let fn = BigInt(index), sn = BigInt(size) - 1n, r = lh;
    if (fn > sn) return false;
    for (const p of proof) {
      if (sn === 0n) return false;
      if ((fn & 1n) === 1n || fn === sn) {
        r = await nodeHash(p, r);
        while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
      } else {
        r = await nodeHash(r, p);
      }
      fn >>= 1n; sn >>= 1n;
    }
    return sn === 0n && equal(r, root);
  }

  // --- API ---

  async function api(path) {
    const res = await fetch(API + path);
    let data = null;
    try { data = await res.json(); } catch (_) { /* not JSON */ }
    if (!res.ok) { const e = new Error((data && data.error) || ("HTTP " + res.status)); e.status = res.status; throw e; }
    return data;
  }

  return { ORIGIN, VKEY, hex, unhex, fromB64, equal, checkpoint, parseCheckpoint, verifyNote,
           tilePath, leaves, parseLeaf, leafHash, verifyInclusion, api };
})();
