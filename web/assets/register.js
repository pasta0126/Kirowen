// Self-service registration in the browser. The Ed25519 key is created and
// used here (WebCrypto); only the public key and the proof are sent.
"use strict";

const API = document.documentElement.dataset.api || "https://kirowen-api.northernarchive.com";

const $ = id => document.getElementById(id);
const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
const b64 = b => btoa(String.fromCharCode(...b));

let files = null;

function status(msg, isError) {
  const el = $("reg-status");
  el.textContent = msg;
  el.classList.toggle("error", !!isError);
}

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function api(method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* not JSON */ }
  if (!res.ok) throw new Error((data && data.error) || ("HTTP " + res.status));
  return data;
}

async function register(ev) {
  ev.preventDefault();
  const btn = $("reg-btn");
  btn.disabled = true;
  try {
    status("Creating your key…");
    let kp;
    try {
      kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    } catch (_) {
      throw new Error("This browser cannot create Ed25519 keys. Use a current browser, or the kirowen CLI.");
    }
    const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    // PKCS#8 for Ed25519 is a fixed 16-byte prefix followed by the 32-byte seed.
    const seed = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey)).slice(-32);

    status("Reading the log origin…");
    const info = await api("GET", "/v0/");
    const msg = "kirowen register v0\n" + info.origin + "\n" + hex(pub) + "\n";
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, new TextEncoder().encode(msg)));

    status("Registering (about a second)…");
    const r = await api("POST", "/v0/sources", { public_key: b64(pub), proof: b64(sig) });

    const name = "kirowen-" + r.source_id.slice(0, 8);
    const json = o => JSON.stringify(o, null, 2) + "\n";
    files = {
      key: [name + ".key", json({ ed25519_seed: hex(seed), ed25519_public: hex(pub) })],
      cred: [name + ".cred.json", json({ api: API, source_id: r.source_id, token: r.token })],
      pub: [name + ".pub", json({ ed25519_public: hex(pub) })],
    };
    $("r-source").textContent = r.source_id;
    $("r-key").textContent = r.key_id;
    $("r-leaf").textContent = String(r.registration.leaf_index);
    $("r-token").value = r.token;
    try { sessionStorage.setItem("kirowen.token", r.token); } catch (_) { /* storage blocked */ }
    $("reg-form").hidden = true;
    $("reg-result").hidden = false;
    status("");
  } catch (e) {
    status(e.message, true);
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("reg-form").addEventListener("submit", register);
  $("r-copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("r-token").value); $("r-copy").textContent = "Copied"; }
    catch (_) { $("r-token").select(); }
  });
  for (const k of ["key", "cred", "pub"]) {
    $("dl-" + k).addEventListener("click", () => files && download(...files[k]));
  }
  window.addEventListener("beforeunload", e => {
    if (files) { e.preventDefault(); e.returnValue = ""; }
  });
});
