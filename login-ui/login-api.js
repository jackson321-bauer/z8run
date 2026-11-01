/* Dünner Client gegen die dokumentierte Z8-API. Keine Krypto-Logik in der UI. */
(function (global) {
  "use strict";

  function serverBase() {
    const field = document.getElementById("server");
    const raw = field && field.value.trim();
    return raw ? raw.replace(/\/+$/, "") : location.origin;
  }

  function wanted() {
    const space = document.getElementById("space").value.trim();
    const user = document.getElementById("user").value.trim();
    const password = document.getElementById("password").value;
    return { space, user, password };
  }

  async function readText(input) {
    const file = input && input.files && input.files[0];
    if (!file) return "";
    return (await file.text()).trim();
  }

  async function world(space, user) {
    const url = serverBase() + "/login-ui/v1/world?space=" +
      encodeURIComponent(space) + "&user=" + encodeURIComponent(user);
    const res = await fetch(url, { headers: { accept: "application/json" } });
    const data = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(data.error || "Weltdaten nicht abrufbar (HTTP " + res.status + ")");
    return data;
  }

  /* Der Kern läuft im Dedicated Worker (OPFS-Sync-Access gibt es nur dort).
     Nachrichten erst nach der READY-Meldung senden — sonst gehen sie während
     des WASM-Init verloren (Modul-Worker mit Top-Level-Await). */
  let worker = null;
  let workerReady = false;
  const waiting = [];
  function coreWorker() {
    if (!worker) {
      worker = new Worker(serverBase() + "/wasm/worker.js", { type: "module" });
      worker.onmessage = function (event) {
        let msg;
        try { msg = JSON.parse(event.data); } catch (err) { msg = { status: 500, body: { error: String(err) } }; }
        if (msg && msg.body && msg.body.ready) {
          workerReady = true;
          waiting.forEach(function (item) { worker.postMessage(item.msg); });
          return;
        }
        const item = waiting.shift();
        if (item) item.resolve(msg);
      };
      worker.onerror = function (event) {
        const item = waiting.shift();
        if (item) item.resolve({ status: 500, body: { error: "Kern-Worker: " + (event.message || "Fehler") } });
      };
    }
    return worker;
  }

  function callCore(message) {
    return new Promise(function (resolve) {
      coreWorker();
      waiting.push({ msg: message, resolve: resolve });
      if (workerReady) worker.postMessage(message);
    });
  }

  function facade(request) {
    return callCore(request);
  }

  function sessionId() {
    let id = sessionStorage.getItem("z8.session");
    if (!id) {
      id = "ui-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8);
      sessionStorage.setItem("z8.session", id);
    }
    return id;
  }

  /* Browser-Weg (/3): Passbox + HW-Box werden im WASM-Kern geöffnet. */
  async function passboxLogin(form, hardware, worldData) {
    const body = {
      schema: "Argon2IDHashDatei/3",
      space: form.space,
      username: form.user,
      password: form.password,
      hw_pem: hardware.pem,
      kem_dk_b64: hardware.kem,
      v3_b2b: worldData.b2b,
      v3_hw: worldData.hw_shards,
      session_id: sessionId()
    };
    if (worldData.db_id) body.db_id = worldData.db_id;
    const res = await facade({ method: "POST", path: "/v1/login/passbox", body: body });
    if (res.status !== 200) throw new Error(res.body && res.body.error ? res.body.error : "Login abgewiesen");
    return res.body;
  }

  async function logout() {
    await facade({ method: "POST", path: "/v1/session/logout", body: { session_id: sessionId() } });
  }

  function b64urlToBytes(value) {
    const s = value.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function bytesToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /* Native Weg: Challenge, navigator.credentials-Assertion, Client-Shard, Hook. */
  async function passkeyLogin(form, hardware, worldData) {
    if (!worldData.login_flow_id) throw new Error("Login-Flow nicht bereit (nur der Browser-Weg ist verfügbar)");
    const flow = worldData.login_flow_id;
    const chRes = await fetch(serverBase() + "/hook/" + flow + "/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ space: form.space, user: form.user })
    });
    const ch = await chRes.json().catch(function () { return {}; });
    if (!chRes.ok) throw new Error(ch.error || "Challenge abgewiesen");
    const challenge = ch.challenge || (ch.body && ch.body.challenge);
    const rpId = ch.rpId || (ch.body && ch.body.rpId) || location.hostname;
    if (!challenge) throw new Error("Challenge fehlt in der Antwort");

    const allow = (ch.allowCredentials || (ch.body && ch.body.allowCredentials) || []).map(function (c) {
      return { type: "public-key", id: b64urlToBytes(c.id || c.credentialId) };
    });
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: b64urlToBytes(challenge),
        rpId: rpId,
        allowCredentials: allow,
        timeout: 60000,
        userVerification: "preferred"
      }
    });
    if (!cred) throw new Error("Hardware-Key hat die Assertion abgelehnt");

    const shard = await callCore({
      __z8: "open_shard_v3",
      hw_shards: worldData.hw_shards,
      hw_pem: hardware.pem,
      kem_dk_b64: hardware.kem
    });
    if (shard.error) throw new Error(shard.error);

    const body = {
      space: form.space,
      user: form.user,
      password: form.password,
      challenge: challenge,
      credentialId: bytesToB64url(cred.rawId),
      authenticatorData: bytesToB64url(cred.response.authenticatorData),
      clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
      signature: bytesToB64url(cred.response.signature),
      shamir_hw: { x: shard.x, y_b64: shard.y_b64 }
    };
    const res = await fetch(serverBase() + "/hook/" + flow + "/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(data.error || "Login abgewiesen (HTTP " + res.status + ")");
    return data;
  }

  global.Z8 = { serverBase, wanted, readText, world, passboxLogin, passkeyLogin, logout, sessionId };
})(window);
