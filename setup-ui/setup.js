/* Setup-Wizard: Zustandsmaschine, echte Engine-Naht, Fehler als Dialog. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const panels = Array.from(document.querySelectorAll("[data-panel]"));
  const dots = Array.from(document.querySelectorAll("#stepnav li"));
  const nextBtn = $("next");
  const backBtn = $("back");
  const runBtn = $("run");
  const errorBox = $("error");
  let step = 1;
  let done = false;

  const state = {
    providers_config: "", bucket: "", prefix: "",
    quorum_min: 2, create_buckets: false,
    space: "", users: [],
    setup_keys: 3, hw_keys: 2, key_dir: "", db_dir: "", vec0: "",
    out: "",
  };

  function showError(msg) {
    errorBox.textContent = msg || "";
    errorBox.hidden = !msg;
  }

  function dialog(msg) {
    $("dialog-text").textContent = msg;
    const d = $("fehler-dialog");
    if (d && typeof d.showModal === "function") d.showModal();
    else showError(msg);
  }

  function render() {
    panels.forEach((p) => { p.hidden = Number(p.dataset.panel) !== step; });
    dots.forEach((d) => {
      const n = Number(d.dataset.step);
      d.classList.toggle("is-current", n === step);
      d.classList.toggle("is-done", n < step);
    });
    backBtn.hidden = step === 1 || step >= 6;
    nextBtn.hidden = step >= 5;
    runBtn.hidden = step !== 5;
  }

  function userRow(name, password) {
    const row = document.createElement("div");
    row.className = "user-row";
    row.innerHTML =
      '<div><label>Name</label><input class="u-name" type="text" spellcheck="false"></div>' +
      '<div><label>Passwort</label><input class="u-pass" type="password" autocomplete="new-password"></div>' +
      '<button type="button" class="ghost remove" title="Entfernen">Entfernen</button>';
    row.querySelector(".u-name").value = name || "";
    row.querySelector(".u-pass").value = password || "";
    row.querySelector(".remove").addEventListener("click", () => {
      row.remove();
      if (!$("users").children.length) addUser("", "");
    });
    return row;
  }
  function addUser(name, password) { $("users").appendChild(userRow(name, password)); }

  function capture() {
    if (step === 1) {
      state.providers_config = $("providers-config").value.trim();
      state.bucket = $("bucket").value.trim();
      state.prefix = $("prefix").value.trim();
      state.quorum_min = Number($("quorum-min").value) || 2;
      state.create_buckets = $("create-buckets").checked;
    } else if (step === 2) {
      state.space = $("space").value.trim();
    } else if (step === 3) {
      state.users = Array.from(document.querySelectorAll("#users .user-row")).map((r) => ({
        name: r.querySelector(".u-name").value.trim(),
        password: r.querySelector(".u-pass").value,
      }));
    } else if (step === 4) {
      state.setup_keys = Number($("setup-keys").value) || 3;
      state.hw_keys = Number($("hw-keys").value) || 2;
      state.key_dir = $("key-dir").value.trim();
      state.db_dir = $("db-dir").value.trim();
      state.vec0 = $("vec0").value.trim();
    } else if (step === 5) {
      state.out = $("out").value.trim();
    }
  }

  function validate() {
    capture();
    if (step === 1 && !state.providers_config) return "Pfad zur Provider-Config fehlt.";
    if (step === 2 && !state.space) return "Space-Name fehlt.";
    if (step === 3 && (!state.users.length || state.users.some((u) => !u.name || !u.password)))
      return "Jeder Benutzer braucht Name und Passwort.";
    if (step === 4 && (state.setup_keys < 2 || state.hw_keys < 2))
      return "Setup- und HW-Keys brauchen mindestens 2.";
    return "";
  }

  function defaults() {
    if (!state.key_dir) state.key_dir = "/data/z8run/setup-keys/" + state.space;
    if (!state.vec0) state.vec0 = "/data/z8run/vec0.so";
    if (!state.out) state.out = state.key_dir.replace(/\/+$/, "") + "/setup.json";
    $("key-dir").value = state.key_dir;
    $("vec0").value = state.vec0;
    $("out").value = state.out;
  }

  function row(dl, label, value) {
    const el = document.createElement("div");
    const dt = document.createElement("dt"); dt.textContent = label;
    const dd = document.createElement("dd"); dd.textContent = value;
    el.appendChild(dt); el.appendChild(dd);
    dl.appendChild(el);
  }

  function summary() {
    defaults();
    const dl = document.createElement("dl");
    row(dl, "Space", state.space);
    row(dl, "Provider-Config", state.providers_config);
    row(dl, "Bucket / Prefix", (state.bucket || "(aus Config)") + " / " + (state.prefix || "(aus Config)"));
    row(dl, "Quorum", String(state.quorum_min));
    row(dl, "Benutzer", state.users.map((u) => u.name).join(", "));
    row(dl, "Setup-Keys", String(state.setup_keys));
    row(dl, "User-HW-Keys", String(state.hw_keys));
    row(dl, "Key-Verzeichnis", state.key_dir);
    row(dl, "DB-Verzeichnis", state.db_dir || state.key_dir + "/db");
    const box = $("summary"); box.innerHTML = ""; box.appendChild(dl);
  }

  function log(text, isErr) {
    const pre = $("engine-log");
    if (isErr) { const s = document.createElement("span"); s.className = "err"; s.textContent = text + "\n"; pre.appendChild(s); }
    else pre.appendChild(document.createTextNode(text + "\n"));
    pre.scrollTop = pre.scrollHeight;
  }

  async function run() {
    capture();
    if (!state.out) defaults();
    runBtn.disabled = true;
    showError("");
    $("engine-log").textContent = "";
    step = 6; render();
    const payload = {
      providers_config: state.providers_config,
      bucket: state.bucket || null,
      prefix: state.prefix || null,
      space: state.space,
      users: state.users,
      setup_keys: state.setup_keys,
      hw_keys: state.hw_keys,
      quorum_min: state.quorum_min,
      key_dir: state.key_dir || null,
      db_dir: state.db_dir || null,
      vec0: state.vec0 || null,
      out: state.out || null,
      create_buckets: state.create_buckets,
    };
    try {
      const res = await fetch("/setup-ui/v1/init", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        let text = await res.text();
        throw new Error(text || "HTTP " + res.status);
      }
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done: end, value } = await reader.read();
        if (end) break;
        buf += dec.decode(value, { stream: true });
        let cut;
        while ((cut = buf.indexOf("\n\n")) >= 0) {
          const block = buf.slice(0, cut); buf = buf.slice(cut + 2);
          const line = block.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).join("\n");
          if (!line) continue;
          if (line.startsWith("log|")) log(line.slice(4));
          else if (line.startsWith("error|")) { log(line.slice(6), true); dialog(line.slice(6)); }
          else if (line.startsWith("done|")) finish(JSON.parse(line.slice(5)));
        }
      }
    } catch (err) {
      const msg = String(err && err.message ? err.message : err);
      log(msg, true);
      dialog(msg);
    } finally {
      runBtn.disabled = false;
    }
  }

  function finish(data) {
    done = true;
    state.out = data.out || state.out;
    const dl = document.createElement("dl");
    row(dl, "Space", data.space || state.space);
    row(dl, "Space-Adresse", data.addr_space || "");
    row(dl, "Benutzer", (data.users || []).map((u) => u.name + " → " + u.addr_user).join(", "));
    row(dl, "Dateien", String(data.files || 0));
    row(dl, "Provider", data.provider_degraded ? "degraded (Quorum hielt)" : "3/3");
    const box = $("result"); box.innerHTML = ""; box.appendChild(dl);
    $("out-path").textContent = state.out || "(kein Setup-JSON geschrieben)";
    step = 7; render();
  }

  nextBtn.addEventListener("click", () => {
    const err = validate();
    if (err) { showError(err); return; }
    showError("");
    if (step === 4) { defaults(); }
    if (step === 5) { summary(); }
    if (step < 5) { step += 1; render(); if (step === 5) summary(); }
  });
  backBtn.addEventListener("click", () => {
    if (step > 1 && !done) { step -= 1; showError(""); render(); }
  });
  runBtn.addEventListener("click", run);
  $("add-user").addEventListener("click", () => addUser("", ""));

  addUser("", "");
  render();
  window.__z8_setup_ready = true;
})();
