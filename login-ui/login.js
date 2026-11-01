/* Wizard-Zustandsmaschine: 4 Schritte, Fehler inline, kein Routing-Zwang. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const form = $("wizard");
  const panels = Array.from(document.querySelectorAll("[data-panel]"));
  const dots = Array.from(document.querySelectorAll("#step-dots li"));
  const errorBox = $("error");
  const nextBtn = $("next");
  const backBtn = $("back");
  const submitBtn = $("submit");
  const result = $("result");
  let step = 1;
  let mode = "hw";

  const fields = {
    1: () => $("space"),
    2: () => $("user"),
    3: () => $("password"),
  };
  const keys = { 1: "space", 2: "user", 3: "password" };
  // Zustandsmaschine: Werte werden beim Verlassen eines Schritts übernommen.
  // Chrome-Autofill, das später in die DOM-Felder schreibt, kann den Login
  // damit nicht mehr verfälschen.
  const values = { space: "", user: "", password: "" };

  function capture(current) {
    const field = fields[current] && fields[current]();
    if (field) values[keys[current]] = current === 3 ? field.value : field.value.trim();
  }

  function showError(message, field) {
    errorBox.textContent = message || "";
    errorBox.hidden = !message;
    document.querySelectorAll("input[aria-invalid]").forEach((el) => el.removeAttribute("aria-invalid"));
    if (field) {
      field.setAttribute("aria-invalid", "true");
      field.focus();
    }
  }

  function render() {
    panels.forEach((p) => { p.hidden = Number(p.dataset.panel) !== step; });
    dots.forEach((d) => {
      const n = Number(d.dataset.step);
      d.classList.toggle("is-current", n === step);
      d.classList.toggle("is-done", n < step);
    });
    backBtn.hidden = step === 1;
    nextBtn.hidden = step === 4;
    submitBtn.hidden = step !== 4;
    $("step-dots").setAttribute("aria-current", String(step));
  }

  function validate(current) {
    const field = fields[current] && fields[current]();
    if (!field) return true;
    const value = field.value.trim();
    if (!value) {
      showError(current === 1 ? "Bitte die Space-Adresse eingeben." : "Bitte einen Benutzernamen eingeben.", field);
      return false;
    }
    if (current === 1 && !/^[a-z0-9][a-z0-9._-]*$/i.test(value)) {
      showError("Space-Adresse: nur Buchstaben, Ziffern, Punkt, Unterstrich, Bindestrich.", field);
      return false;
    }
    showError("");
    return true;
  }

  function setBusy(busy, label) {
    submitBtn.disabled = busy;
    nextBtn.disabled = busy;
    if (busy) submitBtn.textContent = label || "Anmelden …";
    else submitBtn.textContent = "Anmelden";
  }

  async function hardware() {
    return {
      pem: await Z8.readText($("hw-pem")),
      kem: await Z8.readText($("hw-kem")),
    };
  }

  function splitName(value) {
    const at = value.lastIndexOf("@");
    return at > 0 ? { name: value.slice(0, at), space: value.slice(at + 1) } : { name: value, space: $("space").value.trim() };
  }

  async function doLogin() {
    const hw = await hardware();
    if (mode === "hw" && (!hw.pem || !hw.kem)) {
      showError("Hardware-Key fehlt: PEM und KEM-Datei auswählen (oder Passkey nutzen).");
      return;
    }
    const formData = { space: values.space, user: values.user, password: values.password };
    if (!formData.space || !formData.user || !formData.password) {
      showError("Bitte alle Schritte ausfüllen.");
      return;
    }
    setBusy(true);
    showError("");
    try {
      const world = await Z8.world(formData.space, formData.user);
      let data;
      if (mode === "passkey") data = await Z8.passkeyLogin(formData, hw, world);
      else data = await Z8.passboxLogin(formData, hw, world);

      const token = data.token || (data.proxy_token) || "";
      $("res-space").textContent = data.space_addr || world.space_addr || formData.space;
      $("res-user").textContent = data.username || formData.user;
      $("res-fp").textContent = (data.master_sha256 || "").slice(0, 32) || "—";
      $("res-token").textContent = token ? token.slice(0, 24) + "…" : "(Session)";
      window.__z8_token = token;
      form.hidden = true;
      result.hidden = false;
      dots.forEach((d) => d.classList.add("is-done"));
    } catch (err) {
      const msg = String(err && err.message ? err.message : err);
      showError(msg, step === 3 ? $("password") : null);
    } finally {
      setBusy(false);
    }
  }

  nextBtn.addEventListener("click", () => {
    if (!validate(step)) return;
    capture(step);
    if (step < 4) { step += 1; render(); }
  });

  backBtn.addEventListener("click", () => {
    if (step > 1) { step -= 1; showError(""); render(); }
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (step !== 4) { nextBtn.click(); return; }
    doLogin();
  });

  [1, 2, 3].forEach((n) => {
    fields[n]().addEventListener("input", () => showError(""));
    fields[n]().addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); if (step < 4) nextBtn.click(); else doLogin(); }
    });
  });

  ["hw-pem", "hw-kem"].forEach((id) => $(id).addEventListener("change", () => showError("")));

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      mode = tab.dataset.tab;
      document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("is-active", t === tab));
      document.querySelectorAll("[data-tab-panel]").forEach((p) => { p.hidden = p.dataset.tabPanel !== mode; });
      showError("");
    });
  });

  $("passkey-btn").addEventListener("click", () => {
    $("passkey-hint").textContent = "Passkey wird beim Anmelden über navigator.credentials angefordert.";
  });

  $("logout").addEventListener("click", async () => {
    try { await Z8.logout(); } catch (_) { /* lokal abmelden genügt */ }
    window.__z8_token = "";
    result.hidden = true;
    form.hidden = false;
    step = 1;
    showError("");
    render();
    $("space").focus();
  });

  function themeNote() {
    const light = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
    $("theme-note").textContent = light ? "Design: hell (System)" : "Design: dunkel (Standard)";
  }
  if (window.matchMedia) window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", themeNote);

  const params = new URLSearchParams(location.search);
  if (params.get("space")) $("space").value = params.get("space");
  if (params.get("user")) $("user").value = params.get("user");

  themeNote();
  render();
  window.__z8_ui_ready = true;
})();
