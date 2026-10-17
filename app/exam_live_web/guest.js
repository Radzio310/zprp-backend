/* Egzamin na żywo - strona uczestnika w przeglądarce (17.10.2026).

   Dla WSZYSTKICH: sędzia loguje się kontem BAZY (POST /exam-live/web-login - ten sam login co
   w aplikacji) i dołącza zwykłym POST /exam-live/join, więc wynik trafia do jego historii jak
   z aplikacji. Gość z pseudonimem tylko wtedy, gdy prowadzący włączył gości.

   Stan po odświeżeniu: miejsce w sesji (`bazaLive.seat`: id sesji, rodzaj, guest_token) i token
   logowania (`bazaLive.auth`, 12 h) leżą w localStorage; strona wraca prosto do bieżącej fazy.
   Wszystko od ludzi (nicki, treści) idzie do DOM przez textContent. */
(function () {
  "use strict";
  var L = window.Live, el = L.el, $ = L.$;
  var view = $("view"), enc = encodeURIComponent;
  var SEAT = "bazaLive.seat", AUTH = "bazaLive.auth";
  var client = null, wake = null, cur = null, peekData = null, lastSnap = null;

  L.hall();
  if (window.matchMedia) {
    var mq = matchMedia("(prefers-color-scheme: light)");
    var setTheme = function () { document.body.classList.toggle("light", mq.matches); };
    setTheme();
    if (mq.addEventListener) mq.addEventListener("change", setTheme);
  }

  /* ----- adres: /exam-live/j/{token}, /exam-live/join/{token}, ?pin= ----- */
  function refFromUrl() {
    var parts = location.pathname.split("/").filter(Boolean);
    var i = Math.max(parts.indexOf("j"), parts.indexOf("join"));
    if (i >= 0 && parts[i + 1]) return { token: decodeURIComponent(parts[i + 1]) };
    var pin = (new URLSearchParams(location.search).get("pin") || "").replace(/\D/g, "");
    return pin.length === 6 ? { pin: pin } : null;
  }
  function sameRef(a, b) { return !!(a && b && ((a.token && a.token === b.token) || (a.pin && a.pin === b.pin))); }

  function auth() {
    var a = L.readJSON(AUTH);
    if (a && a.token && a.exp > Date.now() + 60000) return a;
    if (a) L.writeJSON(AUTH, null);
    return null;
  }

  /* ----- sieć ----- */
  function api(method, url, body, headers) {
    var h = { "Content-Type": "application/json" };
    Object.keys(headers || {}).forEach(function (k) { h[k] = headers[k]; });
    return fetch(url, { method: method, headers: h, body: body ? JSON.stringify(body) : undefined, cache: "no-store" })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (r.ok) return j;
          var d = (j && (j.detail || j)) || {};
          var e = new Error((typeof d === "string" ? d : d.message) || "Coś poszło nie tak. Spróbuj jeszcze raz.");
          e.code = typeof d === "object" ? d.code : null; e.status = r.status;
          throw e;
        });
      }, function () {
        var e = new Error("Brak połączenia z serwerem. Sprawdź internet i spróbuj jeszcze raz."); e.code = "NET"; e.status = 0; throw e;
      });
  }
  function seatHeaders(seat) {
    if (seat.kind === "guest") return { "X-Guest-Token": seat.gt };
    var a = auth();
    return a ? { Authorization: "Bearer " + a.token } : {};
  }

  /* ----- nagłówek ----- */
  function setHead(title, eyebrow) {
    $("title").textContent = title || "Egzamin na żywo";
    $("eyebrow").textContent = eyebrow || "BAZA · Egzamin z przepisów";
    document.title = (title || "Egzamin na żywo") + " - BAZA";
  }
  function setBrand(p) {
    if (!p || !p.brand) return;
    peekData = p;
    L.applyPalette(p.brand.palette);
    var c = $("crest");
    if (!c.firstChild) c.appendChild(el("img", { alt: "", src: p.brand.crest_url }));
    setHead(p.title, L.charLabel(p.character) + " · " + p.province_label);
  }

  function show(node) {
    if (cur && cur.destroy) cur.destroy();
    cur = node;
    L.clear(view);
    view.appendChild(node.node || node);
    if (node.mount) node.mount();
    window.scrollTo(0, 0);
  }
  function viewOf(kids, extra) { return el("div", { class: "view" + (extra ? " " + extra : "") }, kids); }

  /* ================= wejście: PIN ================= */
  function pinView(msg) {
    setFuse(false); clock(null);
    var input = el("input", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", "aria-label": "Kod PIN", pattern: "[0-9]*" });
    var cells = [];
    var box = el("div", { class: "pinbox" });
    for (var i = 0; i < 6; i++) {
      if (i === 3) box.appendChild(el("span", { class: "gap" }));
      var c = el("span", { class: "cell empty ticket num" }); cells.push(c); box.appendChild(c);
    }
    box.appendChild(input);
    var err = el("p", { class: "err", text: msg || "" });
    var go = el("button", { class: "btn", type: "button", text: "Dalej", disabled: true });
    function paint() {
      var v = input.value.replace(/\D/g, "").slice(0, 6);
      if (v !== input.value) input.value = v;
      cells.forEach(function (c, i) {
        var had = c.textContent;
        c.textContent = v[i] || "";
        c.className = "cell ticket num " + (v[i] ? "fill" : "empty") + (i === v.length && document.activeElement === input ? " cur" : "");
        if (had === c.textContent && v[i]) c.classList.remove("fill");
      });
      go.disabled = v.length !== 6;
      if (v.length === 6) submit();
    }
    var busy = false;
    function submit() {
      if (busy) return;
      busy = true; go.disabled = true; err.textContent = "";
      peek({ pin: input.value }).then(null, function (e) { busy = false; err.textContent = e.message; go.disabled = false; input.focus(); });
    }
    input.addEventListener("input", paint);
    input.addEventListener("focus", paint); input.addEventListener("blur", paint);
    go.addEventListener("click", submit);
    box.addEventListener("click", function () { input.focus(); });
    setHead("Dołącz do sesji", "BAZA · Egzamin z przepisów · na żywo");
    show({
      node: viewOf([
        el("div", { class: "card stack rise" }, [
          el("span", { class: "eyebrow", text: "Kod PIN z ekranu prowadzącego" }),
          box, err, go
        ]),
        el("p", { class: "note center fade", style: { "--d": ".3s" }, text: "Masz aplikację BAZA? Tam też: Egzamin na żywo - Dołącz. Tutaj zalogujesz się tym samym kontem." })
      ]),
      mount: function () { setTimeout(function () { input.focus(); }, 250); }
    });
  }

  /* ================= karta sesji przed dołączeniem ================= */
  function peek(ref) {
    var q = ref.token ? "token=" + enc(ref.token) : "pin=" + enc(ref.pin);
    return api("GET", "/exam-live/peek?" + q).then(function (p) {
      setBrand(p);
      sessionView(p, ref);
    }, function (e) {
      if (e.code === "LIVE_ENDED") { goneView("Ta sesja jest już zakończona", "Wyniki zobaczysz w aplikacji BAZA, jeśli grałeś kontem."); return; }
      if (e.code === "LIVE_NOT_FOUND" && ref.token) { goneView("Nie znam tego linku", "Link mógł wygasnąć. Wpisz kod PIN z ekranu prowadzącego.", true); return; }
      throw e;
    });
  }

  function hero(p) {
    var kind = L.charLabel(p.character);
    var phase = p.phase === "lobby" ? "Czeka na start" : p.phase === "end" ? "Zakończona" : "Trwa";
    return el("div", { class: "hero ticket rise" }, [
      el("div", { class: "row" }, [
        el("span", { class: "crest" }, [el("img", { alt: "", src: p.brand.crest_url })]),
        el("div", null, [el("span", { class: "eyebrow", text: "Egzamin z przepisów · na żywo" }), el("h1", { text: p.title || "Egzamin z przepisów" })])
      ]),
      el("div", { class: "tags" }, [el("span", { class: "tag", text: kind }), el("span", { class: "tag", text: p.province_label }),
        el("span", { class: "tag", text: p.q_total + " " + L.plural(p.q_total, "pytanie", "pytania", "pytań") })]),
      el("div", { class: "perf" }),
      el("div", { class: "stub" }, [el("span", null, [el("i", { class: "live-dot" }), el("b", { text: phase })]),
        el("span", { text: p.guests_allowed ? "Konto BAZY albo gość" : "Tylko konto BAZY" })])
    ]);
  }

  function sessionView(p, ref) {
    var a = auth();
    var err = el("p", { class: "err" });
    var actions = el("div", { class: "stack rise", style: { "--d": ".15s" } });
    if (p.locked) actions.appendChild(el("p", { class: "note warn", text: "Prowadzący zamknął salę: nowe osoby już nie wejdą. Jeśli byłeś w niej wcześniej, zaloguj się - wrócisz na swoje miejsce." }));
    else if (!p.joinable) actions.appendChild(el("p", { class: "note warn", text: "Sesja już trwa, a prowadzący nie wpuszcza spóźnionych. Jeśli byłeś w niej wcześniej, zaloguj się - wrócisz na swoje miejsce." }));
    if (a) {
      var me = el("button", { class: "btn accent", type: "button", text: "Dołącz jako " + (a.name || "sędzia " + a.judge) });
      me.addEventListener("click", function () { me.disabled = true; joinUser(ref, err).then(null, function () { me.disabled = false; }); });
      actions.appendChild(me);
      actions.appendChild(el("button", { class: "link", type: "button", text: "To nie ja - zaloguj innym kontem", onclick: function () { L.writeJSON(AUTH, null); loginView(p, ref); } }));
    } else {
      actions.appendChild(el("button", { class: "btn accent", type: "button", text: "Zaloguj się kontem BAZY", onclick: function () { loginView(p, ref); } }));
    }
    if (p.guests_allowed) actions.appendChild(el("button", { class: "btn ghost", type: "button", text: "Wejdź jako gość (wynik bez zapisu)", onclick: function () { nickView(p, ref); } }));
    else actions.appendChild(el("p", { class: "note", text: "Prowadzący nie wpuszcza gości: wynik liczy się tylko z konta BAZY." }));
    actions.appendChild(err);
    show({ node: viewOf([hero(p), actions, el("button", { class: "link fade", type: "button", text: "Inny kod PIN", style: { "--d": ".4s" }, onclick: function () { history.replaceState(null, "", "/exam-live/join"); pinView(); } })]) });
  }

  /* ================= logowanie kontem BAZY ================= */
  function loginView(p, ref, msg) {
    var user = el("input", { autocomplete: "username", autocapitalize: "none", spellcheck: "false", id: "lu" });
    var pass = el("input", { type: "password", autocomplete: "current-password", id: "lp" });
    var err = el("p", { class: "err", text: msg || "" });
    var go = el("button", { class: "btn accent", type: "submit", text: "Zaloguj i dołącz" });
    var form = el("form", { class: "card stack rise" }, [
      el("span", { class: "eyebrow", text: "Konto BAZY" }),
      el("div", { class: "field" }, [el("label", { for: "lu", text: "Login" }), user]),
      el("div", { class: "field" }, [el("label", { for: "lp", text: "Hasło" }), pass]),
      err, go,
      el("p", { class: "note", text: "Te same dane co w aplikacji BAZA (konto ZPRP). Wynik trafi do Twojej historii egzaminów." })
    ]);
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      err.textContent = ""; go.disabled = true; go.textContent = "Loguję…";
      api("POST", "/exam-live/web-login", { username: user.value, password: pass.value }).then(function (res) {
        L.writeJSON(AUTH, { token: res.access_token, exp: Date.now() + (res.expires_in || 3600) * 1000, name: res.name || "", judge: res.judge_id });
        go.textContent = "Dołączam…";
        return joinUser(ref, err);
      }).then(null, function (e) { err.textContent = e.message; go.disabled = false; go.textContent = "Zaloguj i dołącz"; });
    });
    show({ node: viewOf([p ? hero(p) : null, form, el("button", { class: "link", type: "button", text: "Wróć", onclick: function () { p ? sessionView(p, ref) : pinView(); } })]),
      mount: function () { setTimeout(function () { user.focus(); }, 300); } });
  }

  function joinUser(ref, err) {
    var a = auth();
    if (!a) { loginView(peekData, ref, "Zaloguj się, żeby dołączyć."); return Promise.reject(new Error("auth")); }
    return api("POST", "/exam-live/join", { pin: ref.pin || null, token: ref.token || null }, { Authorization: "Bearer " + a.token }).then(function (res) {
      var seat = { sid: res.session_id, kind: "user", ref: ref, at: Date.now() };
      L.writeJSON(SEAT, seat);
      live(seat, res.snapshot);
    }, function (e) {
      if (e.status === 401) { L.writeJSON(AUTH, null); loginView(peekData, ref, "Logowanie wygasło. Zaloguj się jeszcze raz."); }
      else if (err) err.textContent = e.message;
      throw e;
    });
  }

  /* ================= gość ================= */
  function nickView(p, ref) {
    var nick = el("input", { maxlength: "24", autocomplete: "nickname", id: "nn", enterkeyhint: "go" });
    var err = el("p", { class: "err" });
    var go = el("button", { class: "btn", type: "submit", text: "Wchodzę" });
    var form = el("form", { class: "card stack rise" }, [
      el("span", { class: "eyebrow", text: "Gość" }),
      el("div", { class: "field" }, [el("label", { for: "nn", text: "Pseudonim na rzutniku" }), nick]),
      err, go,
      el("p", { class: "note", text: "Jako gość grasz na żywo, ale wynik nie trafi na żadne konto. Sędzio: zaloguj się kontem BAZY." })
    ]);
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      err.textContent = ""; go.disabled = true;
      api("POST", "/exam-live/guest/join", { pin: ref.pin || null, token: ref.token || null, nick: nick.value }).then(function (res) {
        var seat = { sid: res.session_id, kind: "guest", gt: res.guest_token, name: res.name, ref: ref, at: Date.now() };
        L.writeJSON(SEAT, seat);
        live(seat, res.snapshot);
      }, function (e) { err.textContent = e.message; go.disabled = false; });
    });
    show({ node: viewOf([hero(p), form, el("button", { class: "link", type: "button", text: "Wróć", onclick: function () { sessionView(p, ref); } })]),
      mount: function () { setTimeout(function () { nick.focus(); }, 300); } });
  }

  function goneView(title, text, withPin) {
    setFuse(false); clock(null);
    show({ node: viewOf([el("div", { class: "gone" }, [
      el("span", { class: "eyebrow accent", text: "Egzamin na żywo" }),
      el("h1", { class: "big-title display", text: title }),
      el("p", { class: "note", text: text || "" }),
      withPin !== false ? el("button", { class: "btn", type: "button", text: "Wpisz kod PIN", onclick: function () { history.replaceState(null, "", "/exam-live/join"); pinView(); } }) : null
    ])]) });
  }

  /* ================= na żywo ================= */
  function live(seat, first) {
    if (client) client.stop();
    if (!wake) wake = L.keepAwake();
    if (!peekData && seat.ref) api("GET", "/exam-live/peek?" + (seat.ref.token ? "token=" + enc(seat.ref.token) : "pin=" + enc(seat.ref.pin))).then(setBrand, function () {});
    var guest = seat.kind === "guest";
    client = new L.LiveClient({
      stateUrl: function (since) { return (guest ? "/exam-live/guest/" : "/exam-live/") + enc(seat.sid) + "/state" + (since != null && since >= 0 ? "?since_rev=" + since : ""); },
      headers: function () { return seatHeaders(seat); },
      wsUrl: function () { return L.wsBase() + "/exam-live/ws/" + enc(seat.sid) + "?role=" + (guest ? "guest" : "player"); },
      auth: function () { if (guest) return { type: "auth", gt: seat.gt }; var a = auth(); return a ? { type: "auth", token: a.token } : null; },
      onSnapshot: function (s) { render(seat, s); },
      onStatus: L.connPill($("conn")),
      onError: function (m) {
        if (m && m.code === "LIVE_KICKED") { client.stop(); lost(seat, { code: "LIVE_KICKED", status: 403 }); return; }
        if (m && m.message && m.code !== "LIVE_NOT_JOINED" && m.code !== "UNAUTHORIZED") L.toast(m.message);
      },
      onFatal: function (e) { lost(seat, e); }
    });
    if (first) client.apply(first);
    client.start();
  }

  function lost(seat, e) {
    setFuse(false); clock(null);
    if (e.status === 401) { L.writeJSON(AUTH, null); loginView(peekData, seat.ref, "Logowanie wygasło. Zaloguj się jeszcze raz - wrócisz na swoje miejsce."); return; }
    L.writeJSON(SEAT, null);
    if (e.code === "LIVE_KICKED") { goneView("Prowadzący usunął Cię z sali", "Jeśli to pomyłka, podejdź do prowadzącego.", false); return; }
    if (e.status === 404) { goneView("Tej sesji już nie ma", "Prowadzący mógł ją usunąć albo wygasła."); return; }
    if (seat.ref) peek(seat.ref).then(null, function (x) { pinView(x.message); });
    else pinView("Nie rozpoznaję Cię w tej sesji. Dołącz jeszcze raz.");
  }

  var phaseKey = null;
  function render(seat, snap) {
    lastSnap = snap;
    var s = snap.session;
    if (!peekData) setHead(s.title, L.charLabel(s.character));
    if (snap.role === "host") {
      client.stop();
      goneView("Prowadzisz tę sesję", "Steruj nią w aplikacji BAZA. Ta strona jest dla uczestników.", false);
      return;
    }
    var key = s.phase === "lobby" ? "lobby" : s.phase === "end" ? "end" : s.phase + ":" + s.q_index;
    if (key !== phaseKey || !cur || !cur.update) { phaseKey = key; show(build(seat, snap)); }
    else cur.update(snap);
  }

  function build(seat, snap) {
    var ph = snap.session.phase;
    if (ph === "lobby") return lobbyView(seat, snap);
    if (ph === "question" && snap.question) return questionView(seat, snap);
    if (ph === "reveal") return revealView(seat, snap);
    if (ph === "leaderboard") return boardView(seat, snap);
    if (ph === "end") return endView(seat, snap);
    return boardView(seat, snap);
  }

  /* ----- lont i zegar w nagłówku ----- */
  function setFuse(on, deadline, total) {
    var f = $("fuse"), i = f.firstChild;
    f.classList.toggle("on", !!on);
    if (!on) return;
    var left = L.secondsLeft(deadline);
    i.style.transition = "none";
    i.style.transform = "scaleX(" + Math.min(1, left / Math.max(1, total)).toFixed(4) + ")";
    void i.offsetWidth;
    i.style.transition = "transform " + left.toFixed(2) + "s linear";
    i.style.transform = "scaleX(0)";
  }
  var clockTimer = null;
  function frozen(seconds) {
    var c = $("clock"), f = $("fuse");
    clearInterval(clockTimer);
    c.hidden = false; c.textContent = String(Math.ceil(seconds || 0)); c.classList.remove("hot"); f.classList.remove("hot");
    f.classList.add("on");
    var i = f.firstChild; i.style.transition = "transform .3s"; i.style.transform = "scaleX(" + Math.min(1, (seconds || 0) / Math.max(1, frozen.total || 20)).toFixed(4) + ")";
  }
  function clock(deadline) {
    var c = $("clock");
    clearInterval(clockTimer);
    if (!deadline) { c.hidden = true; $("fuse").classList.remove("hot"); return; }
    c.hidden = false;
    var lastS = null;
    function tick() {
      var left = L.secondsLeft(deadline), s = Math.ceil(left);
      if (s === lastS) return;
      lastS = s; c.textContent = String(s);
      var hot = left > 0 && left <= 5;
      c.classList.toggle("hot", hot); $("fuse").classList.toggle("hot", hot);
      if (hot) { c.classList.remove("beat"); void c.offsetWidth; c.classList.add("beat"); if (navigator.vibrate && s === 3) navigator.vibrate(30); }
      if (left <= 0) clearInterval(clockTimer);
    }
    tick();
    clockTimer = setInterval(tick, 200);
  }

  /* ----- lobby: bilet uczestnika ----- */
  function lobbyView(seat, snap) {
    setFuse(false); clock(null);
    var me = snap.me || {}, s = snap.session;
    var count = el("b", { class: "num", text: String(s.joined) });
    var shine = el("span", { class: "shine" });
    var user = me.kind !== "guest";
    var front = el("div", { class: "face ticket" }, [
      el("span", { class: "eyebrow", text: "Twój bilet na salę" }),
      el("div", { class: "name", text: me.name || seat.name || "" }),
      el("div", { class: "kind", text: user ? "Konto BAZY · wynik trafi do Twojej historii" : "Gość · wynik nie trafi na konto" }),
      el("div", { class: "perf" }),
      el("div", { class: "bottom" }, [el("span", { text: "Na sali" }), count]),
      shine
    ]);
    var back = el("div", { class: "face b ticket" }, [
      el("span", { class: "eyebrow", text: "Jak to działa" }),
      el("ol", null, [
        el("li", { text: "Pytanie pojawia się na rzutniku i tutaj." }),
        el("li", { text: s.character === "exam" ? "Liczy się poprawność. Masz jedną odpowiedź na pytanie." : "Liczy się poprawność i szybkość. Jedna odpowiedź na pytanie." }),
        el("li", { text: "Po każdym pytaniu zobaczysz pieczątkę i swoje miejsce." })
      ]),
      el("div", { class: "perf" }),
      el("div", { class: "bottom" }, [el("span", { text: "Stuknij, żeby odwrócić" })])
    ]);
    var flip = el("div", { class: "flip pop", role: "button", tabindex: "0", "aria-label": "Twój bilet - stuknij, żeby odwrócić" }, [el("div", { class: "inner" }, [front, back])]);
    flip.addEventListener("click", function () { flip.classList.toggle("back"); });
    var stop = null;
    return {
      node: viewOf([flip, el("div", { class: "waiting fade", style: { "--d": ".5s" } }, [
        el("i", { style: { "--d": "0s" } }, []), el("i", { style: { "--d": ".2s" } }), el("i", { style: { "--d": ".4s" } }), el("span", { text: "Czekamy na start prowadzącego" })])]),
      mount: function () { stop = L.every(4500, 9500, function () { shine.classList.remove("go"); void shine.offsetWidth; shine.classList.add("go"); }); },
      update: function (snap2) { L.countUp(count, snap2.session.joined, 500); },
      destroy: function () { if (stop) stop(); }
    };
  }

  /* ----- pytanie ----- */
  function questionView(seat, snap) {
    var q = snap.question, s = snap.session;
    var only = !!q.tiles_only, picked = [], sending = false;
    var total = q.time_s || s.question_time_s || 20, paused = false;
    frozen.total = total;
    var pauseCard = el("div", { class: "card center stack pop pausecard" }, [el("div", { class: "stamp part slam" }, ["Pauza", el("small", { text: "zegar stoi" })]),
      el("p", { class: "note", text: "Prowadzący wstrzymał pytanie. Odpowiesz, gdy czas ruszy." })]);
    function applyPause(sn) {
      var on = !!(sn.session.paused || (sn.question && sn.question.paused));
      if (on === paused && !on) return;
      paused = on;
      grid.classList.toggle("paused", on);
      if (on) { frozen(sn.question ? sn.question.seconds_left : 0); if (!pauseCard.parentNode) box.insertBefore(pauseCard, box.firstChild); }
      else { if (pauseCard.parentNode) pauseCard.remove(); setFuse(true, q.deadline_at, total); clock(q.deadline_at); }
    }
    var head = el("div", { class: "qhead" }, [el("span", null, ["Pytanie ", el("b", { class: "num", text: String(q.index + 1) }), " / " + q.total]),
      q.rule ? el("span", { text: "Przepis " + q.rule }) : null]);
    var grid = el("div", { class: "ptiles" + (only ? " only" : "") + (q.multi && !only ? " multi" : "") });
    var tiles = {};
    (q.answers || []).forEach(function (a, i) {
      var t = el("button", { class: "ptile", type: "button", "data-k": a.key, style: { "--d": (0.05 + i * 0.06).toFixed(2) + "s" } }, [
        el("span", { class: "badge" }, [L.shape(a.key)]),
        el("span", { class: "tx", text: only ? (L.LETTERS[a.key] || "") : (a.text || "") }),
        q.multi ? el("span", { class: "chk", text: "✓" }) : null
      ]);
      t.addEventListener("click", function () { pick(a.key); });
      tiles[a.key] = t; grid.appendChild(t);
    });
    var submit = q.multi ? el("button", { class: "btn accent submit", type: "button", text: "Zaznacz odpowiedzi", disabled: true }) : null;
    if (submit) submit.addEventListener("click", function () { send(picked.slice()); });
    var body = el("div", { class: "stack" }, [head, only ? null : el("div", { class: "qtext", text: q.text || "" }),
      q.multi ? el("span", { class: "qmulti", text: "Kilka poprawnych - zaznacz wszystkie" }) : null]);
    var box = viewOf([body, grid, submit]);

    function paintPicked() {
      Object.keys(tiles).forEach(function (k) { tiles[k].classList.toggle("sel", picked.indexOf(k) >= 0); });
      if (submit) { submit.disabled = !picked.length || sending; submit.textContent = picked.length ? "Zatwierdź (" + picked.length + ")" : "Zaznacz odpowiedzi"; }
    }
    function pick(k) {
      if (sending) return;
      if (q.multi) { var i = picked.indexOf(k); if (i >= 0) picked.splice(i, 1); else picked.push(k); paintPicked(); if (navigator.vibrate) navigator.vibrate(8); return; }
      picked = [k]; paintPicked(); send([k]);
    }
    function send(sel) {
      if (sending || !sel.length) return;
      sending = true; grid.classList.add("locked"); paintPicked();
      if (navigator.vibrate) navigator.vibrate(15);
      var url = seat.kind === "guest" ? "/exam-live/guest/" + enc(seat.sid) + "/answer" : "/exam-live/" + enc(seat.sid) + "/answer";
      api("POST", url, { selected: sel }, seatHeaders(seat)).then(function (res) {
        if (res.snapshot) client.apply(res.snapshot);
      }, function (e) {
        if (e.code === "LIVE_ALREADY_ANSWERED") return;
        sending = false; grid.classList.remove("locked"); paintPicked();
        if (e.code === "LIVE_TIME_UP" || e.code === "LIVE_NOT_ACCEPTING") { L.toast("Czas minął - ta odpowiedź już nie weszła."); return; }
        if (e.status === 401) { lost(seat, e); return; }
        L.toast(e.message);
      });
    }
    function sentView(snap2) {
      var me = snap2.me || {};
      var sel = me.selected || picked;
      var picks = el("div", { class: "picks" }, sel.map(function (k) { return el("span", { class: "badge", "data-k": k }, [L.shape(k)]); }));
      var waitTxt = el("p", { text: "" });
      var card = el("div", { class: "sent ticket pop" }, [el("span", { class: "hole" }), el("h2", { text: "Odpowiedź przyjęta" }), picks, waitTxt]);
      function upd(sn) { waitTxt.textContent = "Czekamy na resztę sali · " + (sn.session.answered || 0) + " z " + (sn.session.joined || 0); }
      upd(snap2);
      L.clear(view); view.appendChild(viewOf([head, card]));
      return upd;
    }
    var sentUpd = null, shownDeadline = q.deadline_at;
    return {
      node: box,
      mount: function () {
        if (snap.session.paused || q.paused) applyPause(snap); else { setFuse(true, q.deadline_at, total); clock(q.deadline_at); }
        if (snap.me && snap.me.answered) sentUpd = sentView(snap);
      },
      update: function (snap2) {
        var wasPaused = paused;
        if (snap2.question && snap2.question.deadline_at !== q.deadline_at) q.deadline_at = snap2.question.deadline_at;
        if (snap2.session.paused || wasPaused) applyPause(snap2);
        else if (snap2.question && snap2.question.deadline_at && snap2.question.deadline_at !== shownDeadline) { setFuse(true, q.deadline_at, total); clock(q.deadline_at); }
        shownDeadline = q.deadline_at;
        if (snap2.me && snap2.me.answered) { if (!sentUpd) sentUpd = sentView(snap2); else sentUpd(snap2); }
      },
      destroy: function () {}
    };
  }

  /* ----- odsłonięcie: pieczątka ----- */
  function revealView(seat, snap) {
    setFuse(false); clock(null);
    var me = snap.me || {}, r = snap.reveal || { correct_keys: [] }, q = snap.question || { answers: [] };
    var kind = me.correct === true ? ["ok", "Trafione", "pełna poprawność"] : me.partial ? ["part", "Częściowo", "część poprawnych"]
      : me.correct === false ? ["no", "Pudło", "tym razem nie"] : ["none", "Bez odpowiedzi", "czas minął"];
    var stamp = el("div", { class: "stamp slam " + kind[0] }, [kind[1], el("small", { text: kind[2] })]);
    var ptsN = el("span", { text: "0" });
    var pts = el("div", { class: "pts num" + (me.points ? "" : " zero") }, ["+", ptsN]);
    var sum = el("div", { class: "sum" }, ["Razem ", el("b", { class: "num", text: L.fmt(me.total || 0) }), " pkt" + (me.place ? " · miejsce " : ""), me.place ? el("b", { class: "num", text: String(me.place) }) : null]);
    var keys = el("div", { class: "keys" });
    var mine = me.selected || [];
    (q.answers || []).forEach(function (a, i) {
      var ok = (r.correct_keys || []).indexOf(a.key) >= 0, my = mine.indexOf(a.key) >= 0;
      if (!ok && !my) return;
      keys.appendChild(el("div", { class: "k rise" + (ok ? " ok" : ""), "data-k": a.key, style: { "--d": (0.6 + i * 0.08).toFixed(2) + "s" } }, [
        el("span", { class: "badge" }, [L.shape(a.key)]), el("span", { text: a.text || L.LETTERS[a.key] }),
        el("span", { class: "mine", text: ok && my ? "✓ Twoja" : ok ? "poprawna" : "Twoja" })]));
    });
    var parts = [el("div", { class: "verdict" }, [stamp, pts, sum]), keys];
    if (r.curiosity) parts.push(el("div", { class: "curio ticket rise", style: { "--d": "1s" } }, [el("span", { class: "eyebrow", text: "Ciekawostka" }), r.curiosity]));
    return {
      node: viewOf(parts),
      mount: function () {
        if (navigator.vibrate) navigator.vibrate(me.correct ? [20, 60, 20] : 40);
        setTimeout(function () { L.countUp(ptsN, me.points || 0, 800); }, 450);
      },
      update: function () {}
    };
  }

  /* ----- ranking ----- */
  function placeCard(you, total, label) {
    return el("div", { class: "place ticket pop" }, [
      el("span", { class: "big num", text: you && you.place ? String(you.place) : "-" }),
      el("div", { class: "meta" }, [el("span", { class: "eyebrow", text: label }), el("b", { text: you && you.place ? "miejsce z " + total : "miejsce ukryte" }),
        el("span", { text: L.fmt((you && you.score) || 0) + " pkt" })])
    ]);
  }
  function rows(top) {
    return el("div", { class: "rows" }, (top || []).map(function (r, i) {
      return el("div", { class: "r" + (r.you ? " you" : ""), style: { "--d": (0.25 + i * 0.05).toFixed(2) + "s" } }, [
        el("span", { class: "pl num", text: String(r.place) }), el("span", { class: "nm", text: r.name + (r.you ? " (Ty)" : "") }), el("span", { class: "sc num", text: L.fmt(r.score) })]);
    }));
  }
  function boardView(seat, snap) {
    setFuse(false); clock(null);
    var b = snap.leaderboard, me = snap.me || {}, s = snap.session;
    if (!b) {
      return { node: viewOf([el("div", { class: "card center stack pop" }, [el("span", { class: "eyebrow", text: "Po pytaniu " + (s.q_index + 1) + " z " + s.q_total }),
        el("div", { class: "big-title display", text: "Ranking po ostatnim pytaniu" }), el("p", { class: "note", text: "Masz " + L.fmt(me.total || 0) + " pkt. Za chwilę następne pytanie." })])]), update: function () {} };
    }
    return { node: viewOf([placeCard(b.you, b.total_players, "Po pytaniu " + (s.q_index + 1) + " z " + s.q_total), el("span", { class: "eyebrow", text: "Najlepsi" }), rows(b.top)]), update: function () {} };
  }

  /* ----- koniec ----- */
  function endView(seat, snap) {
    setFuse(false); clock(null);
    if (wake) { wake.release(); wake = null; }
    var f = snap.final || {}, you = f.you, b = snap.leaderboard, user = seat.kind !== "guest";
    var parts = [];
    if (f.character === "exam" && you) {
      parts.push(el("div", { class: "verdict" }, [
        el("div", { class: "stamp slam " + (you.passed ? "ok" : "no") }, [you.passed ? "Zaliczony" : "Niezaliczony", el("small", { text: "próg " + f.pass_percent + "%" })]),
        el("div", { class: "pts num", text: L.pct(you.percent || 0) }),
        el("div", { class: "sum" }, ["Poprawne: ", el("b", { class: "num", text: String(you.correct || 0) }), " z " + (f.question_count || 0) + " · odpowiedzi: " + (you.answered || 0)])
      ]));
    } else {
      parts.push(el("div", { class: "verdict" }, [el("div", { class: "stamp slam ok" }, ["Koniec", el("small", { text: "dziękujemy za grę" })])]));
      if (you) parts.push(placeCard({ place: you.place, score: you.score }, f.participants || 0, "Wynik końcowy"));
      if (b && b.top && b.top.length) { parts.push(el("span", { class: "eyebrow", text: "Najlepsi" })); parts.push(rows(b.top)); }
    }
    parts.push(el("p", { class: "note center", text: user ? "Wynik zapisany w historii Twojego konta BAZY." : "Grałeś jako gość - wynik nie trafia na konto." }));
    parts.push(el("button", { class: "btn ghost", type: "button", text: "Zamknij", onclick: function () {
      L.writeJSON(SEAT, null); if (client) client.stop(); history.replaceState(null, "", "/exam-live/join"); peekData = null; $("crest").textContent = ""; pinView(); } }));
    return { node: viewOf(parts), update: function () {} };
  }

  /* ================= start ================= */
  (function boot() {
    var ref = refFromUrl(), seat = L.readJSON(SEAT);
    if (seat && seat.sid && (!ref || sameRef(seat.ref, ref)) && (seat.kind === "guest" ? seat.gt : auth())) { live(seat, null); return; }
    if (ref) { peek(ref).then(null, function (e) { pinView(e.message); }); return; }
    pinView();
  })();
  void lastSnap;
})();
