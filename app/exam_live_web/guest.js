/* Egzamin na żywo - strona gościa (przeglądarka, bez konta). Dołączenie: PIN (albo QR) + nick. */
(function () {
  "use strict";
  var el = Live.el, clear = Live.clear;
  var stage = document.getElementById("stage");
  var parts = location.pathname.split("/").filter(Boolean);
  var urlToken = parts[1] === "join" && parts[2] ? parts[2] : "";
  var STORE = "examlive.guest";
  var me = null, client = null, cur = { key: null, ui: null, ring: null, deadline: null, total: 1 }, sending = false;

  function load() { try { return JSON.parse(localStorage.getItem(STORE) || "null"); } catch (e) { return null; } }
  function save(v) { try { if (v) localStorage.setItem(STORE, JSON.stringify(v)); else localStorage.removeItem(STORE); } catch (e) {} }

  function toast(msg) {
    var old = document.querySelector(".toast"); if (old) old.remove();
    var t = el("div", { class: "toast", role: "alert", text: msg });
    document.body.appendChild(t);
    setTimeout(function () { t.remove(); }, 5200);
  }

  function post(url, body) {
    return fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); });
  }
  function errText(res) { var d = (res.body && res.body.detail) || {}; return d.message || "Coś poszło nie tak. Spróbuj ponownie."; }

  /* ----- formularz dołączania ----- */
  function showJoin(note) {
    clear(stage);
    document.getElementById("title").textContent = "Dołącz do sesji";
    var pin = el("input", { class: "pin", inputmode: "numeric", autocomplete: "off", maxlength: "6", placeholder: "••••••", "aria-label": "Kod PIN" });
    var nick = el("input", { autocomplete: "nickname", maxlength: "24", placeholder: "Twój nick", "aria-label": "Nick" });
    var btn = el("button", { class: "btn", type: "button", text: "Dołącz" });
    var kids = [el("h2", { text: "Wejdź do gry" }), el("p", { class: "muted", text: note || "Wpisz kod PIN z ekranu prowadzącego i wybierz nick." })];
    if (!urlToken) { kids.push(el("label", { text: "Kod PIN" })); kids.push(pin); }
    kids.push(el("label", { text: "Nick" })); kids.push(nick); kids.push(btn);
    stage.appendChild(el("section", { class: "glass card phase" }, kids));
    pin.addEventListener("input", function () { pin.value = pin.value.replace(/\D/g, "").slice(0, 6); });
    function go() {
      btn.disabled = true;
      var body = urlToken ? { token: urlToken, nick: nick.value } : { pin: pin.value, nick: nick.value };
      post("/exam-live/guest/join", body).then(function (res) {
        btn.disabled = false;
        if (!res.ok) { toast(errText(res)); return; }
        me = { sid: res.body.session_id, gt: res.body.guest_token, name: res.body.name, ref: urlToken };
        save(me);
        begin(res.body.snapshot);
      }).catch(function () { btn.disabled = false; toast("Brak połączenia z serwerem. Sprawdź internet."); });
    }
    btn.addEventListener("click", go);
    nick.addEventListener("keydown", function (e) { if (e.key === "Enter") go(); });
    (urlToken ? nick : pin).focus();
  }

  /* ----- gra ----- */
  function begin(first) {
    if (client) client.closed = true;
    client = new Live.LiveClient({
      stateUrl: function (since) { return "/exam-live/guest/" + me.sid + "/state?gt=" + encodeURIComponent(me.gt) + (since != null ? "&since_rev=" + since : ""); },
      wsUrl: function () { return Live.wsBase() + "/exam-live/ws/" + me.sid + "?role=guest&gt=" + encodeURIComponent(me.gt); },
      onSnapshot: render,
      onStatus: function (st) {
        var c = document.getElementById("conn"); c.hidden = false; c.className = "conn " + (st === "live" ? "" : st);
      },
      onFatal: function (e) {
        save(null); me = null; cur.key = null;
        showJoin(e.message || "Ta sesja jest już niedostępna. Dołącz ponownie.");
      }
    });
    if (first) { client.apply(first); }
    client.start();
  }

  function head(snap) {
    document.getElementById("title").textContent = snap.session.title;
    document.getElementById("eyebrow").textContent = "BAZA · " + Live.charLabel(snap.session.character);
  }

  function qHead(q, snap) {
    var ringEl = Live.ring();
    var bar = el("i");
    var node = el("div", { class: "qhead" }, [
      el("div", { class: "meta" }, [el("span", { class: "muted", text: "Pytanie " + (q.index + 1) + " z " + q.total }), el("div", { class: "progress" }, [bar])]), ringEl]);
    bar.style.width = ((q.index + 1) / q.total * 100) + "%";
    return { node: node, ring: ringEl };
  }

  function answer(keys, ui) {
    if (sending) return;
    sending = true;
    post("/exam-live/guest/" + me.sid + "/answer", { gt: me.gt, selected: keys }).then(function (res) {
      sending = false;
      if (!res.ok) { toast(errText(res)); ui.unlock(); return; }
      client.apply(res.body.snapshot);
    }).catch(function () { sending = false; ui.unlock(); toast("Nie udało się wysłać odpowiedzi. Spróbuj jeszcze raz."); });
  }

  function buildLobby(snap) {
    var countB = el("span", { class: "big", text: "1" });
    var node = el("div", { class: "phase", style: { display: "grid", gap: "14px" } }, [
      el("section", { class: "glass card center" }, [el("span", { class: "eyebrow", text: "Jesteś w grze" }), el("h2", { text: snap.me ? snap.me.name : "" }),
        el("p", { class: "muted", text: "Poczekaj, aż prowadzący rozpocznie. Patrz na ekran na sali." })]),
      el("section", { class: "glass card center" }, [countB, el("p", { class: "muted", text: "uczestników na liście" })]),
      el("div", { class: "wait" }, [el("span", { class: "dot" }), el("span", { class: "dot" }), el("span", { class: "dot" })])
    ]);
    return { node: node, update: function (s2) { countB.textContent = String(s2.session.joined); } };
  }

  function buildQuestion(snap) {
    var q = snap.question, mine = snap.me || {};
    var h = qHead(q, snap);
    cur.ring = h.ring; cur.deadline = q.deadline_at; cur.total = q.time_s;
    var picked = (mine.selected || []).slice();
    var locked = !!mine.answered;
    var sendBtn = el("button", { class: "btn", type: "button", text: "Wyślij odpowiedź" });
    var tilesHost = el("div");
    var status = el("div", { class: "wait", hidden: !locked }, [el("b", { text: "Odpowiedź przyjęta" }), el("p", { class: "muted", text: "Poczekaj na odsłonięcie poprawnej odpowiedzi." })]);
    var ui = { unlock: function () { locked = false; draw(); } };
    function draw() {
      clear(tilesHost);
      var grid = Live.renderTiles(q, {
        selected: picked, locked: locked,
        onPick: function (key) {
          if (q.multi) {
            var i = picked.indexOf(key); if (i >= 0) picked.splice(i, 1); else picked.push(key);
            draw();
          } else { picked = [key]; locked = true; draw(); answer(picked, ui); }
        }
      });
      if (q.tiles_only) grid.classList.add("only");
      tilesHost.appendChild(grid);
      sendBtn.hidden = !(q.multi && !locked);
      sendBtn.disabled = picked.length === 0;
      status.hidden = !locked;
    }
    sendBtn.addEventListener("click", function () { locked = true; draw(); answer(picked, ui); });
    var kids = [h.node];
    if (q.tiles_only) kids.push(el("div", { class: "glass card center" }, [el("b", { text: "Patrz na ekran" }), el("p", { class: "muted", text: q.multi ? "Wybierz wszystkie poprawne kolory, potem wyślij." : "Stuknij kolor poprawnej odpowiedzi." })]));
    else { kids.push(el("div", { class: "glass qcard" }, [el("p", { text: q.text || "" })])); if (q.multi) kids.push(el("span", { class: "eyebrow", text: "Zaznacz wszystkie poprawne" })); }
    kids.push(tilesHost, sendBtn, status);
    var node = el("div", { class: "phase", style: { display: "grid", gap: "14px" } }, kids);
    draw();
    return { node: node, update: function (s2) { cur.deadline = s2.question && s2.question.deadline_at; if (s2.me && s2.me.answered && !locked) { locked = true; picked = (s2.me.selected || picked); draw(); } } };
  }

  function buildReveal(snap) {
    var q = snap.question, r = snap.reveal, m = snap.me || {};
    var banner;
    if (m.correct === true) banner = el("div", { class: "banner ok" }, ["Dobrze!", el("small", { text: "+" + m.points + " pkt  ·  razem " + m.total })]);
    else if (m.partial) banner = el("div", { class: "banner none" }, ["Częściowo", el("small", { text: "+" + m.points + " pkt  ·  razem " + m.total })]);
    else if (m.correct === false) banner = el("div", { class: "banner no" }, ["Niestety nie", el("small", { text: "Razem " + m.total + " pkt" })]);
    else banner = el("div", { class: "banner none" }, ["Brak odpowiedzi", el("small", { text: "Razem " + m.total + " pkt" })]);
    var grid = el("div", { class: "tiles" });
    q.answers.forEach(function (a) {
      var ok = r.correct_keys.indexOf(a.key) >= 0;
      var kids = [Live.shape(a.key), el("span", { class: "tx", text: a.text || "" })];
      if (ok) kids.push(el("span", { class: "tick", text: "✓" }));
      var t = el("button", { class: "tile" + (ok ? " right" : " dim") + ((m.selected || []).indexOf(a.key) >= 0 ? " sel" : ""), "data-k": a.key, type: "button", disabled: true }, kids);
      grid.appendChild(t);
    });
    var kids2 = [banner];
    if (m.place) kids2.push(el("p", { class: "center muted", text: "Twoje miejsce: " + m.place }));
    kids2.push(grid);
    if (r.curiosity) kids2.push(el("div", { class: "glass card" }, [el("b", { text: "Warto wiedzieć: " }), document.createTextNode(r.curiosity)]));
    return { node: el("div", { class: "phase", style: { display: "grid", gap: "14px" } }, kids2), update: function () {} };
  }

  function buildBoard(snap) {
    var b = snap.leaderboard, kids = [el("section", { class: "glass card center" }, [el("span", { class: "eyebrow", text: "Ranking" }), el("h2", { text: "Czołówka" })]), Live.renderBoard(b.top, {})];
    var inTop = b.top.some(function (r) { return r.you; });
    if (b.you && !inTop) kids.push(Live.renderBoard([{ place: b.you.place, name: b.you.name, score: b.you.score, you: true }], {}));
    return { node: el("div", { class: "phase", style: { display: "grid", gap: "14px" } }, kids), update: function () {} };
  }

  function buildEnd(snap) {
    var f = snap.final || {}, y = f.you, kids = [];
    if (f.character === "exam" && y) {
      kids.push(el("section", { class: "paper phase" }, [
        el("span", { class: "stamp " + (y.passed ? "ok" : "no"), text: y.passed ? "Zaliczono" : "Niezaliczono" }),
        el("p", { text: "Wynik: " + Live.pct(y.percent) + "  ·  próg " + f.pass_percent + "%" }),
        el("p", { class: "muted", text: "Poprawnych: " + y.correct + " z " + f.question_count })
      ]));
    } else if (y) {
      kids.push(el("section", { class: "glass card center" }, [el("span", { class: "eyebrow", text: "Twoje miejsce" }), el("div", { class: "big", text: String(y.place) }), el("p", { class: "muted", text: y.score + " pkt  ·  poprawnych " + y.correct + " z " + f.question_count })]));
    } else kids.push(el("section", { class: "glass card center" }, [el("h2", { text: "Koniec sesji" })]));
    if (snap.leaderboard && f.character !== "exam") kids.push(Live.renderBoard(snap.leaderboard.top, {}));
    kids.push(el("button", { class: "btn ghost", type: "button", text: "Zamknij", onclick: function () { save(null); if (client) client.closed = true; showJoin("Dziękujemy za udział!"); } }));
    return { node: el("div", { class: "phase", style: { display: "grid", gap: "14px" } }, kids), update: function () {} };
  }

  var BUILDERS = { lobby: buildLobby, question: buildQuestion, reveal: buildReveal, leaderboard: buildBoard, end: buildEnd };

  function render(snap) {
    head(snap);
    var s = snap.session, key = s.phase + ":" + s.q_index;
    if (key !== cur.key) {
      cur.key = key; cur.ring = null; sending = false;
      var ui = BUILDERS[s.phase](snap);
      clear(stage).appendChild(ui.node);
      cur.ui = ui;
    }
    cur.ui.update(snap);
  }

  function loop() { if (cur.ring && cur.deadline) cur.ring.update(Live.secondsLeft(cur.deadline), cur.total); requestAnimationFrame(loop); }
  requestAnimationFrame(loop);

  /* ----- start: wznowienie zapisanej tożsamości albo formularz ----- */
  var saved = load();
  if (saved && saved.sid && saved.gt && (!urlToken || saved.ref === urlToken)) { me = saved; begin(null); }
  else showJoin();
})();
