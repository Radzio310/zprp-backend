/* Egzamin na żywo - rzutnik. Strona bez logowania: dostęp przez token sesji z adresu. */
(function () {
  "use strict";
  var el = Live.el, clear = Live.clear;
  var token = location.pathname.split("/").filter(Boolean).pop();
  var stage = document.getElementById("stage");
  var cur = { key: null, ui: null, ring: null, deadline: null, total: 1 };

  /* ----- pomocnicze ----- */
  function setHead(s) {
    document.getElementById("title").textContent = s.title;
    document.getElementById("eyebrow").textContent = "BAZA · " + Live.charLabel(s.character);
    document.title = s.title + " - rzutnik";
    var chip = document.getElementById("pinchip");
    chip.hidden = s.phase === "lobby" || s.phase === "end";
    document.getElementById("pinval").textContent = s.pin || "";
  }

  function qHead(snap, withRing) {
    var q = snap.question, s = snap.session;
    var bar = el("i");
    var head = el("div", { class: "qhead" }, [
      el("div", { class: "meta" }, [
        el("span", { class: "num", text: "Pytanie " + (q.index + 1) + " z " + q.total + (q.number ? "  ·  przepis " + q.number : "") }),
        el("div", { class: "progress" }, [bar]),
        el("span", { class: "skipnote", text: "" })
      ])
    ]);
    var note = head.querySelector(".skipnote");
    var ringEl = null;
    if (withRing) { ringEl = Live.ring(); head.appendChild(ringEl); }
    function setAnswered(snap2) {
      var n = snap2.session.answered || 0, all = snap2.session.joined || 0;
      bar.style.width = (all ? Math.min(100, (n / all) * 100) : 0) + "%";
      note.textContent = "Odpowiedzi: " + n + " z " + all;
    }
    setAnswered(snap);
    return { node: head, ringEl: ringEl, setAnswered: setAnswered };
  }

  function questionCard(q) {
    var card = el("div", { class: "glass qcard" }, [el("p", { text: q.text || "" })]);
    if (q.multi) card.appendChild(el("span", { class: "hint", text: "Zaznacz wszystkie poprawne odpowiedzi" }));
    return card;
  }

  /* ----- fazy ----- */
  function buildLobby(snap) {
    var s = snap.session;
    var pinRow = el("div", { class: "pin" });
    String(s.pin).split("").forEach(function (d, i) { pinRow.appendChild(el("span", { text: d, style: { "animation-delay": (i * 0.09) + "s" } })); });
    var url = location.origin + (s.links && s.links.join_page || "/exam-live/join");
    var steps = el("ul", { class: "steps" }, [
      el("li", null, [el("b", { text: "1." }), el("span", { text: "W aplikacji BAZA wybierz Egzamin na żywo i wpisz kod PIN" })])
    ]);
    var guestLi = el("li", null, [el("b", { text: "2." }), el("span", { text: "Albo zeskanuj kod QR telefonem" })]);
    steps.appendChild(guestLi);
    var guestNote = el("li", null, [el("b", { text: "3." }), el("span")]);
    guestNote.lastChild.appendChild(document.createTextNode("Bez aplikacji: "));
    guestNote.lastChild.appendChild(el("code", { text: url.replace(/^https?:\/\//, "") }));
    steps.appendChild(guestNote);
    var qr = el("div", { class: "qr" }, [el("img", { src: s.links.qr_url, alt: "Kod QR do dołączenia", width: "300", height: "300" })]);
    var joinCard = el("section", { class: "glass join-card" }, [
      el("span", { class: "eyebrow", text: "Dołącz do sesji" }),
      el("p", { class: "lead", text: s.character === "exam" ? "Kod egzaminu na sali" : "Wpisz kod PIN, żeby zagrać" }),
      pinRow,
      el("div", { class: "join-row" }, [qr, steps])
    ]);
    var countB = el("b", { text: "0" });
    var chips = el("div", { class: "chips" });
    var crowd = el("section", { class: "glass crowd" }, [
      el("span", { class: "eyebrow", text: "Na sali" }),
      el("div", { class: "count" }, [countB, el("span", { class: "muted", text: "uczestników" })]),
      chips
    ]);
    var node = el("div", { class: "lobby phase" }, [joinCard, crowd]);
    var seen = {};
    var ui = {
      node: node,
      update: function (snap2) {
        var s2 = snap2.session;
        countB.textContent = String(s2.joined);
        guestNote.style.display = s2.guests_allowed ? "" : "none";
        (snap2.participants || []).forEach(function (p) {
          var k = p.kind + ":" + p.name;
          if (seen[k]) return;
          seen[k] = true;
          chips.appendChild(el("span", { class: "chip" + (p.kind === "guest" ? " guest" : ""), text: p.name }));
        });
        var ph = chips.querySelector(".ph");
        if (s2.joined === 0 && !ph) chips.appendChild(el("span", { class: "muted ph", text: "Czekamy na pierwszych uczestników..." }));
        if (s2.joined > 0 && ph) chips.removeChild(ph);
      }
    };
    return ui;
  }

  function buildQuestion(snap) {
    var q = snap.question;
    var head = qHead(snap, true);
    cur.ring = head.ringEl; cur.deadline = q.deadline_at; cur.total = q.time_s;
    var tiles = Live.renderTiles(q, {});
    var node = el("div", { class: "stage-inner phase" }, [head.node, questionCard(q), tiles]);
    return { node: node, update: function (s2) { head.setAnswered(s2); cur.deadline = s2.question && s2.question.deadline_at; } };
  }

  function buildReveal(snap) {
    var q = snap.question, r = snap.reveal;
    var head = qHead(snap, false);
    head.node.querySelector(".skipnote").textContent = "Poprawnych: " + r.correct_count + " z " + snap.session.joined + (r.skipped ? "  ·  bez odpowiedzi: " + r.skipped : "");
    var max = Math.max(1, Math.max.apply(null, Object.keys(r.distribution).map(function (k) { return r.distribution[k]; })));
    var tiles = el("div", { class: "tiles" });
    q.answers.forEach(function (a) {
      var ok = r.correct_keys.indexOf(a.key) >= 0;
      var n = r.distribution[a.key] || 0;
      var bar = el("i", { class: "bar" });
      var kids = [Live.shape(a.key), el("span", { class: "tx", text: a.text || "" })];
      if (ok) kids.push(el("span", { class: "tick", text: "✓" }));
      kids.push(el("span", { class: "count", text: String(n) }));
      kids.push(bar);
      var tile = el("button", { class: "tile" + (ok ? " right" : " dim"), "data-k": a.key, type: "button", disabled: true }, kids);
      tiles.appendChild(tile);
      setTimeout(function () { bar.style.width = (n / max) * 100 + "%"; }, 150);
    });
    var node = el("div", { class: "stage-inner phase" }, [head.node, questionCard(q), tiles]);
    if (r.curiosity) node.appendChild(el("div", { class: "fact" }, [el("b", { text: "Warto wiedzieć: " }), document.createTextNode(r.curiosity)]));
    return { node: node, update: function () {} };
  }

  function buildLeaderboard(snap) {
    var s = snap.session, b = snap.leaderboard;
    var last = s.q_index >= s.q_total - 1;
    var node = el("div", { class: "center phase" }, [
      el("span", { class: "eyebrow", style: { "text-align": "center" }, text: last ? "Ranking końcowy po ostatnim pytaniu" : "Ranking po pytaniu " + (s.q_index + 1) + " z " + s.q_total }),
      el("h2", { text: last ? "Wyniki" : "Czołówka" }),
      Live.renderBoard(b.top, {}),
      el("span", { class: "muted", style: { "text-align": "center" }, text: "Uczestników: " + b.total_players })
    ]);
    return { node: node, update: function () {} };
  }

  function buildEnd(snap) {
    var f = snap.final || {}, b = snap.leaderboard || { top: [] };
    var podiumRows = b.top.filter(function (r) { return r.place <= 3; }).slice(0, 3);
    var rest = b.top.filter(function (r) { return r.place > 3; });
    var node = el("div", { class: "center phase" }, [el("h2", { text: snap.session.character === "exam" ? "Egzamin zakończony" : "Koniec quizu" })]);
    if (f.character === "exam" && f.pass_percent != null) {
      node.appendChild(el("div", { class: "verdict" }, [el("div", { class: "paper" }, [
        el("span", { class: "stamp ok", text: "Zaliczyło " + (f.passed || 0) + " z " + f.participants }),
        el("p", { text: "Próg zaliczenia: " + f.pass_percent + "%" })
      ])]));
    } else if (podiumRows.length) {
      var order = [podiumRows[1], podiumRows[0], podiumRows[2]].filter(Boolean);
      var pod = el("div", { class: "podium" });
      order.forEach(function (r) {
        pod.appendChild(el("div", { class: "step s" + Math.min(3, r.place) }, [el("b", { text: String(r.place) }), el("span", { text: r.name }), el("em", { text: String(r.score) })]));
      });
      node.appendChild(pod);
    }
    if (rest.length) node.appendChild(Live.renderBoard(rest, {}));
    else if (f.character === "exam" && b.top.length) node.appendChild(Live.renderBoard(b.top, {}));
    return { node: node, update: function () {} };
  }

  var BUILDERS = { lobby: buildLobby, question: buildQuestion, reveal: buildReveal, leaderboard: buildLeaderboard, end: buildEnd };

  function render(snap) {
    var s = snap.session;
    setHead(s);
    var key = s.phase + ":" + s.q_index;
    if (key !== cur.key) {
      cur.key = key; cur.ring = null;
      var ui = BUILDERS[s.phase](snap);
      clear(stage).appendChild(ui.node);
      cur.ui = ui;
    }
    cur.ui.update(snap);
  }

  /* ----- licznik czasu (zegar serwera) ----- */
  function loop() {
    if (cur.ring && cur.deadline) cur.ring.update(Live.secondsLeft(cur.deadline), cur.total);
    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);

  /* ----- połączenie ----- */
  var connEl = document.getElementById("conn"), connText = document.getElementById("connText");
  var labels = { live: "na żywo", poll: "tryb awaryjny", off: "brak sieci" };
  var client = new Live.LiveClient({
    stateUrl: function (since) { return "/exam-live/projector/" + token + "/state" + (since != null ? "?since_rev=" + since : ""); },
    wsUrl: function () { return Live.wsBase() + "/exam-live/ws/" + token + "?role=projector"; },
    onSnapshot: render,
    onStatus: function (st) { connEl.className = "conn " + (st === "live" ? "" : st); connText.textContent = labels[st] || st; },
    onFatal: function (e) {
      cur.key = "err";
      clear(stage).appendChild(el("div", { class: "err glass phase", style: { padding: "2rem" } }, [el("h2", { text: "Nie można pokazać sesji" }), el("p", { class: "muted", text: e.message || "Sprawdź adres rzutnika." })]));
    }
  });
  client.start();

  /* ----- ekran: nie gasnąć, pełny ekran, ukrywanie kursora ----- */
  var lock = null;
  function wake() {
    try { if (navigator.wakeLock && document.visibilityState === "visible") navigator.wakeLock.request("screen").then(function (l) { lock = l; }).catch(function () {}); } catch (e) {}
  }
  wake();
  document.addEventListener("visibilitychange", wake);
  function fullscreen() {
    try { if (document.fullscreenElement) document.exitFullscreen(); else document.documentElement.requestFullscreen(); } catch (e) {}
  }
  document.getElementById("fs").addEventListener("click", fullscreen);
  document.addEventListener("keydown", function (e) { if (e.key === "f" || e.key === "F") fullscreen(); });
  var idleT;
  function awake() { document.body.classList.remove("idle"); clearTimeout(idleT); idleT = setTimeout(function () { document.body.classList.add("idle"); }, 4000); }
  document.addEventListener("mousemove", awake); awake();
})();
