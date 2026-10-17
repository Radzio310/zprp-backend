/* Egzamin na żywo - rzutnik (17.10.2026). Strona bez logowania: dostęp przez token rzutnika z adresu.

   Sceny: lobby (kod QR budowany z kropek, PIN na biletach, wejścia nicków), pytanie (lont czasu,
   zegar, licznik odpowiedzi), odsłonięcie (rozkład, pieczątki trafień, ciekawostka), ranking (podium),
   koniec (podium albo zbiorcze „zaliczyło X z Y" na egzaminie). Każda faza to osobna scena;
   zmiana fazy = przenikanie dwóch warstw (jak zwrotki w Communio). Bez dźwięku.

   Skalowanie: scena 16:9 wpisana w ekran, wszystkie wymiary w cqh. Długie teksty (pytanie,
   odpowiedzi, adres) dopasowują krój wyszukiwaniem połówkowym - adres nigdy nie jest ucięty. */
(function () {
  "use strict";
  var L = window.Live, el = L.el, svg = L.svg, $ = L.$;
  var token = decodeURIComponent(location.pathname.split("/").filter(Boolean).pop() || "");
  var enc = encodeURIComponent;
  var stage = $("stage"), zoom = $("zoom");
  var brand = null, cur = null, last = null, crestImgs = [], zoomOn = false, ended = false;

  L.hall();

  /* ----- motyw: ciemny domyślnie, jasny na jasne sale (L) ----- */
  var theme = L.readJSON("bazaLive.projTheme") === "light" ? "light" : "dark";
  function applyTheme() {
    document.body.classList.toggle("light", theme === "light");
    $("themeTxt").textContent = theme === "light" ? "Ciemny" : "Jasny";
  }
  function toggleTheme() { theme = theme === "light" ? "dark" : "light"; L.writeJSON("bazaLive.projTheme", theme); applyTheme(); }
  applyTheme();

  /* ----- ekran nie gaśnie (Screen Wake Lock), a bez niego podpowiedź o wygaszaczu ----- */
  var wake = L.keepAwake();
  if (!("wakeLock" in navigator)) $("startHint").textContent = "albo F · ta przeglądarka nie blokuje uśpienia: wyłącz wygaszacz ekranu";

  function cq(n) { return (stage.clientHeight / 100) * n; }
  function mood(m) { if (m) document.body.setAttribute("data-mood", m); else document.body.removeAttribute("data-mood"); }

  /* ----- marka: qr.json niesie barwy, herb i macierz kodu ----- */
  function loadBrand() {
    fetch("/exam-live/projector/" + enc(token) + "/qr.json", { cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (!j) return;
        brand = j; L.applyPalette(j.palette);
        crestImgs.forEach(function (img) { img.src = j.crest_url; });
        if (cur && cur.onBrand) cur.onBrand();
      })
      .catch(function () { setTimeout(loadBrand, 3000); });
  }

  function crestNode(cls) {
    var img = el("img", { alt: "", src: brand ? brand.crest_url : null, decoding: "async" });
    crestImgs.push(img);
    if (crestImgs.length > 40) crestImgs.splice(0, crestImgs.length - 40);
    return el("span", { class: "crest " + (cls || "") }, [img]);
  }

  function joinHost() { return location.host; }

  /* ----- wspólne klocki ----- */
  function brandbar(s, extra) {
    return el("div", { class: "brandbar" }, [
      crestNode(),
      el("div", { class: "who" }, [
        el("span", { class: "eyebrow accent", text: "BAZA · " + L.charLabel(s.character) + (brand && brand.province_label ? " · " + brand.province_label : "") }),
        el("span", { class: "ttl", text: s.title || "Egzamin z przepisów" })
      ])
    ].concat(extra || []));
  }

  function pinRow(pin, animate) {
    var row = el("div", { class: "pinrow", "aria-label": "Kod PIN " + pin }, [el("span", { class: "lab", text: "KOD PIN" })]);
    var digits = [];
    String(pin || "").split("").forEach(function (ch, i) {
      if (i === 3) row.appendChild(el("span", { class: "sep" }));
      var d = el("span", { class: "digit ticket display num", text: ch, style: { "--d": animate ? (0.25 + i * 0.08 + Math.random() * 0.05).toFixed(2) + "s" : "0s" } });
      digits.push(d); row.appendChild(d);
    });
    row.tick = function () {
      var d = digits[Math.floor(Math.random() * digits.length)];
      if (!d) return;
      d.classList.remove("tick"); void d.offsetWidth; d.classList.add("tick");
    };
    return row;
  }

  function linkLine() {
    var url = el("span", { class: "url" }, [joinHost(), el("em", { text: "/exam-live/join" })]);
    var line = el("div", { class: "linkline" }, [el("span", { class: "or", text: "albo wejdź na" }), el("div", { class: "box" }, [url])]);
    line.fit = function () { L.fitLine(url, cq(3.2), cq(1.1)); };
    return line;
  }

  function sealNode() {
    var id = "seal" + Math.floor(Math.random() * 1e6);
    var ring = svg("svg", { viewBox: "0 0 200 200", "aria-hidden": "true" }, [
      svg("defs", null, [svg("path", { id: id, d: "M32 100a68 68 0 1 1 136 0a68 68 0 1 1 -136 0" })]),
      svg("circle", { cx: 100, cy: 100, r: 94, fill: "none", stroke: "currentColor", "stroke-width": 5 }),
      svg("circle", { cx: 100, cy: 100, r: 85, fill: "none", stroke: "currentColor", "stroke-width": 1.6 }),
      svg("circle", { cx: 100, cy: 100, r: 52, fill: "none", stroke: "currentColor", "stroke-width": 1.6, "stroke-dasharray": "2 5" }),
      svg("text", { fill: "currentColor", "font-size": 14.5, "font-weight": 800, "letter-spacing": 2.4, "font-family": "system-ui, sans-serif" },
        [svg("textPath", { href: "#" + id, text: "EGZAMIN Z PRZEPISÓW · NA ŻYWO · BAZA · " })]),
      svg("text", { x: 100, y: 96, fill: "currentColor", "font-size": 30, "font-weight": 900, "text-anchor": "middle", "font-family": "Georgia, serif", text: "ZPRP" }),
      svg("text", { x: 100, y: 122, fill: "currentColor", "font-size": 12, "font-weight": 800, "text-anchor": "middle", "letter-spacing": 1.5,
        "font-family": "system-ui, sans-serif", text: new Date().toLocaleDateString("pl-PL") })
    ]);
    return el("div", { class: "seal slam" }, [ring]);
  }

  function foot(s) {
    var right = s.late_join && !s.locked && s.phase !== "end" && s.pin
      ? el("span", { class: "join" }, ["Spóźnieni: PIN ", el("b", { class: "num", text: String(s.pin).slice(0, 3) + " " + String(s.pin).slice(3) }), " · " + joinHost() + "/exam-live/join"])
      : el("span");
    return el("div", { class: "foot" }, [el("span", { text: "BAZA · Egzamin z przepisów" }), right]);
  }

  /* ================= LOBBY ================= */
  function lobbyScene(snap) {
    var s = snap.session, stops = [];
    var node = el("div", { class: "scene lobby" });
    node.appendChild(brandbar(s));
    var h1 = el("h1", { class: "display", text: s.title || "Egzamin z przepisów" });
    var hbox = el("div", { style: { height: "15.5cqh", display: "flex", "align-items": "flex-end" } }, [h1]);
    var lead = el("p", { class: "lead", text: s.character === "exam"
      ? "Egzamin na sali. W aplikacji BAZA wybierz Egzamin na żywo i wpisz kod - albo zeskanuj kod telefonem."
      : "Quiz na żywo. W aplikacji BAZA wybierz Egzamin na żywo i wpisz kod - albo zeskanuj kod telefonem." });
    var pins = pinRow(s.pin, true);
    var link = linkLine();
    var countB = el("b", { class: "num display", text: "0" });
    var countS = el("span", { text: "" });
    var chips = el("div", { class: "chips" });
    var left = el("div", { class: "left" }, [hbox, lead, pins, link, el("div", { class: "crowd" }, [el("div", { class: "count" }, [countB, countS]), chips])]);
    node.appendChild(left);

    var qrSlot = el("div", { class: "qr" });
    var card = el("div", { class: "qrcard ticket", role: "button", tabindex: "0", title: "Powiększ kod (Q)", onclick: function () { openZoom(); } }, [
      qrSlot, el("div", { class: "perf" }),
      el("div", { class: "stub" }, [
        el("div", null, [el("div", { class: "eyebrow", text: "Zeskanuj aparatem" }), el("div", { class: "scan", text: "i jesteś na sali" })]),
        L.shape("e")
      ])
    ]);
    card.appendChild(el("div", { class: "lockstamp" }, [el("div", { class: "stamp no" }, ["Sala zamknięta", el("small", { text: "nowe osoby nie wejdą" })])]));
    node.appendChild(card);
    var qr = null;
    function placeQr() {
      if (!brand || qr) return;
      qr = L.qrNode(brand, { build: true });
      card.replaceChild(qr, qrSlot);
    }

    /* nicki: ostatnie wejścia jako bilety, starsze zwijają się w „+N" */
    var shown = {}, CAP = 22;
    function syncNames(snap2) {
      var s2 = snap2.session, list = snap2.participants || [];
      L.countUp(countB, s2.joined, 700);
      countS.textContent = s2.joined === 0 ? "Czekamy na pierwszą osobę" : L.plural(s2.joined, "osoba na sali", "osoby na sali", "osób na sali");
      var recent = list.slice(-CAP), keep = {}, fresh = 0;
      recent.forEach(function (p) { keep[p.kind + ":" + p.name] = true; });
      Object.keys(shown).forEach(function (k) { if (!keep[k]) { shown[k].remove(); delete shown[k]; } });
      Array.prototype.slice.call(chips.querySelectorAll(".ghost, .more")).forEach(function (n) { n.remove(); });
      var more = s2.joined - recent.length;
      if (more > 0) chips.insertBefore(el("span", { class: "chip more num", text: "+" + more }), chips.firstChild);
      recent.forEach(function (p) {
        var k = p.kind + ":" + p.name;
        if (shown[k]) return;
        var chip = el("span", { class: "chip " + (p.kind === "guest" ? "guest" : "user ticket"), text: p.name, title: p.kind === "guest" ? "Gość" : "Konto BAZY",
          style: { "--d": (fresh++ * 0.07).toFixed(2) + "s" } });
        shown[k] = chip; chips.appendChild(chip);
      });
      if (s2.joined === 0) for (var i = 0; i < 4; i++) chips.appendChild(el("span", { class: "chip ghost", style: { "--d": (i * 0.35).toFixed(2) + "s" } }));
    }

    return {
      node: node,
      mount: function () {
        placeQr(); syncNames(snap); this.fit(); card.classList.toggle("locked", !!snap.session.locked);
        stops.push(L.every(1800, 4600, function () { if (qr) qr.glint(); }));
        stops.push(L.every(3600, 8200, function () { pins.tick(); }));
        stops.push(L.every(7000, 13000, function () { var c = node.querySelector(".crest"); if (c) { c.classList.remove("shine"); void c.offsetWidth; c.classList.add("shine"); } }));
      },
      fit: function () { L.fit(h1, hbox, cq(7.4), cq(3.6)); link.fit(); },
      onBrand: function () { placeQr(); },
      update: function (snap2) { syncNames(snap2); card.classList.toggle("locked", !!snap2.session.locked); },
      destroy: function () { stops.forEach(function (f) { f(); }); }
    };
  }

  /* ----- powiększony kod: warstwa na poziomie sceny, nie w kafelku ----- */
  function openZoom() {
    if (!brand || !last) return;
    L.clear(zoom);
    var big = L.qrNode(brand, { build: true });
    var side = el("div", { class: "side" }, [
      el("span", { class: "eyebrow accent", text: "Dołącz do sesji" }),
      el("div", { class: "display", style: { font: "700 5cqh/1.1 var(--display)", "max-width": "60cqh" }, text: last.session.title || "" }),
      pinRow(last.session.pin, true),
      el("span", { class: "muted", style: { font: "600 2.2cqh/1.3 var(--sans)" }, text: joinHost() + "/exam-live/join" }),
      el("span", { class: "muted", style: { font: "500 1.7cqh/1.3 var(--sans)" }, text: "Kliknij albo Esc, żeby wrócić" })
    ]);
    zoom.appendChild(el("div", { class: "ticket" }, [big]));
    zoom.appendChild(side);
    zoom.classList.add("on"); zoom.setAttribute("aria-hidden", "false"); zoomOn = true;
  }
  function closeZoom() { zoom.classList.remove("on"); zoom.setAttribute("aria-hidden", "true"); zoomOn = false; }
  zoom.addEventListener("click", closeZoom);

  /* ================= PYTANIE / ODSŁONIĘCIE ================= */
  function tiles(q, reveal) {
    var n = (q.answers || []).length;
    var grid = el("div", { class: "answers n" + n + (reveal ? " static" : "") });
    var max = 1, parts = [];
    if (reveal) Object.keys(reveal.distribution || {}).forEach(function (k) { max = Math.max(max, reveal.distribution[k] || 0); });
    (q.answers || []).forEach(function (a, i) {
      var tx = el("span", { class: "tx", text: a.text || "" });
      var kids = [el("span", { class: "badge" }, [L.shape(a.key), el("span", { class: "ltr", text: L.LETTERS[a.key] || "" })]), tx];
      var tile = el("div", { class: "ans-tile", "data-k": a.key, style: { "--d": (0.15 + i * 0.09).toFixed(2) + "s" } });
      if (reveal) {
        var right = (reveal.correct_keys || []).indexOf(a.key) >= 0, cnt = reveal.distribution[a.key] || 0;
        tile.classList.add(right ? "right" : "wrong");
        var bar = el("i", { class: "bar", style: { "--bd": (0.35 + i * 0.08).toFixed(2) + "s" } });
        var num = el("span", { class: "cnt num", text: "0", style: { "--bd": (0.35 + i * 0.08).toFixed(2) + "s" } });
        tile.insertBefore(bar, tile.firstChild);
        kids.push(num);
        kids.push(el("span", { class: "tick", text: "✓", style: { "--td": (0.5 + i * 0.1).toFixed(2) + "s" } }));
        parts.push({ bar: bar, num: num, cnt: cnt, max: max });
      }
      kids.forEach(function (k) { tile.appendChild(k); });
      grid.appendChild(tile);
    });
    grid.reveal = function () {
      parts.forEach(function (p) {
        p.bar.style.transform = "scaleX(" + (p.cnt / Math.max(1, p.max)).toFixed(3) + ")";
        setTimeout(function () { L.countUp(p.num, p.cnt, 900); }, 380);
      });
    };
    grid.fit = function () {
      var txs = Array.prototype.slice.call(grid.querySelectorAll(".tx"));
      if (!txs.length) return;
      var lo = cq(1.7), hi = cq(3.6);
      function ok(px) {
        txs.forEach(function (t) { t.style.fontSize = px + "px"; });
        return txs.every(function (t) { var tile = t.parentNode; return tile.scrollHeight <= tile.clientHeight + 1 && t.scrollWidth <= t.clientWidth + 1; });
      }
      if (ok(hi)) return;
      for (var i = 0; i < 10; i++) { var m = (lo + hi) / 2; if (ok(m)) lo = m; else hi = m; }
      ok(lo);
    };
    return grid;
  }

  function qHead(q, s) {
    var meta = el("div", { class: "meta" }, [
      el("span", { class: "qn" }, ["Pytanie ", el("b", { class: "num", text: String(q.index + 1) }), " / " + q.total])
    ]);
    if (q.rule) meta.appendChild(el("span", { class: "pill", text: "Przepis " + q.rule }));
    if (q.multi) meta.appendChild(el("span", { class: "pill", text: "Kilka poprawnych" }));
    return el("div", { class: "qtop" }, [crestNode(), meta]);
  }

  function questionScene(snap) {
    var q = snap.question, s = snap.session;
    var node = el("div", { class: "scene question" });
    var fuseI = el("i"), fuse = el("div", { class: "fuse" }, [fuseI]);
    var sec = el("span", { class: "sec num" }), ansB = el("b", { class: "num", text: "0" }), meterI = el("i");
    var ansTxt = el("span", { class: "ans" }, [ansB, " z " + s.joined + " odpowiedzi"]);
    var pauseB = el("div", { class: "pausebadge", "aria-hidden": "true" }, [el("i"), el("i"), el("span", { text: "Wstrzymane" })]);
    var clock = el("div", { class: "clock" }, [sec, ansTxt, el("div", { class: "meter" }, [meterI])]);
    var p = el("p", { text: q.text || "" });
    var qbox = el("div", { class: "qbox" }, [p]);
    var grid = tiles(q, null);
    [fuse, qHead(q, s), clock, pauseB, qbox, grid, foot(s)].forEach(function (n) { node.appendChild(n); });
    var lastSec = null, total = q.time_s || 20, paused = false;

    /* Pauza prowadzącego: lont i zegar stoją na zamrożonej liczbie sekund, scena przygasa. */
    function applyPause(snap2) {
      var on = !!(snap2.session.paused || (snap2.question && snap2.question.paused));
      paused = on;
      node.classList.toggle("paused", on);
      if (!on) return;
      var left = (snap2.question && snap2.question.seconds_left) || 0;
      fuseI.style.transition = "transform .4s var(--out)";
      fuseI.style.transform = "scaleX(" + Math.min(1, left / total).toFixed(4) + ")";
      sec.textContent = String(Math.ceil(left)); lastSec = null;
      sec.classList.remove("hot"); fuse.classList.remove("hot"); mood(null);
    }
    function startFuse() {
      if (paused || !q.deadline_at) return;
      var left = L.secondsLeft(q.deadline_at);
      fuseI.style.transition = "none";
      fuseI.style.transform = "scaleX(" + Math.min(1, left / total).toFixed(4) + ")";
      void fuseI.offsetWidth;
      fuseI.style.transition = "transform " + left.toFixed(2) + "s linear";
      fuseI.style.transform = "scaleX(0)";
    }
    function answered(snap2) {
      var a = snap2.session.answered || 0, all = Math.max(1, snap2.session.joined || 0);
      L.countUp(ansB, a, 400);
      ansTxt.lastChild.textContent = " z " + (snap2.session.joined || 0) + " odpowiedzi";
      meterI.style.transform = "scaleX(" + Math.min(1, a / all).toFixed(3) + ")";
    }
    return {
      node: node, ticks: true,
      mount: function () { this.fit(); applyPause(snap); startFuse(); answered(snap); if (!paused) mood(null); },
      fit: function () { L.fit(p, qbox, cq(6.4), cq(2.6)); grid.fit(); },
      update: function (snap2) {
        applyPause(snap2);
        if (snap2.question && snap2.question.deadline_at !== q.deadline_at) { q.deadline_at = snap2.question.deadline_at; startFuse(); }
        answered(snap2);
      },
      tick: function () {
        if (paused || !q.deadline_at) return;
        var left = L.secondsLeft(q.deadline_at), whole = Math.ceil(left);
        if (whole === lastSec) return;
        lastSec = whole;
        sec.textContent = String(whole);
        var hot = left > 0 && left <= 5;
        sec.classList.toggle("hot", hot); fuse.classList.toggle("hot", hot);
        mood(hot ? "hot" : null);
        if (hot) { sec.classList.remove("beat"); void sec.offsetWidth; sec.classList.add("beat"); }
      },
      destroy: function () { mood(null); }
    };
  }

  function revealScene(snap) {
    var q = snap.question, s = snap.session, r = snap.reveal || { correct_keys: [], distribution: {}, answered: 0, skipped: 0, correct_count: 0 };
    var node = el("div", { class: "scene reveal" + (r.curiosity ? " with-curio" : "") });
    var p = el("p", { text: q.text || "" });
    var qbox = el("div", { class: "qbox" }, [p]);
    var grid = tiles(q, r);
    var good = el("b", { class: "num", text: "0" });
    var head = el("div", { class: "score-head" }, [good, el("span", { text: "poprawnie z " + (r.answered || 0) + " odpowiedzi" + (r.skipped ? " · " + r.skipped + " bez odpowiedzi" : "") })]);
    [qHead(q, s), head, qbox, grid].forEach(function (n) { node.appendChild(n); });
    if (r.curiosity) node.appendChild(el("div", { class: "curio ticket" }, [el("span", { class: "eyebrow", text: "Ciekawostka" }), el("p", { text: r.curiosity })]));
    else node.appendChild(foot(s));
    return {
      node: node,
      mount: function () {
        this.fit();
        setTimeout(function () { grid.classList.add("revealed"); node.classList.add("revealed"); grid.reveal(); }, 320);
        setTimeout(function () { L.countUp(good, r.correct_count || 0, 900); }, 500);
        var rate = (r.correct_count || 0) / Math.max(1, r.answered || 0);
        mood(r.answered && rate >= 0.6 ? "good" : null);
      },
      fit: function () { L.fit(p, qbox, cq(5.2), cq(2.4)); grid.fit(); },
      update: function () {},
      destroy: function () { mood(null); }
    };
  }

  /* ================= RANKING ================= */
  function podium(board, opts) {
    var top = (board && board.top) || [];
    var wrap = el("div", { class: "board scene-board" + (top.length <= 3 ? " solo" : "") });
    var heights = ["40cqh", "29cqh", "21cqh"];
    var order = [1, 0, 2].filter(function (i) { return i < top.length; });
    var pod = el("div", { class: "podium" });
    order.forEach(function (i, k) {
      var r = top[i], score = el("span", { class: "num", text: "0" });
      var step = el("div", { class: "step p" + (i + 1), style: { "--bd": (0.2 + (2 - i) * 0.35).toFixed(2) + "s", "--nd": (0.6 + (2 - i) * 0.35).toFixed(2) + "s" } }, [
        el("div", { class: "who ticket" }, [el("b", { text: r.name }), score]),
        el("div", { class: "block", style: { "--h": heights[i] } }, [el("span", { class: "pl num", text: String(r.place) })])
      ]);
      pod.appendChild(step);
      setTimeout(function () { L.countUp(score, r.score, 1100); }, (900 + (2 - i) * 350));
      void k;
    });
    wrap.appendChild(pod);
    if (top.length > 3) {
      var rest = el("div", { class: "rest" });
      top.slice(3).forEach(function (r, i) {
        rest.appendChild(el("div", { class: "rrow", style: { "--d": (1.4 + i * 0.07).toFixed(2) + "s" } }, [
          el("span", { class: "pl num", text: String(r.place) }), el("span", { class: "nm", text: r.name }), el("span", { class: "sc num", text: L.fmt(r.score) })
        ]));
      });
      wrap.appendChild(rest);
    }
    void opts;
    return wrap;
  }

  function boardScene(snap) {
    var s = snap.session, b = snap.leaderboard;
    var node = el("div", { class: "scene board" });
    node.appendChild(brandbar(s));
    if (!b || !(b.top || []).length) {
      var dots = el("div", { class: "dots" });
      for (var i = 0; i < s.q_total; i++) dots.appendChild(el("i", { class: i < s.q_index ? "done" : i === s.q_index ? "now" : "" }));
      node.appendChild(el("div", { class: "interlude" }, [
        el("span", { class: "eyebrow accent", text: "Pytanie " + (s.q_index + 1) + " z " + s.q_total + " za nami" }),
        el("h2", { class: "display", text: !b ? "Ranking pokażemy po ostatnim pytaniu" : "Jeszcze nikt nie zdobył punktów" }),
        dots, el("p", { text: "Za chwilę następne pytanie." })
      ]));
    } else {
      node.appendChild(el("h2", { class: "display", text: "Ranking po pytaniu " + (s.q_index + 1) + " z " + s.q_total }));
      node.appendChild(el("span", { class: "sub", text: (b.mode === "speed" ? "Punkty za poprawność i szybkość" : "Punkty za poprawność") + " · " + b.total_players + " " + L.plural(b.total_players, "osoba", "osoby", "osób") }));
      var pod = podium(b);
      while (pod.firstChild) node.appendChild(pod.firstChild);
      if ((b.top || []).length <= 3) node.classList.add("solo");
    }
    node.appendChild(foot(s));
    return { node: node, mount: function () { mood(null); }, update: function () {} };
  }

  /* ================= KONIEC ================= */
  function endScene(snap) {
    var s = snap.session, f = snap.final || {}, b = snap.leaderboard;
    var exam = (f.character || s.character) === "exam";
    var node = el("div", { class: "scene end" });
    var center = el("div", { class: "center" });
    if (exam) {
      var all = f.participants || 0, passed = f.passed || 0, frac = all ? passed / all : 0;
      var C = 2 * Math.PI * 44, fg;
      var ring = el("div", { class: "ring" }, [
        svg("svg", { viewBox: "0 0 100 100", class: "arc", "aria-hidden": "true" }, [
          svg("defs", null, [svg("linearGradient", { id: "arcg", x1: "0", y1: "0", x2: "1", y2: "1" }, [
            svg("stop", { offset: "0", "stop-color": "var(--p1)", style: { "stop-color": "var(--p1)" } }),
            svg("stop", { offset: "1", "stop-color": "var(--good)", style: { "stop-color": "var(--good)" } })])]),
          svg("circle", { class: "bg", cx: 50, cy: 50, r: 44, "stroke-width": 7 }),
          (fg = svg("circle", { class: "fg", cx: 50, cy: 50, r: 44, "stroke-width": 7, "stroke-dasharray": C.toFixed(2), "stroke-dashoffset": C.toFixed(2) }))
        ]),
        el("div", { class: "in" }, [el("b", { class: "num", text: "0" }), el("span", { text: "z " + all + " zaliczyło" })])
      ]);
      [crestNode("big"), el("span", { class: "eyebrow accent", text: "Egzamin zakończony" }), el("h1", { class: "display", text: s.title || "Egzamin z przepisów" }), ring,
        el("p", { class: "lead", text: "Próg zaliczenia " + (f.pass_percent != null ? f.pass_percent : s.pass_percent) + "% · " + (f.question_count || s.q_total) + " pytań · wyniki trafiły do komisji" })
      ].forEach(function (n) { center.appendChild(n); });
      node.appendChild(center);
      node.appendChild(sealNode());
      return {
        node: node,
        mount: function () {
          mood("end");
          setTimeout(function () { fg.style.strokeDashoffset = (C * (1 - frac)).toFixed(2); L.countUp(ring.querySelector(".in b"), passed, 1500); }, 700);
        },
        update: function () {}
      };
    }
    var hasBoard = b && (b.top || []).length;
    if (hasBoard) node.classList.add("withboard");
    [hasBoard ? null : crestNode("big"), el("span", { class: "eyebrow accent", text: "Koniec · " + (s.title || "Quiz") }),
      el("h1", { class: "display", text: hasBoard ? "Brawo! Oto najlepsi" : "Dziękujemy za wspólną grę" }),
      hasBoard ? null : el("p", { class: "lead", text: (f.participants || 0) + " " + L.plural(f.participants || 0, "osoba wzięła", "osoby wzięły", "osób wzięło") + " udział · " + (f.question_count || s.q_total) + " pytań" })
    ].forEach(function (n) { if (n) center.appendChild(n); });
    node.appendChild(center);
    if (hasBoard) {
      var pod = podium(b);
      while (pod.firstChild) node.appendChild(pod.firstChild);
      if ((b.top || []).length <= 3) node.classList.add("solo");
    }
    node.appendChild(sealNode());
    return { node: node, mount: function () { mood("end"); }, update: function () {} };
  }

  function fatalScene(e) {
    var gone = e && (e.status === 404 || e.code === "LIVE_NOT_FOUND");
    var node = el("div", { class: "scene" }, [el("div", { class: "fatal" }, [
      el("span", { class: "eyebrow accent", text: "BAZA · Egzamin na żywo" }),
      el("h1", { class: "display", text: gone ? "Tej sesji już nie ma" : "Nie mogę otworzyć rzutnika" }),
      el("p", { text: gone ? "Link rzutnika wygasł albo sesja została usunięta. Otwórz nowy link z aplikacji BAZA (Egzamin na żywo - Rzutnik)."
        : ((e && e.message) || "Sprawdź połączenie i odśwież stronę.") })
    ])]);
    return { node: node, mount: function () {}, update: function () {} };
  }

  /* ================= silnik scen ================= */
  function sceneKey(s) { return s.phase === "lobby" ? "lobby" : s.phase === "end" ? "end" : s.phase + ":" + s.q_index; }
  function build(snap) {
    var ph = snap.session.phase;
    if (ph === "lobby") return lobbyScene(snap);
    if (ph === "question" && snap.question) return questionScene(snap);
    if (ph === "reveal" && snap.question) return revealScene(snap);
    if (ph === "leaderboard") return boardScene(snap);
    if (ph === "end") return endScene(snap);
    return boardScene(snap);
  }
  function swap(next, key) {
    var old = cur;
    next.key = key;
    cur = next;
    stage.insertBefore(next.node, zoom);
    if (next.mount) next.mount();
    requestAnimationFrame(function () { requestAnimationFrame(function () { next.node.classList.add("on"); }); });
    var boot = $("boot");
    if (boot) { boot.classList.add("out"); setTimeout(function () { boot.remove(); }, 700); }
    if (old) {
      if (old.destroy) old.destroy();
      old.node.classList.remove("on"); old.node.classList.add("out");
      setTimeout(function () { old.node.remove(); }, 750);
    }
  }
  function render(snap) {
    last = snap;
    var s = snap.session;
    document.title = (s.title || "Egzamin") + " - rzutnik";
    var key = sceneKey(s);
    if (!cur || cur.key !== key) swap(build(snap), key);
    else if (cur.update) cur.update(snap);
    if (s.phase !== "lobby" && zoomOn && !s.late_join) closeZoom();
    if (s.phase === "end" && !ended) { ended = true; wake.release(); }
  }
  function fatal(e) { swap(fatalScene(e), "fatal"); }

  (function loop() {
    if (cur && cur.tick) cur.tick();
    requestAnimationFrame(loop);
  })();

  var client = new L.LiveClient({
    stateUrl: function (since) { return "/exam-live/projector/" + enc(token) + "/state" + (since != null && since >= 0 ? "?since_rev=" + since : ""); },
    wsUrl: function () { return L.wsBase() + "/exam-live/ws/" + enc(token) + "?role=projector"; },
    onSnapshot: render,
    onStatus: L.connPill($("conn")),
    onFatal: fatal
  });
  loadBrand();
  client.start();

  /* ----- pełny ekran, klawisze, kursor ----- */
  /* Duży przycisk startowy tylko na powitanie: po pierwszym użyciu albo po 8 s znika na dobre
     (pełny ekran ma wtedy przycisk w rogu), więc nigdy nie zasłania podium. */
  function hush() { document.body.classList.add("hush"); }
  setTimeout(hush, 8000);
  function full() {
    hush();
    var d = document;
    if (d.fullscreenElement || d.webkitFullscreenElement) (d.exitFullscreen || d.webkitExitFullscreen).call(d);
    else { var e = d.documentElement; (e.requestFullscreen || e.webkitRequestFullscreen).call(e); }
  }
  document.addEventListener("fullscreenchange", function () {
    var on = !!document.fullscreenElement;
    document.body.classList.toggle("full", on);
    $("fullTxt").textContent = on ? "Zamknij pełny ekran" : "Pełny ekran";
  });
  $("fullBtn").onclick = full; $("startBtn").onclick = full; $("themeBtn").onclick = toggleTheme;
  stage.addEventListener("dblclick", function (e) { if (!zoom.contains(e.target)) full(); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "f" || e.key === "F") { e.preventDefault(); full(); }
    else if (e.key === "l" || e.key === "L") toggleTheme();
    else if (e.key === "q" || e.key === "Q") { if (zoomOn) closeZoom(); else openZoom(); }
    else if (e.key === "Escape" && zoomOn) closeZoom();
  });
  var quiet = null;
  function moved() { document.body.classList.remove("quiet"); clearTimeout(quiet); quiet = setTimeout(function () { document.body.classList.add("quiet"); }, 2500); }
  document.addEventListener("mousemove", moved); document.addEventListener("mousedown", moved); moved();
  var rt = null;
  window.addEventListener("resize", function () { clearTimeout(rt); rt = setTimeout(function () { if (cur && cur.fit) cur.fit(); }, 120); });
})();
