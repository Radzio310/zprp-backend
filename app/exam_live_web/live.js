/* Egzamin na żywo - wspólna biblioteka rzutnika i strony uczestnika (17.10.2026, bez zależności).

   ODPORNOŚĆ (wzorzec Communio „Śpiewajmy razem"): serwer trzyma stan i rozsyła MIGAWKĘ gniazdem.
   Strona (1) zaczyna od GET migawki, więc odświeżenie niczego nie gubi, (2) przy zerwanym gnieździe
   odpytuje GET co 2 s z ?since_rev (tanio), (3) łączy się ponownie z wykładniczym opóźnieniem,
   (4) po powrocie karty na wierzch pobiera stan od razu, (5) pigułka „Łączę ponownie…" dopiero po
   5 s ciszy - krótkie mrugnięcie sieci nie straszy sali.

   BEZPIECZEŃSTWO: wszystko od ludzi (nicki, nazwy, treści) trafia do DOM wyłącznie przez textContent.
   SVG budujemy przez createElementNS - żadnego innerHTML. */
(function () {
  "use strict";

  /* Przestrzeń nazw SVG składana z części: pliki stron nie mają w sobie pełnych adresów (test bez CDN). */
  var SVGNS = ["http:", "", "www.w3.org", "2000", "svg"].join("/");
  var REDUCED = !!(window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches);

  function el(tag, attrs, kids) {
    var node = document.createElement(tag);
    setAttrs(node, attrs);
    append(node, kids);
    return node;
  }
  function svg(tag, attrs, kids) {
    var node = document.createElementNS(SVGNS, tag);
    setAttrs(node, attrs);
    append(node, kids);
    return node;
  }
  function setAttrs(node, attrs) {
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v == null || v === false) return;
      if (k === "class") node.setAttribute("class", v);
      else if (k === "text") node.textContent = v;
      else if (k.slice(0, 2) === "on") node.addEventListener(k.slice(2), v);
      else if (k === "style" && typeof v === "object") Object.keys(v).forEach(function (s) { node.style.setProperty(s, v[s]); });
      else node.setAttribute(k, v === true ? "" : v);
    });
  }
  function append(node, kids) {
    (kids || []).forEach(function (kid) { if (kid != null && kid !== false) node.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid); });
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
  function $(id) { return document.getElementById(id); }

  /* ----- kształty odpowiedzi (te same co w aplikacji) ----- */
  var SHAPES = {
    a: ["path", { d: "M12 2.5 22 20.5H2z" }],
    b: ["path", { d: "M12 1.5 22.5 12 12 22.5 1.5 12z" }],
    c: ["circle", { cx: 12, cy: 12, r: 10 }],
    d: ["rect", { x: 3, y: 3, width: 18, height: 18, rx: 2 }],
    e: ["path", { d: "M12 1.8 14.9 8.6 22.2 9.2 16.6 14 18.4 21.2 12 17.4 5.6 21.2 7.4 14 1.8 9.2 9.1 8.6z" }],
    f: ["path", { d: "M12 2 21 7v10l-9 5-9-5V7z" }]
  };
  function shape(key, cls) {
    var s = SHAPES[key] || SHAPES.a;
    return el("span", { class: "shape " + (cls || "") }, [svg("svg", { viewBox: "0 0 24 24", "aria-hidden": "true" }, [svg(s[0], s[1])])]);
  }
  var LETTERS = { a: "A", b: "B", c: "C", d: "D", e: "E", f: "F" };

  /* ----- zegar serwera ----- */
  var offsetMs = 0;
  function syncClock(serverNow) { var t = Date.parse(serverNow); if (!isNaN(t)) offsetMs = t - Date.now(); }
  function serverMs() { return Date.now() + offsetMs; }
  function secondsLeft(deadlineIso) { var t = Date.parse(deadlineIso); return isNaN(t) ? 0 : Math.max(0, (t - serverMs()) / 1000); }

  /* ----- klient migawek ----- */
  function LiveClient(opts) {
    /* opts: {stateUrl(sinceRev|null), wsUrl(), auth() -> ramka auth|null, headers() -> {}, onSnapshot(s), onStatus("live"|"poll"|"off"), onFatal(e)} */
    this.opts = opts; this.rev = -1; this.ws = null; this.attempt = 0; this.timer = null; this.pollTimer = null; this.closed = false;
    this.lastPhase = null; this.offlineSince = null;
  }
  LiveClient.prototype.start = function () {
    var self = this;
    this.fetchState(true);
    this.open();
    this.startPolling();
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible" && !self.closed) { self.fetchState(true); if (!self.ws || self.ws.readyState > 1) self.open(); }
    });
    window.addEventListener("online", function () { if (!self.closed) { self.fetchState(true); self.open(); } });
  };
  LiveClient.prototype.stop = function () {
    this.closed = true; clearInterval(this.pollTimer); clearTimeout(this.timer); clearInterval(this.pingTimer);
    try { if (this.ws) this.ws.close(); } catch (e) { /* już zamknięte */ }
  };
  LiveClient.prototype.status = function (s) { if (this.opts.onStatus) this.opts.onStatus(s); };
  LiveClient.prototype.apply = function (snap) {
    if (!snap || snap.unchanged) { if (snap && snap.server_now) syncClock(snap.server_now); return; }
    var phase = snap.session && snap.session.phase;
    if (typeof snap.rev === "number" && snap.rev < this.rev && phase === this.lastPhase) return;
    this.rev = snap.rev; this.lastPhase = phase;
    syncClock(snap.server_now);
    this.opts.onSnapshot(snap);
  };
  LiveClient.prototype.fetchState = function (force) {
    var self = this;
    if (this.closed) return;
    var headers = this.opts.headers ? this.opts.headers() : {};
    fetch(this.opts.stateUrl(force ? null : this.rev), { cache: "no-store", headers: headers })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { status: r.status, ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok) {
          var d = (res.body && (res.body.detail || res.body)) || {};
          if (res.status === 401 || res.status === 403 || res.status === 404) { self.fatal({ code: d.code || ("HTTP_" + res.status), message: d.message || "", status: res.status }); return; }
          self.status("off");
          return;
        }
        if (!self.ws || self.ws.readyState !== 1) self.status("poll");
        self.apply(res.body);
      })
      .catch(function () { self.status("off"); });
  };
  LiveClient.prototype.fatal = function (e) { this.stop(); if (this.opts.onFatal) this.opts.onFatal(e); };
  LiveClient.prototype.startPolling = function () {
    var self = this;
    if (this.pollTimer) return;
    this.pollTimer = setInterval(function () { if (!self.ws || self.ws.readyState !== 1) self.fetchState(false); }, 2000);
  };
  LiveClient.prototype.open = function () {
    var self = this;
    if (this.closed || (this.ws && this.ws.readyState <= 1)) return;
    var ws;
    try { ws = new WebSocket(this.opts.wsUrl()); } catch (e) { this.retry(); return; }
    this.ws = ws;
    ws.onopen = function () {
      self.attempt = 0;
      var auth = self.opts.auth ? self.opts.auth() : null;
      if (auth) ws.send(JSON.stringify(auth));
      self.status("live");
    };
    ws.onmessage = function (ev) {
      var m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m.type === "snapshot") { self.status("live"); self.apply(m.snapshot); }
      else if (m.type === "error" && self.opts.onError) self.opts.onError(m);
    };
    ws.onclose = function (ev) {
      if (self.closed) return;
      if (ev && (ev.code === 4401 || ev.code === 4403 || ev.code === 4404)) { self.fetchState(true); }
      self.status("poll");
      self.retry();
    };
    ws.onerror = function () { try { ws.close(); } catch (e) { /* nic */ } };
    clearInterval(this.pingTimer);
    this.pingTimer = setInterval(function () { if (ws.readyState === 1) ws.send('{"type":"ping"}'); }, 25000);
  };
  LiveClient.prototype.retry = function () {
    var self = this;
    clearTimeout(this.timer);
    var wait = Math.min(10000, 800 * Math.pow(2, this.attempt++)) * (0.7 + Math.random() * 0.6);
    this.timer = setTimeout(function () { self.open(); }, wait);
  };

  /* Pigułka połączenia: dopiero po 5 s bez gniazda i bez udanego GET. */
  function connPill(node) {
    var t = null;
    return function (state) {
      if (state === "live" || state === "poll") { clearTimeout(t); t = null; node.classList.remove("on"); if (state === "poll") arm(); return; }
      arm();
    };
    function arm() { if (!t) t = setTimeout(function () { node.classList.add("on"); }, 5000); }
  }

  function wsBase() { return (location.protocol === "https:" ? "wss://" : "ws://") + location.host; }

  /* ----- dopasowanie tekstu do pudełka (jak zwrotki w Communio): wyszukiwanie połówkowe ----- */
  function fit(node, box, maxPx, minPx) {
    box = box || node.parentNode;
    var W = box.clientWidth, H = box.clientHeight;
    if (!W || !H) return;
    var lo = minPx, hi = maxPx;
    function ok() { return node.scrollHeight <= H + 1 && node.scrollWidth <= W + 1; }
    node.style.fontSize = hi + "px";
    if (ok()) return hi;
    for (var i = 0; i < 12; i++) { var m = (lo + hi) / 2; node.style.fontSize = m + "px"; if (ok()) lo = m; else hi = m; }
    node.style.fontSize = lo + "px";
    return lo;
  }
  /* Jeden wiersz, nigdy nie przycięty: zmniejsza krój, aż cały napis zmieści się w szerokości. */
  function fitLine(node, maxPx, minPx) {
    var box = node.parentNode;
    node.style.whiteSpace = "nowrap";
    var lo = minPx || 6, hi = maxPx;
    node.style.fontSize = hi + "px";
    if (node.scrollWidth <= box.clientWidth + 1) return;
    for (var i = 0; i < 12; i++) { var m = (lo + hi) / 2; node.style.fontSize = m + "px"; if (node.scrollWidth <= box.clientWidth + 1) lo = m; else hi = m; }
    node.style.fontSize = lo + "px";
  }

  /* ----- liczby, które dobiegają (bez bujania) ----- */
  function countUp(node, to, ms) {
    var from = parseInt(node.getAttribute("data-v") || "0", 10) || 0;
    node.setAttribute("data-v", String(to));
    if (REDUCED || from === to) { node.textContent = fmt(to); return; }
    var t0 = performance.now(); ms = ms || 900;
    function step(t) {
      var p = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - p, 3);
      node.textContent = fmt(Math.round(from + (to - from) * e));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  function fmt(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, " "); }
  function pct(n) { return (Math.round(n * 10) / 10).toString().replace(".", ",") + "%"; }
  function plural(n, one, few, many) {
    var d = n % 10, h = n % 100;
    return n === 1 ? one : (d >= 2 && d <= 4 && !(h >= 12 && h <= 14)) ? few : many;
  }
  function charLabel(c) { return c === "exam" ? "Egzamin na sali" : "Quiz szkoleniowy"; }

  /* ----- losowe życie w spoczynku: każdy element ma własny rytm, nic nie bije równo ----- */
  function every(minMs, maxMs, fn) {
    var t = null, alive = true;
    function next() { if (!alive) return; t = setTimeout(function () { if (!alive) return; if (document.visibilityState === "visible") fn(); next(); }, minMs + Math.random() * (maxMs - minMs)); }
    if (!REDUCED) next();
    return function stop() { alive = false; clearTimeout(t); };
  }

  /* ----- barwy sesji (z qr.json / peek) ----- */
  function applyPalette(p) {
    if (!p) return;
    var st = document.documentElement.style;
    st.setProperty("--p1", p.primary); st.setProperty("--p2", p.secondary);
    st.setProperty("--q1", p.from); st.setProperty("--q2", p.to);
  }

  /* ----- kod QR z macierzy (qr.json): kropki rosną falą od środka, oczka-bilety wbijają się jak pieczątka ----- */
  var qrSeq = 0;
  function qrNode(data, opts) {
    opts = opts || {};
    var n = data.size, q = data.quiet || 2, total = n + 2 * q, gid = "qg" + (++qrSeq);
    var root = svg("svg", { viewBox: "0 0 " + total + " " + total, role: "img", "aria-label": "Kod QR do dołączenia" });
    root.appendChild(svg("defs", null, [svg("linearGradient", { id: gid, x1: "0", y1: "0", x2: "1", y2: "1" }, [
      svg("stop", { offset: "0", "stop-color": data.palette.from }), svg("stop", { offset: "1", "stop-color": data.palette.to })])]));
    root.appendChild(svg("rect", { width: total, height: total, rx: 1.2, fill: "#FFFFFF" }));
    var g = svg("g", { transform: "translate(" + q + " " + q + ")", fill: "url(#" + gid + ")" });
    var c = (n - 1) / 2, maxD = Math.sqrt(2) * c, dots = [];
    data.modules.forEach(function (row, y) {
      for (var x = 0; x < row.length; x++) {
        if (row.charAt(x) !== "1") continue;
        var dist = Math.sqrt((x - c) * (x - c) + (y - c) * (y - c)) / maxD;
        var dot = svg("circle", { class: "dot", cx: x + 0.5, cy: y + 0.5, r: (data.style && data.style.dot_radius) || 0.42,
          style: { "--d": (0.12 + dist * 0.85 + Math.random() * 0.18).toFixed(3) + "s" } });
        dots.push(dot); g.appendChild(dot);
      }
    });
    var hr = (data.style && data.style.eye_hole_concave_radius) || 0.9, pr = (data.style && data.style.pupil_concave_radius) || 0.8;
    (data.eyes || []).forEach(function (e, i) {
      var ring = "M" + e.x + " " + e.y + "h7v7h-7Z" + ticketPath(e.x + 1, e.y + 1, 5, hr);
      var d = (1.05 + i * 0.14).toFixed(2) + "s";
      g.appendChild(svg("path", { class: "eye", "fill-rule": "evenodd", d: ring, style: { "--d": d } }));
      g.appendChild(svg("path", { class: "eye", d: ticketPath(e.x + 2, e.y + 2, 3, pr), style: { "--d": (1.2 + i * 0.14).toFixed(2) + "s" } }));
    });
    var lg = data.logo;
    if (lg && opts.crest !== false && data.crest_url) {
      var plate = svg("g", { class: "plate", style: { "--d": "1.55s" } }, [
        svg("rect", { x: lg.x + 0.15, y: lg.y + 0.15, width: lg.size - 0.3, height: lg.size - 0.3, rx: 0.9, fill: "#FFFFFF", stroke: "url(#" + gid + ")", "stroke-width": 0.22 }),
        svg("image", { href: data.crest_url, x: lg.x + 0.55, y: lg.y + 0.55, width: lg.size - 1.1, height: lg.size - 1.1, preserveAspectRatio: "xMidYMid meet" })
      ]);
      g.appendChild(plate);
    }
    root.appendChild(g);
    var wrap = el("div", { class: "qr" + (opts.build && !REDUCED ? " build" : "") }, [root]);
    wrap.dots = dots;
    /* Błysk w spoczynku: kilka losowych kropek, każda z własnym opóźnieniem. */
    wrap.glint = function () {
      if (!dots.length) return;
      var k = 4 + Math.floor(Math.random() * 6);
      for (var i = 0; i < k; i++) {
        var dot = dots[Math.floor(Math.random() * dots.length)];
        dot.style.setProperty("--g", (Math.random() * 0.5).toFixed(2) + "s");
        dot.classList.remove("glint"); void dot.getBoundingClientRect(); dot.classList.add("glint");
      }
    };
    wrap.rebuild = function () {
      if (REDUCED) return;
      wrap.classList.remove("build"); void wrap.offsetWidth; wrap.classList.add("build");
    };
    return wrap;
  }
  function ticketPath(x, y, w, r) {
    return "M" + (x + r) + " " + y + "H" + (x + w - r) + "A" + r + " " + r + " 0 0 0 " + (x + w) + " " + (y + r) +
      "V" + (y + w - r) + "A" + r + " " + r + " 0 0 0 " + (x + w - r) + " " + (y + w) + "H" + (x + r) +
      "A" + r + " " + r + " 0 0 0 " + x + " " + (y + w - r) + "V" + (y + r) + "A" + r + " " + r + " 0 0 0 " + (x + r) + " " + y + "Z";
  }

  /* Hala: reflektory, linie boiska (6 m, przerywana 9 m), ziarno. Jedna na stronę. */
  function hall() {
    var court = svg("svg", { class: "court", viewBox: "0 0 1200 600", preserveAspectRatio: "xMidYMax slice", "aria-hidden": "true" }, [
      svg("path", { d: "M80 600V40H1120V600" }),
      svg("path", { d: "M340 600A260 260 0 0 1 600 340A260 260 0 0 1 860 600" }),
      svg("path", { d: "M210 600A390 390 0 0 1 600 210A390 390 0 0 1 990 600", "stroke-dasharray": "18 16" }),
      svg("path", { d: "M570 470h60" })
    ]);
    var node = el("div", { class: "hall", "aria-hidden": "true" }, [
      el("div", { class: "lamp l1" }), el("div", { class: "lamp l2" }), el("div", { class: "lamp l3" }), el("div", { class: "lamp l4" }),
      court, el("div", { class: "grain" }), el("div", { class: "vignette" })
    ]);
    document.body.insertBefore(node, document.body.firstChild);
    return node;
  }

  function toast(text, kind) {
    var node = $("toast");
    if (!node) { node = el("div", { id: "toast", class: "toast", role: "status", "aria-live": "polite" }); document.body.appendChild(node); }
    node.className = "toast" + (kind ? " " + kind : "");
    node.textContent = text;
    void node.offsetWidth; node.classList.add("on");
    clearTimeout(node._t); node._t = setTimeout(function () { node.classList.remove("on"); }, 4200);
  }

  function readJSON(key) { try { return JSON.parse(localStorage.getItem(key) || "null"); } catch (e) { return null; } }
  function writeJSON(key, v) { try { if (v == null) localStorage.removeItem(key); else localStorage.setItem(key, JSON.stringify(v)); } catch (e) { /* tryb prywatny */ } }

  /* Ekran nie gaśnie, dopóki strona jest na wierzchu (blokada wraca po powrocie karty). */
  function keepAwake() {
    var lock = null, want = true;
    function take() {
      if (!want || !navigator.wakeLock || document.visibilityState !== "visible") return;
      navigator.wakeLock.request("screen").then(function (l) { lock = l; l.addEventListener("release", function () { lock = null; }); }).catch(function () { /* odmowa / bateria */ });
    }
    document.addEventListener("visibilitychange", take);
    document.addEventListener("click", function () { if (!lock) take(); });
    take();
    return { release: function () { want = false; if (lock) lock.release().catch(function () {}); }, supported: !!navigator.wakeLock };
  }

  window.Live = {
    el: el, svg: svg, clear: clear, $: $, shape: shape, LETTERS: LETTERS, LiveClient: LiveClient, connPill: connPill, wsBase: wsBase,
    secondsLeft: secondsLeft, syncClock: syncClock, serverMs: serverMs, fit: fit, fitLine: fitLine, countUp: countUp, fmt: fmt, pct: pct,
    plural: plural, charLabel: charLabel, every: every, applyPalette: applyPalette, qrNode: qrNode, hall: hall, toast: toast,
    readJSON: readJSON, writeJSON: writeJSON, keepAwake: keepAwake, REDUCED: REDUCED
  };
})();
