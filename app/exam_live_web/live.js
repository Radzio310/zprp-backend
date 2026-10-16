/* Egzamin na żywo - wspólna biblioteka rzutnika i strony gościa (bez zależności).
   Wzorzec jak w Communio: serwer trzyma stan i rozsyła MIGAWKĘ przez WebSocket, a strona
   (1) po dołączeniu robi GET migawki, (2) przy zerwanym gniazdie odpytuje GET co 2 s
   (z ?since_rev, więc tanio), (3) łączy się ponownie z wykładniczym opóźnieniem.
   Wszystko, co pochodzi od ludzi (nicki), trafia do DOM wyłącznie przez textContent. */
(function () {
  "use strict";

  var SHAPES = {
    a: '<svg viewBox="0 0 24 24"><path d="M12 2.5 22 20.5H2z"/></svg>',
    b: '<svg viewBox="0 0 24 24"><path d="M12 1.5 22.5 12 12 22.5 1.5 12z"/></svg>',
    c: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>',
    d: '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/></svg>',
    e: '<svg viewBox="0 0 24 24"><path d="M12 1.8 14.9 8.6 22.2 9.2 16.6 14 18.4 21.2 12 17.4 5.6 21.2 7.4 14 1.8 9.2 9.1 8.6z"/></svg>',
    f: '<svg viewBox="0 0 24 24"><path d="M12 2 21 7v10l-9 5-9-5V7z"/></svg>'
  };

  function el(tag, attrs, kids) {
    var node = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v == null || v === false) return;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k === "html") node.innerHTML = v; /* tylko stałe SVG z tego pliku */
      else if (k.slice(0, 2) === "on") node.addEventListener(k.slice(2), v);
      else if (k === "style" && typeof v === "object") Object.keys(v).forEach(function (s) { node.style.setProperty(s, v[s]); });
      else node.setAttribute(k, v === true ? "" : v);
    });
    (kids || []).forEach(function (kid) { if (kid != null) node.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid); });
    return node;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }

  function shape(key) { return el("span", { class: "shape", html: SHAPES[key] || SHAPES.a }); }

  /* Zegar serwera: offset = server_now - Date.now() z każdej migawki. */
  var offsetMs = 0;
  function syncClock(serverNow) {
    var t = Date.parse(serverNow);
    if (!isNaN(t)) offsetMs = t - Date.now();
  }
  function serverMs() { return Date.now() + offsetMs; }
  function secondsLeft(deadlineIso) {
    var t = Date.parse(deadlineIso);
    return isNaN(t) ? 0 : Math.max(0, (t - serverMs()) / 1000);
  }

  /* Klient migawek: WS + polling awaryjny + ponowne łączenie. */
  function LiveClient(opts) {
    this.opts = opts; /* {stateUrl(since), wsUrl(), onSnapshot(s), onStatus(state), onError(e), onFatal(e)} */
    this.rev = -1; this.ws = null; this.attempt = 0; this.timer = null; this.pollTimer = null; this.closed = false;
  }
  LiveClient.prototype.start = function () {
    var self = this;
    this.fetchState(true);
    this.open();
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible") { self.fetchState(true); if (!self.ws || self.ws.readyState > 1) self.open(); }
    });
  };
  LiveClient.prototype.apply = function (snap) {
    if (!snap || snap.unchanged) return;
    if (snap.session && typeof snap.rev === "number" && snap.rev < this.rev && snap.session.phase === this.lastPhase) return;
    this.rev = snap.rev; this.lastPhase = snap.session && snap.session.phase;
    syncClock(snap.server_now);
    this.opts.onSnapshot(snap);
  };
  LiveClient.prototype.fetchState = function (force) {
    var self = this;
    fetch(this.opts.stateUrl(force ? null : this.rev), { cache: "no-store", headers: this.opts.headers || {} })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok) { var d = (res.body && res.body.detail) || {}; if (self.opts.onFatal) self.opts.onFatal({ code: d.code, message: d.message || "Błąd połączenia." }); return; }
        self.apply(res.body);
      })
      .catch(function () { if (self.opts.onStatus) self.opts.onStatus("off"); });
  };
  LiveClient.prototype.startPolling = function () {
    var self = this;
    if (this.pollTimer) return;
    this.pollTimer = setInterval(function () { if (!self.ws || self.ws.readyState !== 1) self.fetchState(false); }, 2000);
  };
  LiveClient.prototype.open = function () {
    var self = this;
    if (this.closed) return;
    var ws;
    try { ws = new WebSocket(this.opts.wsUrl()); } catch (e) { this.retry(); return; }
    this.ws = ws;
    ws.onopen = function () { self.attempt = 0; if (self.opts.onStatus) self.opts.onStatus("live"); };
    ws.onmessage = function (ev) {
      var m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m.type === "snapshot") self.apply(m.snapshot);
      else if (m.type === "error") {
        if (self.opts.onError) self.opts.onError(m);
        if (m.code === "LIVE_NOT_JOINED" || m.code === "LIVE_NOT_FOUND" || m.code === "UNAUTHORIZED") { self.closed = true; if (self.opts.onFatal) self.opts.onFatal(m); }
      }
    };
    ws.onclose = function () { if (self.closed) return; if (self.opts.onStatus) self.opts.onStatus("poll"); self.startPolling(); self.retry(); };
    ws.onerror = function () { try { ws.close(); } catch (e) {} };
    clearInterval(this.pingTimer);
    this.pingTimer = setInterval(function () { if (ws.readyState === 1) ws.send('{"type":"ping"}'); }, 25000);
  };
  LiveClient.prototype.retry = function () {
    var self = this;
    clearTimeout(this.timer);
    var wait = Math.min(10000, 800 * Math.pow(2, this.attempt++)) * (0.7 + Math.random() * 0.6);
    this.timer = setTimeout(function () { self.open(); }, wait);
  };
  LiveClient.prototype.send = function (obj) {
    if (this.ws && this.ws.readyState === 1) { this.ws.send(JSON.stringify(obj)); return true; }
    return false;
  };

  function wsBase() { return (location.protocol === "https:" ? "wss://" : "ws://") + location.host; }

  /* Kafle odpowiedzi. opts: {answers, mode:'tiles'|'full', onPick, selected, correct, distribution, locked} */
  function renderTiles(question, opts) {
    var grid = el("div", { class: "tiles" });
    (question.answers || []).forEach(function (a) {
      var kids = [shape(a.key)];
      if (a.text != null) kids.push(el("span", { class: "tx", text: a.text })); else kids.push(el("span", { class: "tx" }));
      var tile = el("button", { class: "tile", "data-k": a.key, type: "button" }, kids);
      if (opts.onPick && !opts.locked) tile.addEventListener("click", function () { opts.onPick(a.key, tile); });
      else tile.disabled = true;
      if (opts.selected && opts.selected.indexOf(a.key) >= 0) tile.classList.add("sel");
      grid.appendChild(tile);
    });
    return grid;
  }

  /* Ranking: wiersze z paskami proporcjonalnymi do punktów, wejście kaskadowe. */
  function renderBoard(rows, opts) {
    opts = opts || {};
    var max = rows.reduce(function (m, r) { return Math.max(m, r.score); }, 1);
    var board = el("div", { class: "board" });
    rows.forEach(function (r, i) {
      var cls = "row" + (r.place <= 3 ? " p" + r.place : "") + (r.you ? " you" : "");
      var fill = el("div", { class: "fill" });
      var row = el("div", { class: cls, style: { "animation-delay": (i * 0.12) + "s" } }, [
        fill, el("span", { class: "pl", text: String(r.place) }),
        el("span", { class: "nm", text: r.name + (r.you ? " (Ty)" : "") }),
        el("span", { class: "sc", text: String(r.score) })
      ]);
      board.appendChild(row);
      setTimeout(function () { fill.style.width = Math.max(4, (r.score / max) * 100) + "%"; }, 60 + i * 120);
    });
    return board;
  }

  function ring(sizeClass) {
    var c = 2 * Math.PI * 42;
    var svg = '<svg viewBox="0 0 100 100"><circle class="bg" cx="50" cy="50" r="42"/><circle class="fg" cx="50" cy="50" r="42" stroke-dasharray="' + c + '" stroke-dashoffset="0"/></svg>';
    var wrap = el("div", { class: "ring " + (sizeClass || ""), html: svg });
    var label = el("b", { text: "0" });
    wrap.appendChild(label);
    wrap.update = function (left, total) {
      var fg = wrap.querySelector(".fg");
      fg.style.strokeDashoffset = String(c * (1 - Math.max(0, Math.min(1, left / Math.max(1, total)))));
      label.textContent = String(Math.ceil(left));
      wrap.classList.toggle("hot", left <= 5 && left > 0);
    };
    return wrap;
  }

  function charLabel(c) { return c === "exam" ? "Egzamin na sali" : "Quiz szkoleniowy"; }
  function pct(n) { return (Math.round(n * 10) / 10).toString().replace(".", ",") + "%"; }

  window.Live = { el: el, clear: clear, shape: shape, LiveClient: LiveClient, renderTiles: renderTiles, renderBoard: renderBoard,
    ring: ring, secondsLeft: secondsLeft, syncClock: syncClock, serverMs: serverMs, wsBase: wsBase, charLabel: charLabel, pct: pct };
})();
