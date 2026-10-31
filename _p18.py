def rd(p):
    return open(p, encoding='utf-8').read()


def wr(p, t):
    open(p, 'w', encoding='utf-8').write(t)


# ───────── rank: tożsamość meczu i scalanie ─────────
p = 'app/mentor_trybuna_rank.py'
t = rd(p)
t += '''

def identity(entry: Mapping[str, Any]) -> str:
    """Tożsamość meczu wyniku: kod meczu + dzień (czas polski), inaczej drużyny + dzień, inaczej sam klucz wpisu. Dzień meczu bierze się
    z `match_day` (film z YouTube: dzień MECZU, nie transmisji), inaczej z `date`."""
    day = S.parse_day(entry.get("match_day")) or S.parse_day(entry.get("date"))
    code = S._alnum(entry.get("code")).casefold()
    if code and day:
        return f"c:{code}|{day.isoformat()}"
    teams = sorted(S.fold(x) for x in (entry.get("home"), entry.get("away")) if x)
    if teams and day:
        return f"t:{'|'.join(teams)}|{day.isoformat()}"
    return f"k:{entry.get('key')}"


def _has_video(entry: Mapping[str, Any]) -> bool:
    return entry.get("source") == "bastion" and entry.get("state") == "video" and bool((entry.get("ref") or {}).get("bunny_item_id"))


def source_info(entry: Mapping[str, Any]) -> Dict[str, Any]:
    ref = entry.get("ref") or {}
    out: Dict[str, Any] = {"source": entry["source"], "key": entry["key"], "confidence": entry.get("confidence"), "sure": bool(entry.get("sure"))}
    if entry["source"] == "bastion":
        out.update(bunny_item_id=ref.get("bunny_item_id"), game_id=ref.get("game_id"), video_state=entry.get("video_state") or entry.get("state"),
                   url=entry.get("url"))
    elif entry["source"] == "youtube":
        out.update(video_id=ref.get("video_id"), url=ref.get("url"), official=bool(entry.get("official")))
    else:
        out.update(match_id=ref.get("match_id"))
    return out


def merge_ranked(ranked: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Ten sam mecz z kilku źródeł (kaseta z nagraniem, ta sama bez nagrania, film YouTube, wpis z "bazy") = JEDEN wpis z listą
    `sources`. Wersja główna: kaseta Bastionu Z NAGRANIEM, inaczej pierwsza w kolejności trafności. Wpis ma `in_baza` / `baza_match_id`,
    gdy któryś ze źródeł to mecz pary albo Trybuny pary; `target` bierze najlepszy z grupy (mecz pary > mecz z Trybuny > nowy)."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []
    for e in ranked:
        gid = identity(e)
        if gid not in groups:
            groups[gid] = []
            order.append(gid)
        groups[gid].append(e)
    merged: List[Dict[str, Any]] = []
    for gid in order:
        members = groups[gid]
        primary = next((m for m in members if _has_video(m)), members[0])
        out = dict(primary)
        out["sources"] = [source_info(m) for m in sorted(members, key=lambda m: (m is not primary, rank_key(m)))]
        out["confidence"] = max(int(m.get("confidence") or 0) for m in members)
        out["sure"] = any(m.get("sure") for m in members)
        baza = next((m for m in members if m["source"] == "baza"), None)
        out["in_baza"] = baza is not None
        out["baza_match_id"] = (baza.get("ref") or {}).get("match_id") if baza else None
        rank = {"pair_match": 0, "trybuna": 1}
        targets = [m.get("target") for m in members if m.get("target")]
        with_id = [x for x in targets if x.get("match_id")]
        out["target"] = (sorted(with_id, key=lambda x: rank.get(x.get("kind"), 2)) or targets or [None])[0]
        merged.append(out)
    merged.sort(key=rank_key)
    return merged


def best_info(ranked: List[Mapping[str, Any]], best: Optional[str]) -> Dict[str, Any]:
    """`best_in_baza` / `best_match_id` dla wybranego `best` (wpis jest już scalony z wpisem "baza")."""
    top = next((r for r in ranked if r["key"] == best), None) if best else None
    if top is None:
        return {"best_in_baza": False, "best_match_id": None}
    return {"best_in_baza": bool(top.get("in_baza")), "best_match_id": top.get("baza_match_id") or (top.get("target") or {}).get("match_id")}


def counts(ranked: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    """Liczniki spójne z `ranked`: ile wpisów ma dane źródło wśród `sources`."""
    out = {"ranked": 0, "bastion": 0, "youtube": 0, "baza": 0}
    for r in ranked:
        out["ranked"] += 1
        for s in {x["source"] for x in r.get("sources") or [{"source": r["source"]}]}:
            out[s] = out.get(s, 0) + 1
    return out
'''
wr(p, t)

# ───────── rules: Imię Nazwisko ─────────
p = 'app/mentor_trybuna_rules.py'
t = rd(p)
a = 'def name_key(name: Any) -> str:'
assert a in t
t = t.replace(a, '''def display_name(raw: Any) -> str:
    """"RAWICKI Jakub" -> "Jakub Rawicki" (nazwisko wielkimi na początku lub końcu); "JAN KOWALSKI" -> "Jan Kowalski"; "Jan Kowalski" bez zmian."""
    text = " ".join(R.s(raw).split())
    words = text.split()
    sur = [w for w in words if len(w) > 1 and w.isupper()]
    rest = [w for w in words if w not in sur]
    cap = lambda w: "-".join(p.capitalize() for p in w.split("-"))  # noqa: E731
    if sur and rest:
        return " ".join(rest + [cap(w) for w in sur])
    if sur and not rest:
        return " ".join(cap(w) for w in words)
    return text


def name_key(name: Any) -> str:''', 1)
a = '''            out.append({"name": name or f"Sędzia {jid}", "judge_id": jid or None, "position": "AB"[slot - 1], "role": "referee"})'''
assert a in t
t = t.replace(a, '''            out.append({"name": display_name(name) if name else f"Sędzia {jid}", "judge_id": jid or None, "position": "AB"[slot - 1], "role": "referee"})''', 1)
a = '''            out.append({"name": name or f"Delegat {jid}", "judge_id": jid or None, "position": f"D{slot}", "role": "delegate"})'''
assert a in t
t = t.replace(a, '''            out.append({"name": display_name(name) if name else f"Delegat {jid}", "judge_id": jid or None, "position": f"D{slot}", "role": "delegate"})''', 1)
a = '''            out.append({"name": name or f"Stolikowy {jid}", "judge_id": jid or None, "position": pos, "role": "table"})'''
assert a in t
t = t.replace(a, '''            out.append({"name": display_name(name) if name else f"Stolikowy {jid}", "judge_id": jid or None, "position": pos, "role": "table"})''', 1)
wr(p, t)

# ───────── feed ─────────
p = 'app/mentor_trybuna_feed.py'
t = rd(p)


def sub(a, b):
    global t
    assert a in t, a[:90]
    t = t.replace(a, b, 1)


sub('''def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else (R.s(value) or None)''', '''def _iso(value: Any) -> Optional[str]:
    """Czas jako ISO ZE STREFĄ (naiwny datetime z bazy traktujemy jak UTC)."""
    return R.aware(value).isoformat() if isinstance(value, datetime) else (R.s(value) or None)


_LOCAL_STAMP = re.compile(r"^(\\d{4}-\\d{2}-\\d{2})[ T](\\d{2}:\\d{2})(:\\d{2})?$")


def iso_pl(value: Any) -> Optional[str]:
    """Czas do odpowiedzi jako ISO ze strefą (Europe/Warsaw). Napis Meczoteki / ZPRP bez strefy ("2026-10-18 15:00:00") to czas POLSKI
    (nie UTC): dostaje przesunięcie +01:00 / +02:00; aware datetime jest przeliczany na czas polski; napis już ze strefą zostaje."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return R.aware(value).astimezone(WARSAW).isoformat()
    text = R.s(value)
    m = _LOCAL_STAMP.match(text)
    if m:
        return datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}{m.group(3) or ':00'}").replace(tzinfo=WARSAW).isoformat()
    return text''')
sub('''    return not (game.get("unscheduled") or R.s(game.get("date")).endswith("00:00:00"))''', '''    return not (game.get("unscheduled") or re.search(r"[ T]00:00:00(?!\\d)", R.s(game.get("date"))))''')
sub('''            **{k: game.get(k) for k in keep},
            "referees"''', '''            **{k: game.get(k) for k in keep}, "date": iso_pl(game.get("date")), "date_local": game.get("date"),
            "referees"''')
sub('''"date": g.get("date") if day else None,''', '''"date": iso_pl(g.get("date")) if day else None,''')
sub("import asyncio\nimport logging\nimport time\n", "import asyncio\nimport logging\nimport re\nimport time\n")

# YouTube / baza daty + match_day
sub('''                    "published_at": _iso(s.get("starts_at") or s.get("first_seen_at")), "date": local,''', '''                    "published_at": _iso(s.get("starts_at") or s.get("first_seen_at")), "date": iso_pl(local),
                    "match_day": (S.card_day(card).isoformat() if S.card_day(card) else None),''')
sub('''                ranked.append({"source": "youtube", "key": f"yt:{y['video_id']}", "confidence": y["confidence"], "sure": y["sure"], "signals": y["signals"],
                       "title": y["title"], "date": y["date"], "home": y["home"], "away": y["away"], "code": y["code"],''', '''                ranked.append({"source": "youtube", "key": f"yt:{y['video_id']}", "confidence": y["confidence"], "sure": y["sure"], "signals": y["signals"],
                       "title": y["title"], "date": y["date"], "match_day": y.get("match_day"), "home": y["home"], "away": y["away"], "code": y["code"],''') if False else None
wr(p, t)
