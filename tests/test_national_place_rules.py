"""Rozpoznanie położenia miejscowości tabeli odległości ZPRP (15.10.2026)."""

from app import national_distance_parser as PARSER
from app import national_distance_progress as PROGRESS
from app import national_lookup_rules as NL
from app import national_place_rules as P

# Kotwice: miasta jednoznaczne.
WROCLAW = P.Place("1", "Wrocław", 51.1100, 17.0300, "dolnoslaskie", 640000)
OPOLE = P.Place("2", "Opole", 50.6700, 17.9300, "opolskie", 128000)
OLAWA = P.Place("3", "Oława", 50.9400, 17.2900, "dolnoslaskie", 33000)
GDANSK = P.Place("4", "Gdańsk", 54.3500, 18.6500, "pomorskie", 470000)
SLUPSK = P.Place("5", "Słupsk", 54.4600, 17.0300, "pomorskie", 90000)
GDYNIA = P.Place("6", "Gdynia", 54.5200, 18.5300, "pomorskie", 245000)
# Dwie Gacie: pomorska (tam postawił ją Nominatim) i dolnośląska (prawdziwa).
GAC_POM = P.Place("10", "Gać", 54.6940, 17.4560, "pomorskie", 0)
GAC_DOLN = P.Place("11", "Gać", 50.8880, 17.3650, "dolnoslaskie", 300)
# Dwie Krzywe - za jedną nazwą stoją dwie różne miejscowości.
KRZYWA_N = P.Place("20", "Krzywa", 54.5000, 17.9000, "pomorskie", 200)
KRZYWA_S = P.Place("21", "Krzywa", 50.9800, 17.6000, "opolskie", 200)

GAZ = P.Gazetteer(
    (place, ())
    for place in (WROCLAW, OPOLE, OLAWA, GDANSK, SLUPSK, GDYNIA, GAC_POM, GAC_DOLN, KRZYWA_N, KRZYWA_S)
)


def road(a: P.Place, b: P.Place) -> float:
    """Kilometry „jak w ryczałcie" - droga o 24 % dłuższa od linii prostej."""
    return round(P.ROAD_FACTOR * P.haversine_km(a.point, b.point))


def node(place: P.Place, key=None, **kw) -> P.NodeInfo:
    return P.NodeInfo(
        key=key or P.name_key(place.name),
        name_key=P.name_key(place.name),
        name=place.name,
        lat=place.lat,
        lon=place.lon,
        observations=kw.pop("observations", 5),
        province=place.province,
        **kw,
    )


def edge(a: str, b: str, km: float, obs: int = 1) -> P.EdgeInfo:
    return P.EdgeInfo(a_key=a, b_key=b, km=km, observations=obs)


def anchors():
    return [node(p) for p in (WROCLAW, OPOLE, OLAWA, GDANSK, SLUPSK, GDYNIA)]


def run(nodes, edges):
    result = P.resolve_network(nodes, edges, GAZ.candidates)
    keys = P.assign_keys(result.nodes, nodes)
    return result, keys, P.plan_relocation(nodes, edges, result, keys)


# ---------------------------------------------------------------------------
# Województwa i wskazówki
# ---------------------------------------------------------------------------


def test_province_slug_rozpoznaje_zwiazki_i_wojewodztwa():
    assert P.province_slug("Śląski ZPRP") == "slaskie"
    assert P.province_slug("DOLNOŚLĄSKIE") == "dolnoslaskie"
    assert P.province_slug("Warmińsko-Mazurski Związek Piłki Ręcznej") == "warminsko-mazurskie"
    assert P.province_slug("Zachodniopomorski ZPR") == "zachodniopomorskie"
    assert P.province_slug("Kujawsko-Pomorskie") == "kujawsko-pomorskie"
    assert P.province_slug("pomorskie") == "pomorskie"
    assert P.province_slug("Departament Rozgrywek ZPRP") == ""
    assert P.province_slug("") == ""


def test_kod_pocztowy_to_slaba_wskazowka():
    assert P.postal_provinces("43-300") == ("slaskie",)
    assert P.postal_provinces("26-600 Radom") == ("swietokrzyskie", "mazowieckie")
    assert P.postal_provinces("brak") == ()
    # Jawne województwo wygrywa z kodem.
    assert P.hint_provinces("opolskie", postal="43-300") == frozenset({"opolskie"})
    assert P.hint_provinces(None, postal="50-001") == frozenset({"dolnoslaskie"})


def test_skorowidz_rozwija_skroty_nazw():
    gaz = P.Gazetteer(
        [
            (P.Place("30", "Tomaszów Mazowiecki", 51.53, 20.0, "lodzkie", 60000), ()),
            (P.Place("31", "Tomaszów Lubelski", 50.45, 23.4, "lubelskie", 20000), ()),
        ]
    )
    assert [p.gid for p in gaz.candidates("Tomaszów Maz.")] == ["30"]
    assert gaz.candidates("Nieistniejąca Wieś") == []


def test_wsie_blizej_niz_kilka_km_to_jedna_miejscowosc():
    a = P.Place("40", "Dąbrowa", 50.0, 20.0, "malopolskie", 0)
    b = P.Place("41", "Dąbrowa", 50.01, 20.01, "malopolskie", 500)
    c = P.Place("42", "Dąbrowa", 52.0, 20.0, "mazowieckie", 0)
    gaz = P.Gazetteer([(a, ()), (b, ()), (c, ())])
    assert sorted(p.gid for p in gaz.candidates("Dąbrowa")) == ["41", "42"]


def test_prawdziwy_skorowidz_zna_polskie_nazwy_duzych_miast():
    gaz = P.default_gazetteer()
    warsaw = gaz.candidates("Warszawa")
    assert warsaw and warsaw[0].province == "mazowieckie" and warsaw[0].population > 1_000_000
    assert len(gaz.candidates("Gać")) >= 2


# ---------------------------------------------------------------------------
# Cała sieć
# ---------------------------------------------------------------------------


def test_gac_przenosi_sie_tam_dokad_naprawde_jezdza_sedziowie():
    nodes = anchors() + [node(GAC_POM, observations=6)]
    edges = [
        edge("gac", "wroclaw", road(GAC_DOLN, WROCLAW), 3),
        edge("gac", "opole", road(GAC_DOLN, OPOLE), 2),
        edge("gac", "olawa", road(GAC_DOLN, OLAWA), 1),
    ]
    result, keys, plan = run(nodes, edges)
    gac = plan.nodes["gac"]
    assert gac["province"] == "dolnoslaskie"
    assert abs(gac["latitude"] - GAC_DOLN.lat) < 0.01
    assert gac["moved_km"] > 300
    assert gac["approximate"] is False
    # Klucz i trasy bez zmian - kilometry po nazwie zostają takie same.
    assert plan.edge_moves == {}
    assert ("gac", "wroclaw") in plan.reroute


def test_dwie_rozne_krzywe_rozdzielaja_sie_na_dwa_wezly():
    # Dawniej jeden punkt (na północy) zbierał trasy obu miejscowości.
    nodes = anchors() + [node(KRZYWA_N, observations=7)]
    edges = [
        edge("krzywa", "gdansk", road(KRZYWA_N, GDANSK), 3),
        edge("krzywa", "slupsk", road(KRZYWA_N, SLUPSK), 2),
        edge("gdynia", "krzywa", road(KRZYWA_N, GDYNIA), 2),
        edge("krzywa", "wroclaw", road(KRZYWA_S, WROCLAW), 1),
        edge("krzywa", "opole", road(KRZYWA_S, OPOLE), 1),
    ]
    result, keys, plan = run(nodes, edges)
    krzywe = {k: v for k, v in plan.nodes.items() if v["name_key"] == "krzywa"}
    assert set(krzywe) == {"krzywa", "krzywa|opolskie"}
    assert krzywe["krzywa"]["province"] == "pomorskie"
    assert krzywe["krzywa|opolskie"]["province"] == "opolskie"
    # Trasy południowe przechodzą do nowego węzła - w całości.
    assert plan.edge_moves[("krzywa", "wroclaw")] == ("krzywa|opolskie", "wroclaw")
    assert plan.edge_moves[("krzywa", "opole")] == ("krzywa|opolskie", "opole")
    assert ("krzywa", "gdansk") not in plan.edge_moves


def test_jedna_trasa_przy_wielu_kandydatach_to_polozenie_przyblizone():
    # Wrocław leży mniej więcej w tej samej odległości od obu kandydatów.
    a = P.Place("50", "Borkowo", 51.11, 18.60, "opolskie", 0)
    b = P.Place("51", "Borkowo", 51.11, 15.46, "dolnoslaskie", 0)
    gaz = P.Gazetteer([(p, ()) for p in (WROCLAW, a, b)])
    nodes = [node(WROCLAW), P.NodeInfo("borkowo", "borkowo", "Borkowo", 52.5, 20.6, 1)]
    edges = [edge("borkowo", "wroclaw", road(a, WROCLAW))]
    result = P.resolve_network(nodes, edges, gaz.candidates)
    borkowo = next(n for n in result.nodes if n.name_key == "borkowo")
    assert borkowo.approximate is True


def test_przypiety_wezel_zostaje_tam_gdzie_postawil_go_admin():
    pinned = node(GAC_POM, pinned=True, observations=6)
    nodes = anchors() + [pinned]
    edges = [
        edge("gac", "wroclaw", road(GAC_DOLN, WROCLAW), 3),
        edge("gac", "opole", road(GAC_DOLN, OPOLE), 2),
    ]
    result, keys, plan = run(nodes, edges)
    assert "gac" in keys
    gac = plan.nodes["gac"]
    assert gac["pinned"] is True
    assert gac["latitude"] == GAC_POM.lat
    assert plan.edge_moves == {}
    assert ("gac", "wroclaw") not in plan.reroute


def test_drobne_roznice_srodka_miasta_nie_ruszaja_punktu():
    moved = P.NodeInfo("wroclaw", "wroclaw", "Wrocław", WROCLAW.lat + 0.05, WROCLAW.lon, 9)
    nodes = [moved, node(OPOLE), node(OLAWA)]
    edges = [edge("opole", "wroclaw", road(OPOLE, WROCLAW)), edge("olawa", "wroclaw", road(OLAWA, WROCLAW))]
    _, _, plan = run(nodes, edges)
    assert plan.nodes["wroclaw"]["latitude"] == moved.lat
    assert not plan.reroute


# ---------------------------------------------------------------------------
# Jeden nowy dokument
# ---------------------------------------------------------------------------


def test_nowy_dokument_wybiera_kandydata_po_kilometrach():
    wro = [P.Option(place=WROCLAW, node=node(WROCLAW))]
    gac = P.side_options([], [GAC_POM, GAC_DOLN])
    a, b = P.choose_document_nodes(road(GAC_DOLN, WROCLAW), gac, wro)
    assert a.option.place.gid == "11"
    assert a.approximate is False
    assert b.option.node is not None


def test_remis_rozstrzyga_wskazowka_a_bez_niej_jest_przyblizone():
    left = P.Place("60", "Janów", 51.11, 18.60, "opolskie", 0)
    right = P.Place("61", "Janów", 51.11, 15.46, "dolnoslaskie", 0)
    wro = [P.Option(place=WROCLAW, node=node(WROCLAW))]
    options = P.side_options([], [left, right])
    km = road(left, WROCLAW)
    plain, _ = P.choose_document_nodes(km, options, wro)
    assert plain.approximate is True
    hinted, _ = P.choose_document_nodes(km, options, wro, frozenset({"dolnoslaskie"}))
    assert hinted.option.place.gid == "61"
    assert hinted.approximate is False


def test_znany_wezel_wygrywa_z_nowym_kandydatem_w_tym_samym_miejscu():
    known = node(GAC_DOLN, key="gac")
    options = P.side_options([known], [GAC_POM, GAC_DOLN])
    assert len(options) == 2  # kandydat dolnośląski = ten sam punkt co węzeł
    a, _ = P.choose_document_nodes(
        road(GAC_DOLN, WROCLAW), options, [P.Option(place=WROCLAW, node=node(WROCLAW))]
    )
    assert a.option.node is known


def test_klucz_drugiej_miejscowosci_o_tej_samej_nazwie():
    assert P.secondary_key("krzywa", "lubuskie", "9", set()) == "krzywa|lubuskie"
    assert P.secondary_key("krzywa", "lubuskie", "9", {"krzywa|lubuskie"}) == "krzywa|lubuskie|9"


def test_wezel_dla_samej_nazwy():
    a = P.NodeInfo("krzywa", "krzywa", "Krzywa", 54.5, 17.9, 9, province="pomorskie")
    b = P.NodeInfo("krzywa|opolskie", "krzywa", "Krzywa", 50.9, 17.6, 2, province="opolskie")
    assert P.pick_node([a, b]).key == "krzywa"
    assert P.pick_node([a, b], "Opolski ZPRP").key == "krzywa|opolskie"


# ---------------------------------------------------------------------------
# Wyszukiwanie km po nazwach (rozliczenia) - zgodność
# ---------------------------------------------------------------------------


def _rows():
    return [
        {"city_a_key": "krzywa", "city_b_key": "wroclaw", "distance_km": 120, "observations": 5,
         "a_name_key": "krzywa", "b_name_key": "wroclaw", "a_province": "pomorskie", "b_province": "dolnoslaskie"},
        {"city_a_key": "krzywa|opolskie", "city_b_key": "wroclaw", "distance_km": 75, "observations": 2,
         "a_name_key": "krzywa", "b_name_key": "wroclaw", "a_province": "opolskie", "b_province": "dolnoslaskie"},
        {"city_a_key": "gliwice", "city_b_key": "piekary slaskie", "distance_km": 31, "observations": 1,
         "a_name_key": None, "b_name_key": None, "a_province": None, "b_province": None},
    ]


def test_pary_nazw_zachowuja_dotychczasowe_kilometry():
    listed, variants = NL.name_pairs(_rows())
    assert ["krzywa", "wroclaw", 120, 5] in listed
    assert ["gliwice", "piekary slaskie", 31, 1] in listed
    assert len(variants[("krzywa", "wroclaw")]) == 2
    pairs = NL.NationalPairs(NL.expand_pairs({(a, b): km for a, b, km, _ in listed}), variants=variants)
    # Wołający bez okręgu: najczęściej potwierdzony wariant (jak dotąd).
    assert NL.national_km(pairs, "Krzywa", "Wrocław") == 120
    assert NL.national_km(pairs, "Piekary Śl.", "Gliwice") == 31
    # Okręg wołającego wybiera miejscowość z jego województwa.
    assert NL.national_km(pairs, "Krzywa", "Wrocław", "Opolski ZPRP") == 75
    assert NL.pick_distance(
        True, home="Krzywa", city="Wrocław", national=pairs, province="opolskie"
    ) == (75.0, NL.SOURCE_NATIONAL)
    assert NL.pick_distance(True, home="Krzywa", city="Wrocław", national=pairs) == (120.0, NL.SOURCE_NATIONAL)
    # Zwykły słownik (stary wołający) działa bez zmian.
    assert NL.national_km(dict(pairs), "Krzywa", "Wrocław", "opolskie") == 120


# ---------------------------------------------------------------------------
# Wskazówki z harvestu i postęp overlaya
# ---------------------------------------------------------------------------


def test_harvest_zapisuje_wskazowki_dokumentu():
    out = PARSER.validate_settlement_candidate(
        url="https://baza.zprp.pl/sedzia_ryczalt_PDF.php?Id=12&IdZawody=34",
        judge_city="Gać",
        venue_city="Oława",
        judge_province=" dolnośląskie ",
        judge_postal_code="55200",
        match_province="Dolnośląski ZPR",
        venue_street="ul. Sportowa 1",
    )
    cols = PARSER.hint_columns(out)
    assert cols == {
        "hint_judge_city": "Gać",
        "hint_venue_city": "Oława",
        "judge_province": "dolnośląskie",
        "judge_postal_code": "55-200",
        "match_province": "Dolnośląski ZPR",
        "venue_street": "ul. Sportowa 1",
    }
    bare = PARSER.validate_settlement_candidate(
        url="https://baza.zprp.pl/sedzia_ryczalt_PDF.php?Id=12&IdZawody=34"
    )
    assert all(value is None for value in PARSER.hint_columns(bare).values())


def test_dom_sedziego_wybiera_wezel_z_jego_wojewodztwa():
    homes = [
        {"city_key": "krzywa", "name_key": "krzywa", "province": "pomorskie", "observations": 9},
        {"city_key": "krzywa|opolskie", "name_key": "krzywa", "province": "opolskie", "observations": 2},
    ]
    rows = [
        {"city_a_key": "krzywa|opolskie", "city_b_key": "wroclaw", "city_a_name": "Krzywa",
         "city_b_name": "Wrocław", "distance_km": 75, "observations": 2},
    ]
    assert PROGRESS.pick_home_node(homes, rows, {"pomorskie"}) == "krzywa"
    # Bez wskazówki: węzeł, z którego prowadzą trasy do miast jego meczów.
    assert PROGRESS.pick_home_node(homes, rows) == "krzywa|opolskie"
    points = {"wroclaw": {"city_key": "wroclaw", "latitude": 51.1, "longitude": 17.0,
                          "province": "dolnoslaskie", "approximate": False, "name_key": "wroclaw"}}
    routes = PROGRESS.routes_from_home(rows, "krzywa|opolskie", points=points)
    assert routes == [{
        "key": "wroclaw", "name": "Wrocław", "km": 75, "latitude": 51.1, "longitude": 17.0,
        "province": "dolnoslaskie", "approximate": False, "nameKey": "wroclaw",
    }]


def test_gola_nazwa_wraca_do_wezla_gdy_stary_stal_w_zlym_miejscu():
    # Przed przeliczeniem nowy dokument założył drugi węzeł obok złego starego.
    old = node(GAC_POM, observations=6)
    new = node(GAC_DOLN, key="gac|dolnoslaskie", observations=1)
    nodes = anchors() + [old, new]
    edges = [
        edge("gac", "wroclaw", road(GAC_DOLN, WROCLAW), 3),
        edge("gac", "opole", road(GAC_DOLN, OPOLE), 2),
        edge("gac|dolnoslaskie", "olawa", road(GAC_DOLN, OLAWA), 1),
    ]
    result, keys, plan = run(nodes, edges)
    gac = [k for k, v in plan.nodes.items() if v["name_key"] == "gac"]
    assert gac == ["gac"]
    assert plan.nodes["gac"]["province"] == "dolnoslaskie"
    assert plan.edge_moves[("gac|dolnoslaskie", "olawa")] == ("gac", "olawa")
    assert "gac|dolnoslaskie" in plan.drop_nodes
