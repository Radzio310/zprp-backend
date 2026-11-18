"""Kanał YouTube -> mecze pary (18.11.2026): reguły na prawdziwych tytułach kanału @referee1710 i meczach ZPRP tej pary."""

from app import mentor_channel_rules as CR

# (tytuł filmu, match_id, numer, gospodarz, gość, termin) - kanał sędziego i jego mecze z publicznej bazy ZPRP.
REAL = [
    [
        "28.02.2026 - KS Otmęt Krapkowice vs MKS MOS Śląsk Wrocław (II połowa)",
        "189679",
        "IKB/97",
        "KS Otmęt Krapkowice",
        "MKS MOS Śląsk Wrocław",
        "2026-02-28T18:00:00"
    ],
    [
        "28.02.2026 - KS Otmęt Krapkowice vs MKS MOS Śląsk Wrocław (I połowa)",
        "189679",
        "IKB/97",
        "KS Otmęt Krapkowice",
        "MKS MOS Śląsk Wrocław",
        "2026-02-28T18:00:00"
    ],
    [
        "22.11.2025 - MSK Wieluń vs MKS Mazur Sierpc",
        "190466",
        "IMC/74",
        "MKS Wieluń",
        "MKS Mazur Sierpc",
        "2025-11-22T11:00:00"
    ],
    [
        "25.10.2025 - Handball Pałac Tarnów vs UKS SMS Wybicki Kielce",
        "190629",
        "IMD/55",
        "Handball Pałac Tarnów",
        "UKS SMS Wybicki Kielce",
        "2025-10-25T17:00:00"
    ],
    [
        "22.10.2025 - UKS SMS Wybicki Kielce II vs UKS Świt Szaflary",
        "191352",
        "IIM4/18",
        "UKS SMS Wybicki II Kielce",
        "UKS Świt Szaflary",
        "2025-10-22T19:00:00"
    ],
    [
        "04.10.2025 - UKS Świt Szaflary vs ASPR Zawadzkie",
        "191348",
        "IIM4/14",
        "UKS Świt Szaflary",
        "ASPR Zawadzkie",
        "2025-10-04T17:30:00"
    ],
    [
        "29.03.2025 IMC_MKS Wieluń - Enea Orlęta Zwoleń",
        "175922",
        "IMC/144",
        "MKS Wieluń",
        "Enea Orlęta Zwoleń",
        "2025-03-29T14:30:00"
    ],
    [
        "16.03.2024 - LKS OSiR Komprachcice vs KS SPR SLV Group Oleśnica",
        "164227",
        "IIM1/108",
        "LKS PR OSiR Komprachcice",
        "KS SPR SLV GROUP Oleśnica",
        "2024-03-16T18:00:00"
    ],
    [
        "09.03.2024 - ASPR Zawadzkie vs SMS ZPRP III Kielce",
        "163475",
        "IIM4/100",
        "ASPR Zawadzkie",
        "SMS ZPRP III Kielce",
        "2024-03-09T18:00:00"
    ],
    [
        "17.02.2024 - SPR Grunwald Ruda Śląska vs UKS 31 Rokitnica Zabrze",
        "163454",
        "IIM4/79",
        "UKS 31 Rokitnica Zabrze",
        "SPR Grunwald Ruda Śląska",
        "2024-02-17T18:00:00"
    ],
    [
        "10.12.2023 - LKS Orzeł Łękawica  vs KS Bystra",
        "163396",
        "IIK4/45",
        "LKS Orzeł Łękawica",
        "KS Bystra",
        "2023-12-10T12:30:00"
    ],
    [
        "12.11.2023 - LKS Orzeł Łękawica  vs Ruch Chorzów",
        "163360",
        "IIK4/9",
        "LKS Orzeł Łękawica",
        "KPR Ruch II Chorzów",
        "2023-11-12T13:30:00"
    ],
    [
        "01.10.2023 AZS AGH II Kraków vs UKS SMS Wybicki Kielce",
        "163295",
        "IIM4/10",
        "AZS AGH II Kraków",
        "UKS SMS Wybicki Kielce",
        "2023-10-01T17:00:00"
    ],
    [
        "21.10.2023 SUMKS Jedynka Myślenice   KS VIVE II KIELCE",
        "163315",
        "IIM4/30",
        "SUMKS Jedynka Myślenice",
        "KS VIVE II Kielce",
        "2023-10-21T11:00:00"
    ],
    [
        "16.10.2022 AGH II Kraków - Wybicki Kielce",
        "151282",
        "IIM4/32",
        "AZS AGH II Kraków",
        "UKS SMS Wybicki Kielce",
        "2022-10-16T17:00:00"
    ],
    [
        "15.10.2022 SUMKS Jedynka Myślenice - HLB Tężnia Busko Zdrój",
        "151284",
        "IIM4/34",
        "SUMKS Jedynka Myślenice",
        "HLB Tężnia Busko-Zdrój",
        "2022-10-15T17:00:00"
    ],
    [
        "01.10.2022 KS Gwardia II Opole - MSPR Siódemka-Miedź-Huras II Legnica",
        "151907",
        "IIM1/23",
        "KS Gwardia II Opole",
        "MSPR Siódemka-Miedź-Huras II Legnica",
        "2022-10-01T17:30:00"
    ],
    [
        "17.09.2022  UKS 31 Rokitnica Zabrze  - SPR Górnik Zabrze",
        "151253",
        "IIM4/3",
        "UKS 31 Rokitnica Zabrze",
        "SPR Górnik Zabrze",
        "2022-09-17T18:00:00"
    ],
    [
        "24.09.2022 SKS Orlik Brzeg - LKS PR OSiR Komprachcice",
        "151904",
        "IIM1/16",
        "SKS Orlik Brzeg",
        "LKS PR OSiR Komprachcice",
        "2022-09-24T19:00:00"
    ]
]


def card(mid, code, home, away, at):
    return {"match_id": mid, "match_code": code, "home": {"name": home}, "away": {"name": away}, "scheduled_at": at}


CARDS = list({r[1]: card(*r[1:]) for r in REAL}.values())  # mecz raz, choć ma dwa filmy-połowy
# Utrudnienia: rewanż tych samych drużyn w innym terminie i inny mecz pary tego samego dnia.
CARDS += [card("rewanz", "IMC/9", "MKS Mazur Sierpc", "MKS Wieluń", "2025-04-12T17:00:00"),
          card("inny", "IIM4/99", "KS Bystra", "Ruch Chorzów", "2023-12-10T12:00:00")]


def test_wszystkie_filmy_kanalu_trafiaja_pewnie_w_swoj_mecz():
    for title, mid, *_ in REAL:
        p = CR.propose(title, CARDS)
        assert p["match_id"] == mid, (title, p)
        assert p["confidence"] == "sure", (title, p)
        assert "data" in p["reasons"]


def test_rozbior_tytulow_kanalu():
    p = CR.parse_title("28.02.2026 - KS Otmęt Krapkowice vs MKS MOS Śląsk Wrocław (II połowa)")
    assert p["date"] == "2026-02-28" and p["half"] == 2 and p["home"] == "KS Otmęt Krapkowice" and p["away"] == "MKS MOS Śląsk Wrocław"
    p = CR.parse_title("29.03.2025 IMC_MKS Wieluń - Enea Orlęta Zwoleń")
    assert p["code"] == "IMC" and p["home"] == "MKS Wieluń" and p["away"] == "Enea Orlęta Zwoleń"
    p = CR.parse_title("21.10.2023 SUMKS Jedynka Myślenice   KS VIVE II KIELCE")
    assert p["home"] == "SUMKS Jedynka Myślenice" and p["away"] == "KS VIVE II KIELCE"
    assert CR.parse_title("Mecz 2. połowa 1.10.22 AGH - Wybicki")["half"] == 2
    assert CR.parse_title("Kompilacja najlepszych akcji")["date"] is None


def test_numer_z_tytulu_i_odwrotna_kolejnosc():
    p = CR.propose("17.02.2024 - SPR Grunwald Ruda Śląska vs UKS 31 Rokitnica Zabrze", CARDS)
    assert "drużyny odwrotnie" in p["reasons"]
    p = CR.propose("29.03.2025 IMC_MKS Wieluń - Enea Orlęta Zwoleń", CARDS)
    assert "numer IMC" in p["reasons"]


def test_slabsze_dopasowania():
    # Data o dzień obok (nagranie wrzucone z datą wrzucenia) - prawdopodobne.
    assert CR.propose("23.11.2025 - MSK Wieluń vs MKS Mazur Sierpc", CARDS)["confidence"] == "likely"
    # Bez daty: dwa mecze tych drużyn (mecz i rewanż) - tylko do sprawdzenia, z alternatywą.
    p = CR.propose("MKS Wieluń - MKS Mazur Sierpc", CARDS)
    assert p["confidence"] == "likely" and p["alternatives"]
    # Inne drużyny tego dnia - nie przyklejamy na siłę.
    assert CR.propose("10.12.2023 - Orzeł Łękawica vs Kalisz", CARDS)["confidence"] == "likely"
    assert CR.propose("Zupełnie inny film o sędziowaniu", CARDS)["match_id"] is None


def test_polowy_lacza_sie_w_jeden_mecz():
    items = [{"video_id": f"v{i}", **CR.propose(t, CARDS)} for i, (t, *_) in enumerate(REAL)]
    groups = CR.half_groups(items)
    assert groups == {"189679": ["v1", "v0"]}  # I połowa (v1) przed II (v0)
    s = CR.summary(items)
    assert s["sure"] == 19 and s["total"] == 19


def test_link_kanalu_i_czas():
    assert CR.channel_ref("https://www.youtube.com/@referee1710") == {"kind": "handle", "value": "@referee1710"}
    assert CR.channel_ref("@referee1710") == {"kind": "handle", "value": "@referee1710"}
    assert CR.channel_ref("https://www.youtube.com/channel/UCkyXYml9ku9IGnFmiScUIKw/videos") == {"kind": "id", "value": "UCkyXYml9ku9IGnFmiScUIKw"}
    assert CR.channel_ref("https://example.com") is None
    assert CR.iso_seconds("PT1H2M3S") == 3723 and CR.iso_seconds("58:12") == 3492 and CR.iso_seconds("x") is None
