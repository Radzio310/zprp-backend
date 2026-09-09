from app.settlement_distances import DistanceIndex, extract_pairs, normalize_city


def test_normalizacja_miasta_zdejmuje_kod_ogonki_i_skroty():
    assert normalize_city("40-159 Katowice")[0] == "katowice"
    assert normalize_city("Piekary Śl.")[0] == "piekary slaskie"
    assert normalize_city("Bystra, śląskie")[0] == "bystra"
    # Postac „scisnieta" ratuje zapisy roznice sie tylko spacja.
    assert normalize_city("Ruda Śląska")[1] == "rudaslaska"


def test_format_cities_edges():
    content = {"cities": ["Zabrze", "Gliwice"], "edges": [{"from": "Zabrze", "to": "Gliwice", "distance_km": 12}]}
    index = DistanceIndex(content)
    assert index.lookup("Zabrze", "Gliwice") == 12
    # Tabela jest symetryczna, choc zapisana raz.
    assert index.lookup("Gliwice", "Zabrze") == 12


def test_format_cities_matrix():
    content = {"cities": ["A", "B"], "matrix": [[0, 30], [30, 0]]}
    assert DistanceIndex(content).lookup("A", "B") == 30


def test_format_mapa_mapa():
    assert DistanceIndex({"Zabrze": {"Bytom": 9}}).lookup("Bytom", "Zabrze") == 9


def test_format_tablica_rekordow():
    content = [{"from": "Bystra", "to": "Katowice", "km": 73}]
    assert DistanceIndex(content).lookup("Bystra", "Katowice") == 73


def test_to_samo_miasto_to_zero_km():
    # Pary „miasto do samego siebie" w tabelach nie ma, a odleglosc jest oczywista.
    assert DistanceIndex({}).lookup("Katowice", "katowice") == 0.0
    assert DistanceIndex({}).lookup("Piekary Śl.", "Piekary Śląskie") == 0.0


def test_brak_pary_to_None_a_nie_zero():
    # Zero wygladaloby jak „mecz na miejscu" i po cichu zabieraloby dojazd.
    assert DistanceIndex({"Zabrze": {"Bytom": 9}}).lookup("Zabrze", "Gdynia") is None


def test_pusta_tabela_nie_wywala_indeksu():
    index = DistanceIndex(None)
    assert index.pairs == 0
    assert index.lookup("Zabrze", "Bytom") is None


def test_extract_pairs_odrzuca_smieci():
    assert extract_pairs({"cities": ["A"], "edges": [{"from": "A"}, None, {"from": "A", "to": "B", "km": "x"}]}) == []
