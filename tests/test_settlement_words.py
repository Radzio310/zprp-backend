from app.settlement_words import amount_in_words, integer_in_words, money, number


def test_kwota_z_dotychczasowego_dokumentu():
    # Wprost z „Lista przejazdow XI": 955,20 zl.
    assert amount_in_words(955.20) == "dziewięćset pięćdziesiąt pięć 20/100"


def test_zero_ma_wlasna_nazwe():
    # Pusty napis w rubryce „slownie" wyglada jak brak wydruku, nie jak zero.
    assert integer_in_words(0) == "zero"
    assert amount_in_words(0) == "zero 00/100"


def test_nastki_nie_myla_sie_z_dziesiatkami():
    assert integer_in_words(12) == "dwanaście"
    assert integer_in_words(20) == "dwadzieścia"
    assert integer_in_words(112) == "sto dwanaście"


def test_odmiana_tysiecy():
    assert integer_in_words(1000) == "tysiąc"          # bez „jeden"
    assert integer_in_words(2000) == "dwa tysiące"
    assert integer_in_words(5000) == "pięć tysięcy"
    # 12-14 to wyjatek: „dwanascie tysiecy", nie „tysiace".
    assert integer_in_words(12000) == "dwanaście tysięcy"
    assert integer_in_words(22000) == "dwadzieścia dwa tysiące"


def test_setki():
    assert integer_in_words(200) == "dwieście"
    assert integer_in_words(500) == "pięćset"
    assert integer_in_words(1896) == "tysiąc osiemset dziewięćdziesiąt sześć"


def test_grosze_zaokraglaja_sie_po_ksiegowemu():
    assert amount_in_words(0.005) == "zero 01/100"
    assert amount_in_words(148.80) == "sto czterdzieści osiem 80/100"


NBSP = " "


def test_money_grupuje_tysiace_spacja_nierozdzielajaca():
    # Z papierowego zestawienia: suma 2 100,00 i 1 896,00.
    # Separator to SPACJA NIEROZDZIELAJACA - w PDF kwota nie moze zlamac sie
    # miedzy tysiacami a setkami, bo „2" na koncu wiersza to inna liczba.
    # Nierozdzielajaca stoi TAKZE przed „zl" - „148,80" na koncu wiersza
    # i samotne „zl" na poczatku nastepnego to nie jest kwota.
    assert money(2100) == f"2{NBSP}100,00{NBSP}zł"
    assert money(1896) == f"1{NBSP}896,00{NBSP}zł"
    assert money(148.8) == f"148,80{NBSP}zł"
    assert money(0) == f"0,00{NBSP}zł"


def test_number_bez_waluty():
    assert number(186) == "186"
    assert number(1234) == f"1{NBSP}234"
    assert number(93.5, 1) == "93,5"
