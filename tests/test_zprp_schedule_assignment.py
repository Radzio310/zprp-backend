from app.zprp.schedule import _parse_matches_table


def _schedule_html(date_cell: str) -> str:
    return f"""
    <table>
      <tr>
        <th>Lp.</th><th>Sezon</th><th>Kolejka</th><th>Mecz</th><th>Data</th>
        <th>Hala</th><th>Widzowie</th><th>Gospodarz</th><th>Wynik</th>
        <th>Gość</th><th>Obsada</th>
      </tr>
      <tr>
        <td>1.</td><td>2026/2027</td><td>Kolejka 1 (30.09.2026)</td><td>TEST/1</td>
        <td>{date_cell}</td>
        <td><a href="https://maps.example" title="Arena, Wrocław, Sportowa 1">hala</a></td>
        <td>100</td><td>Drużyna B</td>
        <td><img src="zmiana.png" alt="zmiana gospodarza">10:20</td>
        <td>Drużyna A</td>
        <td><input name="IdZawody" value="12345"></td>
      </tr>
    </table>
    """


def test_schedule_normalises_host_swap_and_score_to_nominal_sides():
    match = next(iter(_parse_matches_table(_schedule_html("<b>30.09.2026</b>")).values()))

    assert match["host_swapped"] is True
    assert match["ID_zespoly_gosp_ZespolNazwa"] == "Drużyna A"
    assert match["ID_zespoly_gosc_ZespolNazwa"] == "Drużyna B"
    assert match["wynik_gosp_full"] == "20"
    assert match["wynik_gosc_full"] == "10"
    assert match["data_fakt"] == "2026-09-30 00:00:00"
    assert match["data_fakt_time_known"] is False


def test_schedule_marks_explicit_hour_as_known():
    match = next(iter(_parse_matches_table(_schedule_html("<b>30.09.2026</b> (18:37)")).values()))

    assert match["data_fakt"] == "2026-09-30 18:37:00"
    assert match["data_fakt_time_known"] is True
