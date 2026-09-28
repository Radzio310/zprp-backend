import asyncio

from app.zprp.round_windows import RoundWindowRequestItem, resolve_items


def test_resolves_official_round_window_and_reuses_requests():
    calls: list[str] = []

    async def rows(path: str):
        calls.append(path)
        if path == "pokaz_rundy.php?Rozgrywki=12010":
            return [{"Id": "31120", "Nazwa": "I runda"}]
        if path == "pokaz_kolejki.php?Runda=31120":
            return [
                {
                    "ID_kolejka": "66772",
                    "Nr": "6",
                    "Nazwa": "Kolejka 6",
                    "DataStart": "2026-10-16",
                    "DataKoniec": "2026-10-18",
                }
            ]
        return []

    result = asyncio.run(
        resolve_items(
            [
                RoundWindowRequestItem(
                    match_id="206769",
                    competition_id="12010",
                    round_name="I runda",
                    series_name="Kolejka 6",
                ),
                RoundWindowRequestItem(
                    match_id="206770",
                    competition_id="12010",
                    round_name="Runda I",
                    series_name="6",
                ),
            ],
            rows,
        )
    )

    assert [(item.match_id, item.start_date, item.end_date) for item in result.items] == [
        ("206769", "2026-10-16", "2026-10-18"),
        ("206770", "2026-10-16", "2026-10-18"),
    ]
    assert result.unresolved == []
    assert calls.count("pokaz_rundy.php?Rozgrywki=12010") == 1
    assert calls.count("pokaz_kolejki.php?Runda=31120") == 1


def test_rejects_incomplete_or_reversed_window():
    async def rows(path: str):
        if "pokaz_rundy" in path:
            return [{"Id": "22", "Nazwa": "I runda"}]
        return [
            {
                "ID_kolejka": "33",
                "Nazwa": "Kolejka 6",
                "DataStart": "2026-10-18",
                "DataKoniec": "2026-10-16",
            }
        ]

    result = asyncio.run(
        resolve_items(
            [
                RoundWindowRequestItem(
                    match_id="1",
                    competition_id="12",
                    round_name="I runda",
                    series_name="Kolejka 6",
                )
            ],
            rows,
        )
    )

    assert result.items == []
    assert result.unresolved == ["1"]
