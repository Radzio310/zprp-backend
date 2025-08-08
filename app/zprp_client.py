# app/clients/zprp_client.py

import asyncio
import json
import time
import requests
import httpx
import pandas as pd

from app.utils import Utils

ZPRP_URL_WEBSITE = "https://rozgrywki.zprp.pl/"
ZPRP_URL_API     = f"{ZPRP_URL_WEBSITE}api/"

class ZprpResponseError(Exception):
    """Błąd odpowiedzi ZPRP API."""
    pass

class ZprpApiCommon:
    def __init__(self, utils=None, debug_logging: bool = False):
        if not utils:
            utils = Utils(logfile_roller='%Y%m%d', logfile_main_dirs=[()])
        self.utils = utils
        self.request_counter = 0
        self.error_counter   = 0
        self.debug_logging   = debug_logging

    @staticmethod
    def get_link_zprp(link_type: str, link_ids: dict[str, str]) -> str:
        key_map = {
            'season': 'Sezon',
            'type':   'Rozgrywki',
            'round':  'Runda',
            'series': 'Kolejka',
            'game':   'Mecz',
            'table':  'Tabela',
        }

        # wybór endpointu
        if link_type == 'seasons_api':
            link = f'{ZPRP_URL_API}pokaz_sezony.php'; required = []
        elif link_type == 'game_types_api':
            link = f'{ZPRP_URL_API}pokaz_rozgrywki.php';   required = ['season']
        elif link_type == 'game_rounds_api':
            link = f'{ZPRP_URL_API}pokaz_rundy.php';       required = ['type']
        elif link_type == 'series_api':
            link = f'{ZPRP_URL_API}pokaz_kolejki.php';     required = ['round']
        elif link_type == 'games_api':
            link = f'{ZPRP_URL_API}pokaz_mecze.php';       required = ['series']
        else:
            raise ValueError(f'get_link unknown link_type {link_type}!')

        if required:
            args = [f"{key_map[k]}={link_ids[k]}" for k in required]
            link = f"{link}?{'&'.join(args)}"
        return link

    @staticmethod
    def _assemble_game_row(season, game_type, game_round, game_series, game) -> dict:
        # zamiast tłumaczyć, łączymy wszystkie dane w jeden słownik
        row = {}
        row.update(season)
        row.update(game_type)
        row.update(game_round)
        row.update(game_series)
        row.update(game)
        return row

class ZprpApiClient(ZprpApiCommon):
    def __init__(self, utils=None, debug_logging: bool = False):
        super().__init__(utils=utils, debug_logging=debug_logging)
        self.session = requests.Session()

    def _get_request_json(self, link: str, spot: str):
        self.request_counter += 1
        for i in range(6):
            try:
                return self.session.get(link, timeout=10).json()
            except (requests.exceptions.JSONDecodeError, ValueError) as e:
                self.utils.log_this(f"JSON decode error at {spot}: {e}", 'warn')
                time.sleep(0.5)
        raise ZprpResponseError(f"_get_request_json failed at {spot} for {link}")

    def fetch_full_timetable(self, desired_season: str, wzpr_list: list[str], central_level_only: bool) -> pd.DataFrame:
        start = time.perf_counter()
        data = list(self._stream_games(desired_season, wzpr_list, central_level_only))
        df   = pd.DataFrame(data)
        dur  = time.perf_counter() - start
        print(f"SYNC: {len(df)} rows from {self.request_counter} reqs in {dur:.2f}s")
        return df

    def _stream_games(self, desired_season, wzpr_list, central_level_only):
        season = self._find_season(desired_season)
        for gt in self._fetch_game_types(season, wzpr_list, central_level_only):
            for rnd in self._fetch_rounds(gt):
                for ser in self._fetch_series(rnd):
                    for gm in self._fetch_games(ser):
                        yield self._assemble_game_row(season, gt, rnd, ser, gm)

    def _find_season(self, desired_season):
        link = self.get_link_zprp('seasons_api', {})
        all_seasons = self._get_request_json(link, 'seasons_api')
        for s in all_seasons.values():
            if s.get("Nazwa") == desired_season:
                return s.copy()
        raise ValueError(f"Sezon `{desired_season}` nie znaleziony.")

    def _fetch_game_types(self, season, wzpr_list, central_level_only):
        link = self.get_link_zprp('game_types_api', {'season': season['ID_sezon']})
        types = self._get_request_json(link, 'game_types_api')
        for gt in types.values():
            if not int(gt.get('Wystartowano', 0)): continue
            ok_wzpr    = wzpr_list and gt['NazwaWZPR'] in wzpr_list
            ok_central = central_level_only and len(gt['code_export'].split('/')) == 1
            if ok_wzpr or ok_central:
                yield gt

    def _fetch_rounds(self, game_type):
        link = self.get_link_zprp('game_rounds_api', {'type': game_type["Id_rozgrywki"]})
        return self._get_request_json(link, 'game_rounds_api').values()

    def _fetch_series(self, game_round):
        link = self.get_link_zprp('series_api', {'round': game_round["Id"]})
        return self._get_request_json(link, 'series_api').values()

    def _fetch_games(self, game_series):
        link = self.get_link_zprp('games_api', {'series': game_series["ID_kolejka"]})
        return self._get_request_json(link, 'games_api').values()

class ZprpApiClientAsync(ZprpApiCommon):
    def __init__(self, utils=None, debug_logging: bool = False):
        super().__init__(utils=utils, debug_logging=debug_logging)
        self.client = httpx.AsyncClient(timeout=10.0)

    async def _get_request_json(self, link: str, spot: str):
        self.request_counter += 1
        for i in range(6):
            try:
                resp = await self.client.get(link)
                resp.raise_for_status()
                return resp.json()
            except (httpx.RequestError, ValueError) as e:
                self.error_counter += 1
                self.utils.log_this(f"Async JSON error at {spot}: {e}", 'warn')
                await asyncio.sleep(0.5)
        raise ZprpResponseError(f"_get_request_json failed at {spot} for {link}")

    async def fetch_full_timetable(self, desired_season, wzpr_list, central_level_only):
        start = time.perf_counter()
        data = [gm async for gm in self._stream_games(desired_season, wzpr_list, central_level_only)]
        df   = pd.DataFrame(data)
        dur  = time.perf_counter() - start
        self.utils.log_this(f"ASYNC: {len(df)} rows, {self.request_counter} reqs, {dur:.2f}s", 'info')
        return df

    async def _stream_games(self, desired_season, wzpr_list, central_level_only):
        season = await self._find_season(desired_season)
        # analogicznie do wersji synchronicznej, ale z gather(...) jeśli chcesz
        for gt in [gt async for gt in self._fetch_game_types(season, wzpr_list, central_level_only)]:
            for rnd in await self._get_request_json(self.get_link_zprp('game_rounds_api', {'type': gt['Id_rozgrywki']}), 'game_rounds_api'):
                for ser in await self._get_request_json(self.get_link_zprp('series_api', {'round': rnd['Id']}), 'series_api'):
                    for gm in await self._get_request_json(self.get_link_zprp('games_api', {'series': ser['ID_kolejka']}), 'games_api'):
                        yield self._assemble_game_row(season, gt, rnd, ser, gm)
