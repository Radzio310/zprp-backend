# app/clients/zprp_client.py

import asyncio
from datetime import date
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
        row = {}
        row.update(season or {})
        row.update(game_type or {})
        row.update(game_round or {})
        row.update(game_series or {})
        row.update(game or {})
        return row

class ZprpApiClient(ZprpApiCommon):
    def __init__(self, utils=None, debug_logging: bool = False):
        super().__init__(utils=utils, debug_logging=debug_logging)
        self.session = requests.Session()

    def _get_request_json(self, link: str, spot: str):
        self.request_counter += 1
        if self.request_counter % 10 == 0:
            self.utils.log_this(f"Requests so far: {self.request_counter}", 'info')
        for _ in range(6):
            try:
                resp = self.session.get(link, timeout=10)
                resp.raise_for_status()
                return resp.json()
            except (requests.exceptions.JSONDecodeError, ValueError) as e:
                self.utils.log_this(f"JSON decode error at {spot}: {e}", 'warn')
                time.sleep(0.5)
            except requests.RequestException as e:
                self.utils.log_this(f"HTTP error at {spot}: {e}", 'warn')
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
        all_seasons = self._get_request_json(self.get_link_zprp('seasons_api', {}), 'seasons_api') or {}
        for s in all_seasons.values():
            if s.get("Nazwa") == desired_season:
                return s.copy()
        raise ValueError(f"Sezon `{desired_season}` nie znaleziony.")

    def _fetch_game_types(self, season, wzpr_list, central_level_only):
        types = self._get_request_json(
            self.get_link_zprp('game_types_api', {'season': season['ID_sezon']}),
            'game_types_api'
        ) or {}
        for gt in types.values():
            if not int(gt.get('Wystartowano', 0)):
                continue
            # Filtr WZPR tylko jeśli podany
            if wzpr_list and gt.get('NazwaWZPR') not in wzpr_list:
                continue
            # Filtr centralny tylko jeśli True
            code = gt.get('code_export')  # może być None
            if central_level_only and (not code or '/' in code):
                continue
            yield gt


    def _fetch_rounds(self, game_type):
        req = self._get_request_json(self.get_link_zprp('game_rounds_api', {'type': game_type["Id_rozgrywki"]}), 'game_rounds_api')
        return list(req.values()) if isinstance(req, dict) else []

    def _fetch_series(self, game_round):
        req = self._get_request_json(self.get_link_zprp('series_api', {'round': game_round["Id"]}), 'series_api')
        return list(req.values()) if isinstance(req, dict) else []

    def _fetch_games(self, game_series):
        req = self._get_request_json(self.get_link_zprp('games_api', {'series': game_series["ID_kolejka"]}), 'games_api')
        return list(req.values()) if isinstance(req, dict) else []
    
    @staticmethod
    def _normalize_match_number(s: str) -> str:
        return (str(s) or "").strip().upper()

    @classmethod
    def _game_has_number(cls, gm: dict, gt: dict, target_norm: str) -> bool:
        """
        Sprawdza, czy mecz `gm` ma numer równy `target_norm`.
        Oprócz klasycznych pól obsługujemy:
        - `RozgrywkiCode` (np. SPM/1),
        - kombinację: (gt.code_export || gt.code) + '/' + (gm.Nr || gm.nr || gm.Lp)
        """
        # 1) bezpośrednie pola w odpowiedzi meczu
        candidate_keys = (
            "RozgrywkiCode",          # <-- to właśnie masz w payloadzie
            "Nr_meczu", "nr_meczu",
            "Numer_meczu", "numer_meczu",
            "Numer", "nr",
            "Kod_meczu", "kod_meczu", "code_game",
        )
        for k in candidate_keys:
            if k in gm and cls._normalize_match_number(gm[k]) == target_norm:
                return True

        # 2) złożone: prefix z typu rozgrywek + '/' + numer z meczu
        prefixes = [gt.get("code_export"), gt.get("code")]
        numbers  = [gm.get("Nr"), gm.get("nr"), gm.get("Lp")]
        for p in prefixes:
            for n in numbers:
                if p and n:
                    composed = f"{p}/{n}"
                    if cls._normalize_match_number(composed) == target_norm:
                        return True

        return False

    @staticmethod
    def _game_date_str(gm: dict) -> str | None:
        """
        Zwraca 'YYYY-MM-DD' dla meczu (preferuje data_fakt, fallback data_prop),
        albo None jeśli brak daty.
        """
        s = gm.get("data_fakt") or gm.get("data_prop") or ""
        if not s:
            return None
        return str(s)[:10]  # szybkie, bez parsowania daty

    def find_game_by_number(
        self,
        desired_season: str,
        match_number: str,
        wzpr_list: list[str] | None = None,
        central_level_only: bool = False,
        match_date: date | None = None,   # <-- NOWE
    ) -> dict | None:
        season = self._find_season(desired_season)
        target = self._normalize_match_number(match_number)
        date_str = match_date.isoformat() if match_date else None

        for gt in self._fetch_game_types(season, wzpr_list or [], central_level_only):
            for rnd in self._fetch_rounds(gt):
                for ser in self._fetch_series(rnd):
                    for gm in self._fetch_games(ser):

                        # 1) jeśli podano dzień — filtruj najpierw po dacie
                        if date_str is not None:
                            gm_date = self._game_date_str(gm)
                            if gm_date != date_str:
                                continue

                        # 2) dopiero potem sprawdzaj numer
                        if self._game_has_number(gm, gt, target):
                            return self._assemble_game_row(season, gt, rnd, ser, gm)
        return None

class ZprpApiClientAsync(ZprpApiCommon):
    def __init__(self, utils=None, debug_logging: bool = False):
        super().__init__(utils=utils, debug_logging=debug_logging)
        self.client = httpx.AsyncClient(timeout=10.0)

    async def _get_request_json(self, link: str, spot: str):
        self.request_counter += 1
        for _ in range(6):
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
        # możemy uprościć asynchronicznie bez gather, analogicznie do sync
        for gt in [gt async for gt in self._fetch_game_types(season, wzpr_list, central_level_only)]:
            for rnd in await self.client.get(self.get_link_zprp('game_rounds_api', {'type': gt['Id_rozgrywki']})).json() or []:
                for ser in await self.client.get(self.get_link_zprp('series_api', {'round': rnd['Id']})).json() or []:
                    for gm in await self.client.get(self.get_link_zprp('games_api', {'series': ser['ID_kolejka']})).json() or []:
                        yield self._assemble_game_row(season, gt, rnd, ser, gm)
