# app/utils.py

import httpx
import chardet
from typing import Optional, Tuple

async def fetch_with_correct_encoding(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    json: Optional[dict] = None,
    cookies: Optional[dict] = None,
) -> Tuple[httpx.Response, str]:
    """
    Wysyła żądanie i zwraca (response, text),
    automatycznie wykrywając i używając poprawnego kodowania znaków.
    """
    resp = await client.request(
        method,
        url,
        params=params,
        data=data,
        json=json,
        cookies=cookies,
        follow_redirects=True,
    )
    raw = resp.content
    detected = chardet.detect(raw)
    encoding = detected.get("encoding") or "utf-8"
    text = raw.decode(encoding, errors="replace")
    return resp, text

# Dodano klasę Utils do logowania
import logging
from datetime import datetime

class Utils:
    def __init__(self, logfile_roller: Optional[str] = None, logfile_main_dirs: Optional[list] = None):
        self.logger = logging.getLogger("zprp")
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.logger_max_level = logging.INFO

    def log_this(self, line: str, level: str = 'debug', exc_info=None, pure_print: bool = False):
        """
        Loguje wiadomość lub wypisuje ją bezpośrednio.
        """
        if pure_print:
            print(line)
        else:
            log_level = getattr(logging, level.upper(), logging.DEBUG)
            self.logger.log(log_level, line, exc_info=exc_info)
            self.logger_max_level = max(self.logger_max_level, log_level)