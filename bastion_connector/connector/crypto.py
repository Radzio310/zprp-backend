"""Szyfrowanie stanu sesji w spoczynku: AES-256-GCM, klucz z BASTION_SECRETS_KEY.

Format: 0x01 | nonce(12) | szyfrogram+tag. AAD wiaze plik z kluczem polaczenia, wiec stan jednego polaczenia
nie da sie podstawic pod drugie. Rotacja: nowy klucz + stare w BASTION_SECRETS_KEY_PREVIOUS; odczyt probuje
kolejno wszystkie, a store przepisuje stan nowym kluczem.
"""
from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"\x01"


class CryptoError(Exception):
    pass


def parse_key(value: str) -> bytes:
    value = (value or "").strip()
    if not value:
        raise CryptoError("brak klucza BASTION_SECRETS_KEY")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as e:  # noqa: BLE001
        raise CryptoError("klucz nie jest poprawnym base64") from e
    if len(raw) != 32:
        raise CryptoError("klucz musi miec 32 bajty (AES-256)")
    return raw


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return VERSION + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(keys: list[bytes], blob: bytes, aad: bytes) -> tuple[bytes, int]:
    """Zwraca (tekst, indeks klucza). Indeks > 0 = stan trzeba przepisac nowym kluczem."""
    if len(blob) < 1 + 12 + 16 or blob[:1] != VERSION:
        raise CryptoError("nieznany format stanu")
    nonce, ct = blob[1:13], blob[13:]
    for i, k in enumerate(keys):
        try:
            return AESGCM(k).decrypt(nonce, ct, aad), i
        except InvalidTag:
            continue
    raise CryptoError("nie udalo sie odszyfrowac stanu (zly klucz albo uszkodzony plik)")
