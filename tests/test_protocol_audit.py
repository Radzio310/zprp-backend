"""
Dziennik generowania protokołów i podpis pliku.

Sedno tych testów: podpis ma odpowiadać na pytanie „czy to nasz plik dla TEGO
stanu", a nie „czy da się go odczytać". Fałszywka też jest czytelna — i właśnie
dlatego `_verify_protocol_signature` zwraca claim także dla podpisu odrzuconego:
admin ma widzieć, co ktoś próbował podstawić.
"""
import gzip
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app import results as r


@pytest.fixture(scope="module")
def rsa_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


@pytest.fixture(autouse=True)
def _patch_keys(monkeypatch, rsa_keys):
    monkeypatch.setattr(r, "get_rsa_keys", lambda: rsa_keys)


CLAIM = {
    "v": 1,
    "c": "BZ-8F3A-2C91",
    "m": "190756",
    "n": "PP/846",
    "j": "5102138",
    "a": "WITKOWICZ Radosław",
    "t": "2026-08-15T15:54:13+02:00",
    "s": "9c1f" * 16,
}


# ─────────────────────── kod audytu ───────────────────────

def test_audit_code_shape():
    code = r._protocol_audit_code()
    assert code.startswith("BZ-")
    assert len(code) == len("BZ-XXXX-XXXX")
    body = code[3:7] + code[8:]
    assert all(ch in r._AUDIT_ALPHABET for ch in body)


def test_audit_code_avoids_ambiguous_letters():
    """Kod bywa przepisywany z wydruku ręcznie — I/L/O/U odpadają."""
    assert not (set("ILOU") & set(r._AUDIT_ALPHABET))


def test_audit_codes_are_unique_enough():
    assert len({r._protocol_audit_code() for _ in range(500)}) == 500


# ─────────────────────── skrót stanu ───────────────────────

def test_canonical_json_ignores_key_order():
    """Ten sam stan musi dać ten sam skrót niezależnie od kolejności pól —
    inaczej podpis rozjeżdża się sam z siebie między wersjami aplikacji."""
    a = {"b": 1, "a": {"y": 2, "x": 3}}
    b = {"a": {"x": 3, "y": 2}, "b": 1}
    assert r._canonical_json(a) == r._canonical_json(b)
    assert r._sha256_bytes(r._canonical_json(a)) == r._sha256_bytes(r._canonical_json(b))


def test_canonical_json_keeps_polish_letters():
    raw = r._canonical_json({"a": "Zażółć"})
    assert "Zażółć" in raw.decode("utf-8")


def test_state_survives_gzip_roundtrip():
    state = {"matchConfig": {"matchNumber": "PP/846"}, "protocol": [{"t": 1}]}
    blob = gzip.compress(r._canonical_json(state))
    assert json.loads(gzip.decompress(blob).decode("utf-8")) == state


# ─────────────────────── podpis ───────────────────────

def test_sign_and_verify_roundtrip():
    token = r._sign_protocol_claim(CLAIM)
    ok, claim = r._verify_protocol_signature(token)
    assert ok is True
    assert claim == CLAIM


def test_verify_rejects_tampered_payload():
    token = r._sign_protocol_claim(CLAIM)
    payload_b64, sig_b64 = token.split(".", 1)
    forged = dict(CLAIM, a="KTOŚ INNY")
    bad = "%s.%s" % (r._b64u(r._canonical_json(forged)), sig_b64)

    ok, claim = r._verify_protocol_signature(bad)
    assert ok is False
    # …ale podmienioną treść admin i tak widzi.
    assert claim["a"] == "KTOŚ INNY"


def test_verify_rejects_foreign_key(monkeypatch):
    token = r._sign_protocol_claim(CLAIM)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(r, "get_rsa_keys", lambda: (other, other.public_key()))
    ok, _ = r._verify_protocol_signature(token)
    assert ok is False


@pytest.mark.parametrize("junk", ["", "bezkropki", "a.b", "!!!.???"])
def test_verify_survives_junk(junk):
    ok, claim = r._verify_protocol_signature(junk)
    assert ok is False
    assert claim == {}


# ─────────────────────── metadane ───────────────────────

def test_xmp_escapes_and_skips_empty():
    xmp = r._protocol_xmp({"code": "BZ-1", "matchNumber": "A&B<C>", "empty": ""})
    assert "<baza:code>BZ-1</baza:code>" in xmp
    assert "A&amp;B&lt;C&gt;" in xmp
    assert "baza:empty" not in xmp
    assert r._XMP_NS in xmp


def test_audit_public_drops_state_blob():
    """Spakowany stan potrafi mieć setki kilobajtów i nie ma czego szukać w
    liście wpisów — wydajemy go osobnym endpointem."""
    row = {
        "code": "BZ-1",
        "state_gzip": b"\x1f\x8b" * 100,
        "created_at": None,
        "actor_name": "X",
    }
    out = r._audit_public(row)
    assert "state_gzip" not in out
    assert out["actor_name"] == "X"
