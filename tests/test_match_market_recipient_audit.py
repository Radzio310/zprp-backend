"""Migawka wysyłki zachowuje powody na poziomie osób, także po zmianie ustawień."""

import ast
import asyncio
import copy
from pathlib import Path
from types import SimpleNamespace


SOURCE = (Path(__file__).resolve().parents[1] / "app" / "match_market.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
FUNCTIONS = {node.name: node for node in TREE.body if isinstance(node, ast.AsyncFunctionDef)}


class Column:
    def in_(self, value):
        return value

    def is_(self, value):
        return value

    def __eq__(self, value):
        return value


class Columns:
    def __getattr__(self, name):
        return Column()


class Query:
    def where(self, *args):
        return self


def test_offer_audit_distinguishes_people_devices_manager_route_and_author():
    module = ast.fix_missing_locations(ast.Module(body=[
        ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
        FUNCTIONS["_recipient_audit"],
    ], type_ignores=[]))
    local = [
        {"judge_id": str(number), "full_name": f"Sędzia {number}", "photo_url": f"https://photo/{number}"}
        for number in range(1, 6)
    ]
    devices = [
        {"judge_id": str(number), "token_type": "device_fcm", "token": f"token-{number}",
         "notification_prefs": {"enabled": number != 4}}
        for number in (2, 3, 4, 9)
    ]

    class Database:
        calls = 0

        async def fetch_all(self, query):
            self.calls += 1
            return local if self.calls == 1 else devices

    async def extra_cards(ids):
        assert ids == ["9"]
        return {"9": {"full_name": "Admin 9", "photo_url": "https://photo/9"}}

    namespace = {
        "database": Database(),
        "select": lambda *args: Query(),
        "or_": lambda *args: args,
        "province_judges": SimpleNamespace(c=Columns()),
        "push_tokens": SimpleNamespace(c=Columns()),
        "spellings": lambda value: [value],
        "_row": dict,
        "_s": lambda value: str(value or "").strip(),
        "_judges_by_id": extra_cards,
        "market_pushes_allowed": lambda prefs: prefs.get("enabled") is not False,
    }
    exec(compile(module, "match_market._recipient_audit", "exec"), namespace)
    audit = asyncio.run(namespace["_recipient_audit"](
        "SLASKIE", ["2"], {"perJudge": {"2": "accepted"}}, broadcast=True,
        context={"authorId": "1", "managerIds": ["3", "9"],
                 "managerReport": {"perJudge": {"3": "accepted", "9": "accepted"}}},
    ))
    people = {person["judgeId"]: person for person in audit["people"]}
    assert audit["provinceCount"] == 5
    assert len(people) == 6
    assert {judge_id: person["status"] for judge_id, person in people.items()} == {
        "1": "own_offer", "2": "accepted", "3": "accepted",
        "4": "muted", "5": "no_device", "9": "accepted",
    }
    assert people["9"]["route"] == "zarządzający"
    assert people["9"]["fullName"] == "Admin 9"


def test_recipient_page_is_admin_only_and_old_entries_are_not_reconstructed():
    source = ast.unparse(FUNCTIONS["admin_journal_recipients"])
    assert "may_manage_config(is_admin=actor.is_admin)" in source
    assert "match_market_events.c.province == key" in source
    assert "'available': False" in source


def test_push_report_counts_people_once_even_with_multiple_devices():
    push_source = (Path(__file__).resolve().parents[1] / "app" / "push" / "push.py").read_text(encoding="utf-8")
    push_tree = ast.parse(push_source)
    function = copy.deepcopy(next(node for node in push_tree.body if isinstance(node, ast.AsyncFunctionDef)
                                  and node.name == "send_push_to_judges_report"))
    function.body = [node for node in function.body if not isinstance(node, ast.ImportFrom) or node.module != "fcm"]
    module = ast.fix_missing_locations(ast.Module(body=[
        ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
        function,
    ], type_ignores=[]))

    class Database:
        async def fetch_all(self, query):
            return [
                {"installation_id": "failed", "judge_id": "2", "token": "bad", "token_type": "device_fcm", "notification_prefs": {}},
                {"installation_id": "accepted", "judge_id": "2", "token": "good", "token_type": "device_fcm", "notification_prefs": {}},
            ]

    async def send(token, *args, **kwargs):
        if token == "bad":
            raise RuntimeError("FCM rejected")

    async def invalidate(*args):
        pass

    namespace = {
        "database": Database(), "push_tokens": SimpleNamespace(c=Columns()),
        "select": lambda *args: Query(), "or_": lambda *args: args,
        "send_fcm_message": send, "invalidate_rejected_fcm_token": invalidate,
        "logger": SimpleNamespace(warning=lambda *args, **kwargs: None),
    }
    exec(compile(module, "push.send_push_to_judges_report", "exec"), namespace)
    report = asyncio.run(namespace["send_push_to_judges_report"](["2", "2", "3"], "Test", "Body", app_variant="baza"))
    assert report["requestedJudges"] == 2
    assert report["acceptedJudges"] == 1
    assert report["acceptedDevices"] == 1
    assert report["failedDevices"] == 1
    assert report["perJudge"] == {"2": "accepted", "3": "no_device"}
