"""The legacy-collection cleanup command: explicit, idempotent, and narrow to the five collections it names.

It is operator tooling, not a migration. Nothing in the application invokes it, it drops nothing until an
operator passes ``--apply``, and the five names it knows are exactly the collections the removed impact engine
owned -- never one the application still reads or writes.
"""

import runpy
from pathlib import Path
from types import SimpleNamespace
from typing import Self

import pytest

from mist_config_guardian_backend.models import document_models

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "drop-legacy-impact-collections.py"
BACKEND_SRC = REPO_ROOT / "backend" / "src"

LEGACY = {
    "impact_investigations",
    "investigation_revisions",
    "impact_model_request_artifacts",
    "impact_adjudications",
    "neighbor_bindings",
}


@pytest.fixture
def command() -> dict:
    """The script's namespace. Loading it must not connect to anything or drop anything."""
    return runpy.run_path(str(SCRIPT))


class FakeCollection:
    def __init__(self, documents: int) -> None:
        self._documents = documents

    async def estimated_document_count(self) -> int:
        return self._documents


class FakeDatabase:
    """Just enough of a MongoDB database to record what the command asked of it."""

    def __init__(self, **collections: int) -> None:
        self._collections = dict(collections)
        self.dropped: list[str] = []
        self.counted: list[str] = []

    async def list_collection_names(self) -> list[str]:
        return sorted(self._collections)

    def __getitem__(self, name: str) -> FakeCollection:
        self.counted.append(name)
        return FakeCollection(self._collections[name])

    async def drop_collection(self, name: str) -> None:
        self.dropped.append(name)
        self._collections.pop(name, None)


def test_the_command_knows_exactly_the_five_legacy_collections(command) -> None:
    assert set(command["LEGACY_COLLECTIONS"]) == LEGACY
    # Ordered, so two operators reading two runs compare the same report.
    assert list(command["LEGACY_COLLECTIONS"]) == sorted(LEGACY)


def test_no_collection_the_application_still_uses_can_be_dropped(command) -> None:
    live = {model.Settings.name for model in document_models()}
    assert live.isdisjoint(command["LEGACY_COLLECTIONS"])
    assert {"guardian_investigations", "guardian_runs"} <= live


@pytest.mark.asyncio
async def test_nothing_is_dropped_until_an_operator_asks_for_it(command, capsys) -> None:
    database = FakeDatabase(impact_investigations=12, guardian_runs=3)

    dropped = await command["drop_legacy_collections"](database, apply=False)

    assert dropped == []
    assert database.dropped == []
    output = capsys.readouterr().out
    assert "--apply" in output
    assert "impact_investigations" in output
    assert "12" in output


@pytest.mark.asyncio
async def test_applying_drops_only_the_legacy_collections_that_exist(command, capsys) -> None:
    database = FakeDatabase(impact_investigations=12, neighbor_bindings=1, guardian_runs=3, organizations=2)

    dropped = await command["drop_legacy_collections"](database, apply=True)

    assert dropped == ["impact_investigations", "neighbor_bindings"]
    assert database.dropped == ["impact_investigations", "neighbor_bindings"]
    # Every one of the five is reported, whether it was there or not, so the report says what the database holds.
    output = capsys.readouterr().out
    for name in LEGACY:
        assert name in output
    # And each drop is announced as it happens, not only in the closing summary.
    assert "dropped impact_investigations" in output
    assert "dropped neighbor_bindings" in output


@pytest.mark.asyncio
async def test_a_failure_partway_through_still_records_what_was_already_dropped(command, capsys) -> None:
    class Failing(FakeDatabase):
        async def drop_collection(self, name: str) -> None:
            if name == "impact_investigations":
                msg = "not authorized"
                raise RuntimeError(msg)
            await super().drop_collection(name)

    database = Failing(impact_adjudications=1, impact_investigations=2)

    with pytest.raises(RuntimeError):
        await command["drop_legacy_collections"](database, apply=True)

    # The operator is left knowing exactly what is already gone, so a re-run is unambiguous.
    output = capsys.readouterr().out
    assert "dropped impact_adjudications" in output
    assert "dropped impact_investigations" not in output
    assert database.dropped == ["impact_adjudications"]


@pytest.mark.asyncio
async def test_running_it_again_changes_nothing_and_still_succeeds(command, capsys) -> None:
    database = FakeDatabase(impact_adjudications=4, guardian_investigations=1)
    await command["drop_legacy_collections"](database, apply=True)
    capsys.readouterr()

    dropped = await command["drop_legacy_collections"](database, apply=True)

    assert dropped == []
    assert database.dropped == ["impact_adjudications"]
    assert "guardian_investigations" not in capsys.readouterr().out


@pytest.mark.asyncio
async def test_a_collection_that_cannot_be_counted_is_still_dropped_and_reported(command, capsys) -> None:
    class Unreadable(FakeDatabase):
        def __getitem__(self, name: str) -> FakeCollection:
            msg = "count failed"
            raise RuntimeError(msg)

    database = Unreadable(investigation_revisions=7)

    dropped = await command["drop_legacy_collections"](database, apply=True)

    assert dropped == ["investigation_revisions"]
    assert "unknown" in capsys.readouterr().out


class Bound:
    """A stand-in for ``pymongo.timeout`` that records its deadline and what ran inside it."""

    def __init__(self) -> None:
        self.seconds: float | None = None
        self.order: list[str] = []

    def timeout(self, seconds: float) -> Self:
        self.seconds = seconds
        return self

    def __enter__(self) -> Self:
        self.order.append("enter")
        return self

    def __exit__(self, *_exc: object) -> bool:
        self.order.append("exit")
        return False


@pytest.mark.asyncio
async def test_the_cleanup_runs_under_a_deadline_of_its_own(command, monkeypatch, capsys) -> None:
    """Selecting a server is bounded on its own; the listing, the counts and the drops after it are not."""
    bound = Bound()
    database = FakeDatabase(impact_adjudications=1)
    listed = database.list_collection_names

    async def record() -> list[str]:
        bound.order.append("listed")
        return await listed()

    database.list_collection_names = record

    class FakeClient:
        def __init__(self, _url: str, **given: object) -> None:
            bound.order.append(f"selection={given['serverSelectionTimeoutMS'] > 0}")
            self.admin = SimpleNamespace(command=self._ping)

        async def _ping(self, *_args: object) -> dict:
            return {"ok": 1}

        def __getitem__(self, _name: str) -> FakeDatabase:
            return database

        async def close(self) -> None:
            return None

    # run_path returns a copy of the namespace; the functions still read the live one.
    monkeypatch.setitem(command["run"].__globals__, "AsyncMongoClient", FakeClient)
    monkeypatch.setitem(command["run"].__globals__, "pymongo", bound)

    assert await command["run"](apply=False) == 0
    assert bound.seconds == command["OPERATION_TIMEOUT_SECONDS"]
    assert bound.order == ["selection=True", "enter", "listed", "exit"]
    assert "Would drop 1" in capsys.readouterr().out


def test_the_application_never_runs_the_command_itself() -> None:
    # It is operator tooling: no module, task or schedule may reach it, so it cannot run at startup or on a tick.
    sources = list(BACKEND_SRC.rglob("*.py"))
    assert sources
    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert "drop-legacy-impact-collections" not in text, path
        assert "drop_legacy_collections" not in text, path
