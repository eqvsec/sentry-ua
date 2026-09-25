import copy
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import palo_ua_tracker  # noqa: E402
from sentry_ua import demo  # noqa: E402


@pytest.fixture
def config():
    """A collector config matching config.yaml's shipped zones/indexes, with
    alerts disabled."""
    return copy.deepcopy(demo.DEMO_CONFIG)


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "user_agents.db")


@pytest.fixture
def conn(db_path):
    connection = palo_ua_tracker.init_db(db_path)
    yield connection
    connection.close()


@pytest.fixture
def no_alerts(monkeypatch):
    """Records send_gchat_alert calls instead of sending anything."""
    calls = []
    monkeypatch.setattr(
        palo_ua_tracker, "send_gchat_alert", lambda *args, **kwargs: calls.append((args, kwargs))
    )
    return calls


@pytest.fixture
def demo_db(tmp_path):
    path = str(tmp_path / "demo.db")
    demo.generate(path, seed=7)
    return path


def rows(conn, where="1=1", params=()):
    cur = conn.execute(f"SELECT * FROM user_agents WHERE {where}", params)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]
