"""run_dashboard.py: HTTPS flag wiring and collector start/stop, with the
actual processes replaced by recorders."""
import subprocess
import sys

import pytest

import run_dashboard


class FakeProc:
    def __init__(self, hang=False):
        self.hang = hang
        self.events = []

    def terminate(self):
        self.events.append("terminate")

    def kill(self):
        self.events.append("kill")

    def wait(self, timeout=None):
        self.events.append(("wait", timeout))
        if self.hang and "kill" not in self.events:
            raise subprocess.TimeoutExpired("collector", timeout)


@pytest.fixture
def launcher(tmp_path, monkeypatch):
    """Returns run(config_text, *argv) -> (exit_code, streamlit_cmd, collector_proc)."""
    monkeypatch.chdir(tmp_path)

    def run(config_text, *argv, streamlit_rc=0, hang=False):
        (tmp_path / "config.yaml").write_text(config_text, encoding="utf-8")
        calls = {"popen": [], "run": []}
        proc = FakeProc(hang=hang)

        def fake_popen(cmd):
            calls["popen"].append(cmd)
            return proc

        def fake_run(cmd, check):
            calls["run"].append(cmd)
            return subprocess.CompletedProcess(cmd, streamlit_rc)

        monkeypatch.setattr(run_dashboard.subprocess, "Popen", fake_popen)
        monkeypatch.setattr(run_dashboard.subprocess, "run", fake_run)
        monkeypatch.setattr(sys, "argv", ["run_dashboard.py", *argv])
        with pytest.raises(SystemExit) as exit_info:
            run_dashboard.main()
        return exit_info.value.code, calls, proc

    return run


HTTP_CONFIG = "https:\n  enabled: false\n"
HTTPS_CONFIG = "https:\n  enabled: true\n  cert_file: ' /etc/cert.pem '\n  key_file: /etc/key.pem\n"


def test_http_default_starts_collector_and_streamlit(launcher):
    code, calls, proc = launcher(HTTP_CONFIG)
    assert code == 0
    assert calls["popen"] == [[sys.executable, "palo_ua_tracker.py"]]
    (cmd,) = calls["run"]
    assert cmd == [sys.executable, "-m", "streamlit", "run", "dashboard.py"]
    assert not any("ssl" in part for part in cmd)
    assert proc.events[0] == "terminate"  # collector stopped when Streamlit exits


def test_https_passes_trimmed_cert_and_key(launcher):
    _, calls, _ = launcher(HTTPS_CONFIG)
    (cmd,) = calls["run"]
    assert "--server.sslCertFile=/etc/cert.pem" in cmd
    assert "--server.sslKeyFile=/etc/key.pem" in cmd


@pytest.mark.parametrize(
    "config_text",
    [
        "https:\n  enabled: true\n  cert_file: /c.pem\n  key_file: ''\n",
        "https:\n  enabled: true\n  cert_file: ''\n  key_file: /k.pem\n",
        "https:\n  enabled: true\n",
    ],
)
def test_https_requires_both_files(launcher, config_text):
    code, calls, _ = launcher(config_text)
    assert "cert_file and/or key_file is blank" in str(code)
    assert calls["run"] == [] and calls["popen"] == []  # nothing started


def test_no_collector_flag_and_extra_args_pass_through(launcher):
    _, calls, _ = launcher(HTTP_CONFIG, "--no-collector", "--server.port=9000")
    assert calls["popen"] == []
    assert calls["run"][0][-1] == "--server.port=9000"
    assert "--no-collector" not in calls["run"][0]


def test_streamlit_exit_code_is_propagated(launcher):
    code, _, _ = launcher(HTTP_CONFIG, streamlit_rc=3)
    assert code == 3


def test_hung_collector_is_killed(launcher):
    _, _, proc = launcher(HTTP_CONFIG, hang=True)
    assert proc.events[:3] == ["terminate", ("wait", 5), "kill"]


def test_missing_config_is_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["run_dashboard.py"])
    with pytest.raises(SystemExit) as exit_info:
        run_dashboard.main()
    assert "Couldn't read config.yaml" in str(exit_info.value.code)


def test_empty_config_means_plain_http(launcher):
    code, calls, _ = launcher("")
    assert code == 0
    assert not any("ssl" in part for part in calls["run"][0])
