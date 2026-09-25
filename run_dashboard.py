"""Launches the Sentry UA dashboard and (by default) the UDP syslog
collector alongside it, wiring up HTTPS from config.yaml when enabled.

Streamlit's own HTTPS support (server.sslCertFile / server.sslKeyFile) has
to be known before its server starts listening - by the time dashboard.py
itself runs, Streamlit has already bound its socket, so the app script
can't turn HTTPS on for its own run. This launcher reads config.yaml's
`https` section first and passes the cert/key through to `streamlit run`
as command-line flags instead (Streamlit accepts any config.toml option
this way too), before Streamlit ever starts listening.

It also starts palo_ua_tracker.py as a background process before handing
control to Streamlit, and stops it again when Streamlit exits (Ctrl+C,
closed window, or a crash) - one command starts and stops both pieces
together, the same as running them separately by hand, without leaving an
orphaned listener behind. Pass --no-collector to start only the dashboard,
e.g. when palo_ua_tracker.py is already running elsewhere (its own service,
a separate host) and this run should leave it alone.

Usage:
    python run_dashboard.py [--no-collector] [any extra "streamlit run" arguments]

Plain `streamlit run dashboard.py` still works exactly as before and never
touches the collector - this launcher is only needed for HTTPS and/or the
combined start/stop convenience.
"""
import subprocess
import sys

import yaml


def main():
    args = sys.argv[1:]
    start_collector = "--no-collector" not in args
    args = [a for a in args if a != "--no-collector"]

    try:
        with open("config.yaml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except OSError as e:
        sys.exit(f"Couldn't read config.yaml: {e}")

    https_cfg = config.get("https", {}) or {}
    cmd = [sys.executable, "-m", "streamlit", "run", "dashboard.py"]

    if https_cfg.get("enabled"):
        cert_file = (https_cfg.get("cert_file") or "").strip()
        key_file = (https_cfg.get("key_file") or "").strip()
        # Streamlit itself requires both sslCertFile and sslKeyFile to be
        # set together, or it exits with an error - checked here too so the
        # failure mode is a clear message pointing at config.yaml, not a
        # less obvious error from deep inside Streamlit's own startup.
        if not cert_file or not key_file:
            sys.exit(
                "config.yaml has https.enabled: true, but cert_file and/or "
                "key_file is blank. Both are required together - see the "
                "https section in config.yaml."
            )
        cmd += [
            f"--server.sslCertFile={cert_file}",
            f"--server.sslKeyFile={key_file}",
        ]
        print(f"Starting Sentry UA over HTTPS (cert: {cert_file})")
    else:
        print("Starting Sentry UA over HTTP (set https.enabled: true in config.yaml to use TLS)")

    cmd += args

    collector_proc = None
    if start_collector:
        print("Starting the syslog collector (palo_ua_tracker.py) in the background...")
        collector_proc = subprocess.Popen([sys.executable, "palo_ua_tracker.py"])
    else:
        print("--no-collector given - not starting palo_ua_tracker.py; assuming it's running elsewhere.")

    try:
        result = subprocess.run(cmd, check=False)
        return_code = result.returncode
    finally:
        if collector_proc is not None:
            print("Stopping the syslog collector...")
            collector_proc.terminate()
            try:
                collector_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                collector_proc.kill()
                collector_proc.wait()

    sys.exit(return_code)


if __name__ == "__main__":
    main()
