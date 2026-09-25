# Sentry UA - one image, two roles (see compose.yaml):
#   collector:  python palo_ua_tracker.py
#   dashboard:  python run_dashboard.py --no-collector   (default CMD)
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Both processes read/write the database here - a mounted volume, not
    # the image. Overrides config.yaml's database.db_path.
    SENTRY_UA_DB_PATH=/data/user_agents.db \
    # Streamlit must listen on all container interfaces to be reachable
    # through a published port; headless skips its first-run prompt.
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboard.py palo_ua_tracker.py run_dashboard.py config.yaml ./
COPY sentry_ua ./sentry_ua

# Unprivileged runtime user. 1514/udp and 8501/tcp are both >1024, so
# nothing here needs root.
RUN useradd --system --uid 10001 --no-create-home --home-dir /app sentry \
    && mkdir /data \
    && chown sentry /data
USER sentry

VOLUME ["/data"]
EXPOSE 8501/tcp 1514/udp

# run_dashboard.py (not plain `streamlit run`) so config.yaml's https
# section still works inside the container.
CMD ["python", "run_dashboard.py", "--no-collector"]
