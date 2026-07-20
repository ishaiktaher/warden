FROM python:3.11-slim@sha256:baf89808ec37adeaab83cec287adb4a2afa4a11c1d51e961c7ec737877e61af6 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    CONTROL_PLANE_ENV=prod
WORKDIR /app
RUN groupadd --system warden && useradd --system --gid warden --home /app warden
ARG REQUIREMENTS_FILE=requirements.txt
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r "${REQUIREMENTS_FILE}"
COPY --chown=warden:warden control_plane control_plane
COPY --chown=warden:warden ui ui
COPY --chown=warden:warden scripts scripts
USER warden
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/live', timeout=3)"
CMD ["uvicorn", "control_plane.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
