# vetlnk static-analysis image — used only by `vetlnk scan -d` when no
# VT_API_KEY is configured. Never executes the analyzed file; only inspects it
# (libmagic type detection, entropy, strings, YARA) inside a container that
# vetlnk runs with networking disabled.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 binutils \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir python-magic==0.4.27 yara-python==4.5.1

COPY analyze.py /analyze.py
COPY rules /rules

ENTRYPOINT ["python", "/analyze.py"]
