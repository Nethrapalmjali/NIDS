# NIDS production image
#   docker build -t nids .
#   docker run --rm -v nids-data:/data -e NIDS_ADMIN_PASSWORD='change-me-please' nids init
#   docker run -d -p 127.0.0.1:5000:5000 -v nids-data:/data --name nids nids
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NIDS_INSTANCE=/data \
    NIDS_HOST=0.0.0.0 \
    NIDS_PORT=5000

# libgomp1: OpenMP runtime for LightGBM/XGBoost; libpcap: live capture with Scapy
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY nids ./nids
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin nids \
 && mkdir -p /data && chown nids:nids /data \
 && rm -rf /app/nids/instance

USER nids
VOLUME ["/data"]
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/readyz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["python", "-m", "nids.app"]
CMD ["serve"]
