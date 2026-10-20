FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEC360_COLLECTOR_CONFIG=/etc/sec360-collector/config.yml

RUN groupadd --system --gid 10001 collector \
    && useradd --system --uid 10001 --gid collector --home /var/lib/sec360-collector collector

WORKDIR /opt/sec360-collector
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sec360_collector ./sec360_collector

RUN mkdir -p /etc/sec360-collector /var/lib/sec360-collector \
    && chown -R collector:collector /var/lib/sec360-collector

USER collector
VOLUME ["/var/lib/sec360-collector"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=4 \
  CMD python -c "import os,time,sys; p='/tmp/sec360-collector.healthy'; sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p)<900 else 1)"

ENTRYPOINT ["python", "-m", "sec360_collector.main"]
