import argparse
import logging
import signal
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import Any

from sec360_collector import __version__
from sec360_collector.client import PermanentDeliveryError, Sec360Client
from sec360_collector.config import load_config
from sec360_collector.fetchers import collect_source
from sec360_collector.queue import DeliveryQueue


LOG = logging.getLogger("sec360-collector")
STOP = Event()


def _collector_id(token: str) -> str:
    value = token.split("_", 2)[1]
    return str(uuid.UUID(value))


def _flush(queue: DeliveryQueue, client: Sec360Client) -> None:
    for delivery in queue.pending():
        attempts = delivery["attempts"] + 1
        try:
            response = client.ingest(delivery["payload"])
            queue.delivered(delivery["id"])
            LOG.info(
                "Delivered source=%s snapshot=%s disposition=%s records=%s",
                delivery["payload"]["source_id"], delivery["payload"]["snapshot_id"],
                response.get("disposition"), response.get("records_synced"),
            )
        except PermanentDeliveryError as exc:
            queue.failed(delivery["id"], attempts, str(exc), permanent=True)
            LOG.error("Snapshot rejected permanently: %s", exc)
        except Exception as exc:
            queue.failed(delivery["id"], attempts, str(exc))
            LOG.warning("Snapshot delivery deferred: %s", exc)
            break


def _collect_cycle(config: dict[str, Any], queue: DeliveryQueue, client: Sec360Client) -> dict[str, dict[str, Any]]:
    _flush(queue, client)
    statuses: dict[str, dict[str, Any]] = {}
    workers = min(8, max(1, len(config["sources"])))
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="source") as pool:
        futures = {pool.submit(collect_source, source): (source, time.monotonic()) for source in config["sources"]}
        for future in as_completed(futures):
            source, source_started = futures[future]
            source_id = source["id"]
            try:
                records = future.result()
                sequence = queue.next_sequence(source_id)
                payload = {
                    "schema_version": "1.0",
                    "collector_id": _collector_id(config["sec360"]["token"]),
                    "source_id": source_id,
                    "source_name": source.get("name") or source_id,
                    "source_type": source["type"],
                    "snapshot_id": str(uuid.uuid4()),
                    "sequence": sequence,
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "complete": True,
                    "records": records,
                    "health": {"status": "ok"},
                }
                queue.enqueue(payload)
                count = sum(len(value) for value in records.values() if isinstance(value, list))
                statuses[source_id] = {
                    "type": source["type"], "name": source.get("name") or source_id,
                    "status": "ok", "records": count,
                    "duration_ms": int((time.monotonic() - source_started) * 1000),
                }
                LOG.info("Collected source=%s type=%s records=%d", source_id, source["type"], count)
            except Exception as exc:
                statuses[source_id] = {
                    "type": source["type"], "name": source.get("name") or source_id,
                    "status": "error", "error": str(exc)[:500],
                    "duration_ms": int((time.monotonic() - source_started) * 1000),
                }
                LOG.error("Collection failed source=%s type=%s: %s", source_id, source["type"], exc)
    _flush(queue, client)
    try:
        client.heartbeat({"version": __version__, "queue_depth": queue.depth(), "sources": statuses})
    except Exception as exc:
        LOG.warning("Heartbeat delivery failed: %s", exc)
    LOG.info("Collection cycle finished in %.2fs; queue_depth=%d", time.monotonic() - started, queue.depth())
    Path("/tmp/sec360-collector.healthy").touch()
    return statuses


def run(config_path: str | None, once: bool) -> int:
    config = load_config(config_path)
    queue = DeliveryQueue(str(config["queue_path"]))
    client = Sec360Client(config["sec360"])
    interval = max(30, int(config.get("collection_interval_seconds") or 120))
    while not STOP.is_set():
        _collect_cycle(config, queue, client)
        if once:
            return 0
        STOP.wait(interval)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SEC360 on-premises Network Map collector")
    parser.add_argument("--config", help="Path to collector YAML configuration")
    parser.add_argument("--once", action="store_true", help="Collect and deliver one cycle, then exit")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    try:
        return run(args.config, args.once)
    except Exception:
        LOG.exception("Collector stopped with a fatal error")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
