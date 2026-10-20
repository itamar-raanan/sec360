# SEC360 Network Collector

The Network Collector runs inside the management network and is the only component
that stores credentials for Cisco WLC, FortiGate, and MikroTik SwOS. It makes outbound
HTTPS requests to SEC360; SEC360 never opens a connection to the collector or to those
network devices.

## Deploy

1. In SEC360, open **Network Map → Config**, create a collector, and copy the token.
   The token is displayed only when it is created or rotated.
2. Copy `config.example.yml` to `config.yml` and set the local device addresses.
3. Copy the device secrets into a local `.env` file. Do not commit that file.
4. Add the WLC SSH host key to `known_hosts`:

   ```bash
   ssh-keyscan -p 22 10.10.1.20 > known_hosts
   ```

   Verify the fingerprint through a trusted channel before starting the container.
5. Start the service:

   ```bash
   docker compose up -d --build
   docker compose logs -f sec360-network-collector
   ```

The container runs as UID/GID `10001`, drops all Linux capabilities, and publishes no
ports. Its named volume contains only the SQLite delivery queue and monotonic source
sequence counters.

## Configuration

Secrets may be referenced as `${ENV_VAR}` anywhere in `config.yml`. The supported source
types are:

- `cisco_wlc`: SSH collection of APs, clients, and WLAN/SSID mapping.
- `fortigate`: HTTPS REST collection of DHCP leases.
- `mikrotik`: HTTP Digest collection of the SwOS learned-host table.

TLS verification and SSH host-key verification are enabled by default. MikroTik SwOS
often provides only HTTP on the management network; keep that connection on a trusted,
segmented network. `allow_unknown_host_key` should be used only for initial diagnostics.

## Delivery guarantees

Each successful source collection becomes a complete snapshot with a UUID and a
monotonic per-source sequence. The snapshot is written to SQLite before transmission.
SEC360 acknowledges duplicates without creating duplicate observations and rejects stale
sequences. Temporary HTTP, authentication, and server failures remain queued with
exponential backoff. Invalid payloads are retained as dead deliveries for diagnosis.

Run one cycle interactively with:

```bash
docker compose run --rm sec360-network-collector --once
```

## Health and troubleshooting

The container health check reflects the collector process and its last completed loop.
Source errors are included in the heartbeat visible in **Network Map → Config**. Delivery
failures remain in the local queue and are retried; inspect them with:

```bash
docker compose logs --tail=200 sec360-network-collector
docker compose exec sec360-network-collector python -m sec360_collector.main --once
```

The SEC360 URL must be the externally reachable HTTPS base URL, without `/api`. The
collector appends the versioned API paths itself. If a private CA signs SEC360's
certificate, mount its CA bundle into the container and point `REQUESTS_CA_BUNDLE` to it
instead of disabling TLS verification.
