#!/bin/sh
set -eu

certificate=/etc/nginx/ssl/server.crt
private_key=/etc/nginx/ssl/server.key

fingerprint() {
  cksum "$certificate" "$private_key" 2>/dev/null || true
}

(
  previous="$(fingerprint)"
  while sleep 10; do
    current="$(fingerprint)"
    if [ -n "$current" ] && [ "$current" != "$previous" ]; then
      if nginx -t >/dev/null 2>&1; then
        nginx -s reload
        previous="$current"
        echo "SEC360: HTTPS certificate changed; nginx reloaded"
      else
        echo "SEC360: uploaded HTTPS certificate failed nginx validation; reload skipped" >&2
      fi
    fi
  done
) &
