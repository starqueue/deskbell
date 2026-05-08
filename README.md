# deskbell

A small Linux daemon that watches login events on the host and posts a
notification to [ntfy](https://ntfy.sh/) whenever someone successfully logs
in. Covers SSH, console (`util-linux login(1)`), graphical sessions
(GDM/LightDM/SDDM/XDM/KDM/greetd), and Cockpit web sessions.

It reads events from any of:

- `journalctl -f -o json` (preferred on systemd hosts)
- traditional log files (`/var/log/auth.log`, `/var/log/secure`, …)
- `who(1)`, polled (fallback when nothing else is available)

Notifications are deduplicated within a sliding window and rate-limited via a
token bucket; when the rate limit kicks in, queued events are coalesced into a
single digest notification.

## Install

```sh
go install github.com/<owner>/deskbell@latest
sudo deskbell install -topic <your-ntfy-topic>
```

`install` writes a hardened systemd unit, creates a `deskbell` system user, and
enables/starts the service. Tail logs with `journalctl -u deskbell -f`.

## Uninstall

```sh
sudo deskbell uninstall          # stop + disable + remove unit
sudo deskbell uninstall -purge   # also remove env file, user, and binary
```

## Configuration

| Flag / env                                   | Default            | Notes                              |
|----------------------------------------------|--------------------|------------------------------------|
| `-topic` / `DESKBELL_NTFY_TOPIC`             | (required)         | `[A-Za-z0-9_-]{1,64}`              |
| `-ntfy-url` / `DESKBELL_NTFY_URL`            | `https://ntfy.sh`  | http/https only                    |
| `DESKBELL_NTFY_TOKEN` (env-only)             | unset              | Refused over plain HTTP non-loopback |
| `-poll`                                      | `5s`               | Range `1s`–`60s`                   |
| `-dry-run`                                   | `false`            | Print instead of POSTing           |
| `-verbose`                                   | `false`            | Debug logging                      |

## Build / test / lint

```sh
go build ./...
go test ./...
golangci-lint run ./...
```

## License

TBD.
