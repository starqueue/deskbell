# deskbell

A small Linux daemon that watches login events on the host it runs on and
posts a notification whenever someone successfully logs in. It is built for
homelabs and small-fleet operators who want a "doorbell for shells" — fast
to install, no broker, no agent infrastructure, just a single Go binary and
a hardened systemd unit.

deskbell can fan notifications out to any number of [ntfy](https://ntfy.sh)
destinations (public ntfy.sh, self-hosted, or a mix), and optionally also
mirror them to email via SMTP. Both transports run in parallel; one failing
does not block the other.

---

## Table of contents

- [What it detects](#what-it-detects)
- [How it works](#how-it-works)
- [Install](#install)
- [Configuration](#configuration)
  - [Command-line flags](#command-line-flags)
  - [Environment variables](#environment-variables)
  - [Multiple ntfy destinations](#multiple-ntfy-destinations)
  - [Email (SMTP)](#email-smtp)
- [Verifying delivery: `deskbell check`](#verifying-delivery-deskbell-check)
- [Startup ping](#startup-ping)
- [Operating](#operating)
- [Uninstall](#uninstall)
- [Security model](#security-model)
- [Build, test, lint](#build-test-lint)
- [Project layout](#project-layout)
- [Init systems other than systemd](#init-systems-other-than-systemd)
- [Troubleshooting](#troubleshooting)

---

## What it detects

| Login type            | Detected via                                                                |
|-----------------------|-----------------------------------------------------------------------------|
| SSH (any auth method) | `sshd: Accepted <method> for <user> from <ip> port <port>`                  |
| Console / TTY         | `util-linux login(1)` syslog: `LOGIN ON ttyN BY <user>` and `ROOT LOGIN ON` |
| Display managers      | PAM `session opened` for gdm-password, lightdm, sddm, xdm, kdm, greetd      |
| Cockpit (web admin)   | PAM `session opened` for the cockpit service                                |
| Live SSH/console      | `who(1)` snapshot polled at the configured interval (fallback only)         |

Events that are explicitly **not** notified:

- Failed login attempts (out of scope; use fail2ban, sshguard, or auditd).
- Privilege transitions (`su`, `sudo`).
- Service-account sessions (`cron`, `systemd-user`, `polkit`, `runuser`, `at`).
- Authentication that does not result in a session (port-knocking, key probes).

## How it works

```
                        +-----------------------------+
                        |        deskbell daemon      |
   journald --> [JournalSource]                       |
                        |       \                     |
   /var/log/auth.log -> [FileSource]  --> events --> [Deduper] --> [Notifier]
                        |       /                                       |
   who(1) ---------> [WhoSource]                                        |
                        +-----------------+-----------+-----------------+
                                          |           |
                                          v           v
                                  [ntfy transport]  [ntfy transport]  ... [email transport]
```

- **Sources** read from journald, traditional log files, or a polled `who(1)`.
  All three run in parallel; whichever produces the event first wins.
- **Deduper** keeps a 60-second sliding window keyed by user + origin + tty +
  method so the same login showing up in two sources is reported once.
- **Notifier** rate-limits at 6 events / minute (1 token / 10 s, burst of 6).
  Events that exceed the budget are queued (cap 1000) and coalesced into a
  digest notification on a 60 s tick.
- **Transports** receive every notification in parallel. A single transport
  failing does not block or delay the others. Each transport retries on
  transient failures with bounded jittered exponential backoff (3 attempts,
  500 ms initial, 10 s cap). Auth failures and other 4xx-class errors are
  marked permanent and skip the retry wait.

## Install

### Option 1: from a local binary

Build, then run the self-installer (it copies itself to `/usr/local/bin` and
writes a hardened systemd unit):

```sh
go build -ldflags="-X main.version=v0.2.0" -o deskbell .

DESKBELL_NTFY_TOPIC=my-secret-topic-9d2f \
sudo -E ./deskbell install
```

The install command:

1. Refuses on non-systemd hosts.
2. Copies the binary atomically to `/usr/local/bin/deskbell` (skipped when
   already in place).
3. Creates a `deskbell` system user with no home directory and a nologin
   shell, then adds it to `systemd-journal` and `adm` so it can read journald
   and `/var/log/auth.log`.
4. Writes the env file `/etc/deskbell/deskbell.env` (mode 0640, root:deskbell)
   from `DESKBELL_*` variables in the calling process.
5. Writes `/etc/systemd/system/deskbell.service` — see
   [Security model](#security-model) for the sandboxing flags.
6. Runs `systemctl daemon-reload` then `systemctl enable --now deskbell`.

The install command is idempotent: re-running it with `-force` rewrites the
env file from the current environment and bounces the unit on the next
restart.

### Option 2: with the full multi-transport configuration

```sh
DESKBELL_NTFY_TOPIC=my-secret-topic-9d2f \
DESKBELL_NTFY_DESTINATIONS='https://ntfy.example.com|host-events|tk_xxx' \
DESKBELL_SMTP_HOST=smtp.gmail.com \
DESKBELL_SMTP_PORT=587 \
DESKBELL_SMTP_USER=alerts@example.com \
DESKBELL_SMTP_PASS='app-password-here' \
DESKBELL_SMTP_TO='ops@example.com,oncall@example.com' \
sudo -E ./deskbell install
```

`sudo -E` is required so `sudo` propagates the `DESKBELL_*` variables; the
install command then writes only those into the env file.

## Configuration

Configuration is read from CLI flags and `DESKBELL_*` environment variables.
At runtime under systemd, environment variables are loaded from
`/etc/deskbell/deskbell.env` via the unit's `EnvironmentFile=` directive.

### Command-line flags

| Flag             | Default             | Description                                              |
|------------------|---------------------|----------------------------------------------------------|
| `-ntfy-url`      | `https://ntfy.sh`   | Primary ntfy server URL                                  |
| `-topic`         | (unset)             | Primary ntfy topic, must match `[A-Za-z0-9_-]{1,64}`     |
| `-poll`          | `5s`                | Poll interval for log files and `who(1)`; 1 s – 60 s     |
| `-startup-ping`  | `true`              | Send a "deskbell started" notification at startup        |
| `-dry-run`       | `false`             | Print notifications instead of sending                    |
| `-verbose`       | `false`             | Debug logging                                             |

`deskbell version`, `deskbell help`, `deskbell check`, `deskbell install`,
and `deskbell uninstall` are subcommands; each accepts `-h` for help.

### Environment variables

All configuration that doesn't have a flag is set via environment variables.
Secrets (tokens, passwords) are **env-only** so they don't leak via
`/proc/<pid>/cmdline`.

#### ntfy

| Variable                       | Required                | Notes                                                                                                                                                       |
|--------------------------------|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `DESKBELL_NTFY_URL`            | no (defaults to ntfy.sh) | Primary destination URL.                                                                                                                                    |
| `DESKBELL_NTFY_TOPIC`          | conditionally\*         | Primary destination topic. `[A-Za-z0-9_-]{1,64}`.                                                                                                           |
| `DESKBELL_NTFY_TOKEN`          | no                      | Bearer token for the primary destination. Refused over plain HTTP unless the URL is loopback.                                                               |
| `DESKBELL_NTFY_DESTINATIONS`   | no                      | Extra destinations. Comma-separated list of `url|topic[|token]` entries — see [below](#multiple-ntfy-destinations).                                         |

\* At least one of `DESKBELL_NTFY_TOPIC`, `DESKBELL_NTFY_DESTINATIONS`, or
the SMTP env vars must be set; deskbell refuses to start if no transport is
configured.

#### Email (SMTP)

| Variable                | Required when SMTP is enabled | Notes                                                                                                                |
|-------------------------|-------------------------------|----------------------------------------------------------------------------------------------------------------------|
| `DESKBELL_SMTP_HOST`    | yes                           | Hostname (`smtp.gmail.com`) or `host:port`. Setting this turns the email transport on.                               |
| `DESKBELL_SMTP_PORT`    | no (default 587)              | Numeric port. Wins over a port embedded in `_HOST`.                                                                  |
| `DESKBELL_SMTP_USER`    | no (unauthenticated relays)   | SASL PLAIN username.                                                                                                 |
| `DESKBELL_SMTP_PASS`    | required if `_USER` is set    | SASL PLAIN password.                                                                                                 |
| `DESKBELL_SMTP_FROM`    | required if `_USER` is empty  | RFC 5322 sender. Defaults to `_USER`.                                                                                |
| `DESKBELL_SMTP_TO`      | yes                           | Comma-separated RFC 5322 recipients.                                                                                 |
| `DESKBELL_SMTP_TLS`     | no (default `auto`)           | `auto` \| `starttls` \| `tls` \| `none`. `auto` uses implicit TLS on port 465 and STARTTLS otherwise. `none` is refused for non-loopback hosts. |

#### Other

| Variable                | Default | Notes                                                |
|-------------------------|---------|------------------------------------------------------|
| `DESKBELL_STARTUP_PING` | `true`  | Set to `false` / `0` / `off` to skip the start ping. |

### Multiple ntfy destinations

Configure additional destinations by setting `DESKBELL_NTFY_DESTINATIONS` to
a comma-separated list. Each entry is `url|topic[|token]`. The primary
destination (configured via `-topic` / `DESKBELL_NTFY_TOPIC`) is always
included; entries from `DESKBELL_NTFY_DESTINATIONS` are appended.

Example: a public summary topic plus a self-hosted authenticated relay:

```sh
DESKBELL_NTFY_URL=https://ntfy.sh
DESKBELL_NTFY_TOPIC=public-summary-9d2f
DESKBELL_NTFY_DESTINATIONS="https://ntfy.example.com|host-events|tk_abc123"
```

Every login event is fanned out to **both** destinations in parallel; one
returning 5xx does not delay the other.

Validation is per-entry:
- URL must be `http://` or `https://`.
- Topic must match `[A-Za-z0-9_-]{1,64}`.
- A token combined with `http://` to a non-loopback host is refused.

### Email (SMTP)

Setting `DESKBELL_SMTP_HOST` enables the email transport. Notifications go to
SMTP **in addition to** any ntfy destinations — there is no failover mode.

#### Gmail with an app password

```sh
DESKBELL_SMTP_HOST=smtp.gmail.com
DESKBELL_SMTP_PORT=587
DESKBELL_SMTP_USER=you@gmail.com
DESKBELL_SMTP_PASS='abcd efgh ijkl mnop'   # 16-char app password
DESKBELL_SMTP_TO=ops@example.com
```

`auto` mode upgrades port 587 with STARTTLS and authenticates with PLAIN
over the encrypted channel.

#### AWS SES (port 465 implicit TLS)

```sh
DESKBELL_SMTP_HOST=email-smtp.us-east-1.amazonaws.com
DESKBELL_SMTP_PORT=465
DESKBELL_SMTP_USER=AKIA...
DESKBELL_SMTP_PASS='ses-smtp-password'
DESKBELL_SMTP_FROM=alerts@verified-domain.example.com
DESKBELL_SMTP_TO=ops@example.com
```

`auto` picks implicit TLS for port 465.

#### Local relay with no auth

```sh
DESKBELL_SMTP_HOST=127.0.0.1
DESKBELL_SMTP_PORT=25
DESKBELL_SMTP_TLS=none
DESKBELL_SMTP_FROM=deskbell@$(hostname)
DESKBELL_SMTP_TO=root@localhost
```

`TLS=none` is only permitted for loopback hosts; deskbell refuses
unencrypted SMTP to public servers.

## Verifying delivery: `deskbell check`

`deskbell check` posts a single test notification to every configured
transport and reports per-transport success or failure, with retries. Use it
after install, after editing `/etc/deskbell/deskbell.env`, or as a one-shot
health probe in CI / monitoring.

```sh
sudo systemctl set-environment $(cat /etc/deskbell/deskbell.env | xargs)
sudo deskbell check
# check: ntfy[0:ntfy.sh/my-secret-topic-9d2f]    ... OK
# check: email[ops@example.com]                  ... OK
# check: all 2 transports OK
```

Or directly with environment variables in your shell:

```sh
DESKBELL_NTFY_TOPIC=my-secret-topic-9d2f deskbell check
```

`deskbell check`:

- Loads the same configuration as the daemon.
- Forces `-dry-run` off (the whole point is real delivery).
- Sends with the same retry / permanent-error rules as the live daemon.
- Exits 0 if every transport returned success; exits 1 with a count of
  failures otherwise.

## Startup ping

By default, deskbell posts a low-priority "deskbell started on
&lt;hostname&gt;" notification to every transport at start-up. This serves three
purposes:

1. **Configuration check** — if you don't see the message, your config is
   broken.
2. **Liveness signal** — useful for catching daemon restarts in your
   notification feed.
3. **Catch silent failures** — a mis-configured transport surfaces immediately
   instead of after the first login.

Disable with `DESKBELL_STARTUP_PING=false` or `-startup-ping=false`.

## Operating

```sh
sudo systemctl status deskbell
sudo systemctl restart deskbell
sudo journalctl -u deskbell -f          # tail logs
sudo journalctl -u deskbell --since=1h  # last hour
sudo deskbell check                     # verify delivery without restart
```

Edits to `/etc/deskbell/deskbell.env` take effect after `systemctl restart
deskbell`. The unit re-loads the file fresh on every restart.

## Uninstall

```sh
sudo deskbell uninstall          # stop + disable + remove the unit
sudo deskbell uninstall -purge   # also remove env dir, system user, binary
```

`uninstall` is idempotent — running it on a host where deskbell is already
gone is a no-op. `-purge` is destructive; with it, the env file (containing
your tokens / SMTP password) is deleted.

## Security model

Threats deskbell deliberately mitigates:

- **Token leakage via process listings.** Tokens and SMTP passwords are
  read from the environment only; there is no `-token` or `-smtp-pass` flag.
  `/proc/<pid>/cmdline` is therefore safe to expose.
- **Token leakage via plain HTTP.** A bearer token combined with an
  `http://` URL is refused at config time, except for loopback URLs (so
  `http://127.0.0.1:8080` against a self-hosted ntfy is allowed).
- **SMTP credential leakage.** `DESKBELL_SMTP_TLS=none` is refused for any
  non-loopback host. The implicit-TLS and STARTTLS code paths require TLS
  ≥ 1.2 with full server-name verification.
- **Email header injection.** The notification title is scrubbed of CR / LF
  before being placed into `Subject:`, so a crafted user name on a login
  event cannot inject a `Bcc:` header.
- **Privilege.** The daemon runs as a dedicated unprivileged `deskbell`
  system user with `nologin` shell, granted only `systemd-journal` and `adm`
  group membership. The systemd unit additionally applies:
  - `NoNewPrivileges=yes`, empty `CapabilityBoundingSet` and
    `AmbientCapabilities`
  - `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
    `PrivateDevices=yes`
  - `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`,
    `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`,
    `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`,
    `LockPersonality`, `MemoryDenyWriteExecute`
  - `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (no AF_NETLINK,
    no AF_PACKET, no Bluetooth)
  - `SystemCallFilter=@system-service` minus `@privileged @resources @mount`

Threats explicitly **not** in scope:

- Detection of failed authentication attempts.
- Anti-tamper (a root attacker can stop the daemon, edit the unit, or
  poison the journal).
- Confidentiality of notification *content* (titles and bodies travel over
  TLS but are in plaintext at the receiver).

## Build, test, lint

```sh
go build -ldflags="-X main.version=v0.2.0" -o deskbell .
go test ./...
golangci-lint run ./...
```

Linter config is in [`.golangci.yml`](./.golangci.yml). The repo is lint-clean
under golangci-lint v2; run the linter before every commit (see
`CLAUDE.md`).

## Project layout

```
.
├── README.md           # this file
├── main.go             # everything — sources, parser, notifier, transports, install
├── main_test.go        # tests (linux build constraint)
├── go.mod
└── .golangci.yml       # linter config
```

The whole program is intentionally one file. The internal section dividers
in `main.go` are:

1. Tunables / flags
2. Events / parsing (regex-driven login event extraction)
3. Sources (journald, file tail, who(1))
4. Pipeline (deduper, login dedup key)
5. Notifier (queue, rate limit, digest, fan-out dispatcher)
6. Install / uninstall (systemd integration)
7. Wiring (`main` / `realMain` / `run`)

## Init systems other than systemd

`deskbell install` is systemd-only. On hosts without systemd:

- **OpenRC**: drop the binary at `/usr/local/bin/deskbell`, write a simple
  `/etc/init.d/deskbell` that supervises it under `start-stop-daemon`, and
  point `EnvironmentFile`-equivalent at `/etc/deskbell/deskbell.env`.
- **runit**: create `/etc/sv/deskbell/run` invoking `chpst -e
  /etc/deskbell/env exec /usr/local/bin/deskbell` and `ln -s ../sv/deskbell
  /var/service/`.
- **s6**: an `s6-rc` source-definition tree, or whatever your distro's
  s6 framework expects (`66`, `s6-linux-init`, …).
- **supervisord**: an `[program:deskbell]` block in
  `/etc/supervisor/conf.d/deskbell.conf` with `environment=` set from
  `/etc/deskbell/deskbell.env`.

deskbell itself does not care which supervisor runs it. It only requires:

- A way to read `/var/log/auth.log` *or* call `journalctl` *or* shell out to
  `who(1)` (one of the three).
- Network egress to the configured ntfy server(s) and / or SMTP server.
- A stable working directory (it reads no relative paths).

PRs adding install scripts for non-systemd init systems are welcome.

## Troubleshooting

- **`no transports configured`** at startup — neither `DESKBELL_NTFY_TOPIC`,
  `DESKBELL_NTFY_DESTINATIONS`, nor `DESKBELL_SMTP_HOST`+`_TO` is set. Fix
  `/etc/deskbell/deskbell.env` and `systemctl restart deskbell`.
- **Notifications stop after a burst** — you've hit the 6/min rate limit. The
  daemon is queueing them and will emit a digest at the next 60 s tick.
  Check the logs for `notifier queue full`.
- **`token refuses to be sent over plain HTTP`** — your URL is `http://`
  and your topic has a token. Either switch to HTTPS or move the token off.
- **`server does not advertise STARTTLS`** with `DESKBELL_SMTP_TLS=starttls` —
  use `tls` for implicit TLS on port 465, or `auto` to let deskbell pick.
- **`deskbell.service: Failed to set up mount namespacing`** — your kernel
  is older than 5.x or doesn't support unprivileged user namespaces. Comment
  out `PrivateTmp=`, `ProtectSystem=`, etc. one by one in
  `/etc/systemd/system/deskbell.service` until it starts. (You'll lose the
  corresponding sandboxing; consider upgrading.)
- **No console-login notifications on Alpine / BusyBox** — BusyBox `login`
  doesn't emit util-linux's `LOGIN ON tty BY user` syslog format. Use the
  `who(1)` source as a fallback (it's enabled automatically when no other
  source produces events).

## License

TBD — choose before publishing the public repo.
