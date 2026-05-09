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
- [Receiving notifications (ntfy)](#receiving-notifications-ntfy)
  - [iOS — important: make notifications persistent](#ios--important-make-notifications-persistent)
  - [Android — usually works out of the box](#android--usually-works-out-of-the-box)
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
- [Privileges](#privileges)
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

## Receiving notifications (ntfy)

deskbell sends notifications via [**ntfy**](https://ntfy.sh) — a free,
open-source, HTTP-based pub-sub notification service. ntfy lets you push a
message to a server with a `curl`-shaped HTTP request and receive it on any
subscribed device. Source code and self-hosting docs:
**https://github.com/binwiederhier/ntfy** (Apache-2.0).

You can use the public hosted server at `ntfy.sh` (deskbell's default) or
run your own (point deskbell at it with `DESKBELL_NTFY_URL=…`).

To receive deskbell's notifications, **subscribe to the topic** that
deskbell is publishing to. The topic name *is* the secret on the public
ntfy.sh server — anyone who knows it can read your alerts and post into
your feed — so make it long and random (deskbell generates one for you when
the install command sees `DESKBELL_NTFY_TOPIC` already set; otherwise pick
your own ≥ 16 random characters from `[A-Za-z0-9_-]`).

### Browser (no install)

Open `https://ntfy.sh/<your-topic>` in any browser — messages stream live.
Useful for quick verification.

### Phone apps

| Platform                | Where                                                                           |
|-------------------------|---------------------------------------------------------------------------------|
| iOS                     | App Store: search **"ntfy"** (publisher: Philipp Heckel), or follow the App Store link from https://ntfy.sh |
| Android (Google Play)   | https://play.google.com/store/apps/details?id=io.heckel.ntfy                    |
| Android (F-Droid)       | https://f-droid.org/packages/io.heckel.ntfy/                                    |

After installing, open the app, tap the **+** button, leave the server as
`ntfy.sh` (or set your self-hosted URL), and paste the topic.

### CLI / desktop

```sh
# stream as JSON, one line per message
curl -s https://ntfy.sh/<your-topic>/json

# the official ntfy CLI
ntfy subscribe <your-topic>
```

There are also browser extensions and desktop builds linked from the
[ntfy GitHub repo](https://github.com/binwiederhier/ntfy).

---

### iOS — important: make notifications persistent

**On iOS, notifications disappear by default after a few seconds. You will
miss login alerts unless you change one specific setting.** This is an iOS
behaviour, not an ntfy bug — every app's notifications behave this way out
of the box, and you have to tell iOS per-app to keep them on screen.

**Do this once, immediately after installing the ntfy app:**

1. Open the iOS **Settings** app.
2. Scroll to **Notifications**, then tap **ntfy** in the app list.
3. Make sure **Allow Notifications** is **on**.
4. Under **Alerts**, enable all three: **Lock Screen**, **Notification
   Center**, **Banners**.
5. Tap **Banner Style** and change it from *Temporary* to **Persistent**.
   **This is the critical step.** *Temporary* banners auto-dismiss in
   roughly five seconds; *Persistent* banners stay on screen until you
   tap them.
6. Set **Sounds** to **on**.
7. Set **Badges** to **on**.
8. Set **Show Previews** to **Always** so the title is visible without
   unlocking the phone.

Recommended additional settings:

- **Notification Grouping → By App** so a burst of logins doesn't get
  collapsed into a single group you might dismiss accidentally.
- **Time Sensitive Notifications → on** (if shown). deskbell sends login
  alerts with `high` priority; this lets them break through Focus modes.
- **Critical Alerts** — only available with a paid Apple developer
  configuration; ntfy does not currently use these.

**If you don't change Banner Style to Persistent, you will routinely miss
login alerts on iOS.** Consider this step mandatory.

### Android — usually works out of the box

For most users, Android needs **no special configuration**. Just install
the ntfy app, subscribe to your topic, and you're done.

The reason it just works: the **Play Store** build of ntfy uses Google's
**Firebase Cloud Messaging (FCM)** to deliver pushes. FCM is the same
channel WhatsApp / Gmail / Signal use, and it's exempt from Android's
normal background-activity and battery-optimisation restrictions. The
ntfy app itself doesn't have to be running for FCM-routed messages to
reach you.

Two cases where you *do* need to do extra work:

**Case 1 — you installed ntfy from F-Droid.**
F-Droid builds don't include Google services, so the app maintains its
own background WebSocket connection to the ntfy server. That connection
is killed by Android's battery optimisation. Fix:

- **Settings → Apps → ntfy → Battery → Unrestricted** (default is
  *Optimised*).

**Case 2 — you self-host ntfy and haven't configured FCM credentials.**
Same situation as F-Droid: no FCM, so the app holds its own connection
and battery optimisation will eventually kill it. Either configure FCM on
your self-hosted server (see the [ntfy docs](https://docs.ntfy.sh/config/#firebase-fcm))
or exempt the ntfy app from battery optimisation as in Case 1.

**Manufacturer-specific quirks.**
Some Android skins (Xiaomi MIUI, Huawei EMUI, OnePlus/Oppo ColorOS,
older Samsung builds) aggressively kill *all* background apps, sometimes
including FCM-using ones. If notifications arrive late or not at all on
one of those phones, the [ntfy Android docs](https://docs.ntfy.sh/subscribe/phone/)
have per-manufacturer settings (Autostart, "no battery restrictions",
etc.). This is a generic Android-skin issue, not something specific to
ntfy or deskbell.

### Self-hosting ntfy

If you'd rather not depend on the public `ntfy.sh` server, ntfy is a
single Go binary you can run on your own host. See
**https://docs.ntfy.sh/install/** and the
[ntfy GitHub repo](https://github.com/binwiederhier/ntfy) for installation,
TLS configuration, and access control. Point deskbell at it with
`DESKBELL_NTFY_URL=https://ntfy.your-domain.example.com`.

---

## Install

### Option 1: prebuilt binary (recommended)

Statically-linked binaries (no glibc dependency) for `linux/amd64` and
`linux/arm64` are published on the
[releases page](https://github.com/starqueue/deskbell/releases/latest).

```sh
# pick one
ARCH=amd64    # or arm64

curl -L -o deskbell \
  https://github.com/starqueue/deskbell/releases/download/v0.2.0/deskbell-linux-${ARCH}
chmod +x deskbell
```

Verify the download against the published checksums (recommended for any
binary you fetch from the internet):

```sh
curl -L https://github.com/starqueue/deskbell/releases/download/v0.2.0/SHA256SUMS \
  | grep "deskbell-linux-${ARCH}" \
  | sha256sum -c -
# deskbell-linux-amd64: OK
```

Then run the self-installer:

```sh
DESKBELL_NTFY_TOPIC=my-secret-topic-9d2f \
sudo -E ./deskbell install
```

### Option 2: from source

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

### Option 3: with the full multi-transport configuration

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

## Privileges

### Install-time (one-shot, root required)

`sudo -E deskbell install` needs root because it:

- writes to `/usr/local/bin/` (the binary)
- writes to `/etc/systemd/system/` (the unit) and `/etc/deskbell/` (the env file)
- runs `useradd --system` to create the `deskbell` service account
- runs `usermod -aG systemd-journal,adm deskbell` to grant log-read access
- runs `systemctl daemon-reload && systemctl enable --now deskbell`

`deskbell uninstall` is the same story — root for `userdel`, `systemctl
disable`, and removing files.

### Runtime (the daemon itself)

Runs as the unprivileged **`deskbell`** system user (no home directory,
`nologin` shell). What it actually requires:

#### Read access to at least one event source

| Source                                    | Privilege needed                                      |
|-------------------------------------------|-------------------------------------------------------|
| `journalctl -f -o json`                   | membership in the `systemd-journal` group             |
| `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora) | membership in the `adm` group                         |
| `who(1)` / `/var/run/utmp`                | none — utmp is world-readable on every distro         |

The install command adds the `deskbell` user to **both** `systemd-journal`
and `adm` so all three sources are available. If a group doesn't exist on
the host (e.g. minimal containers without `adm`), that source is silently
skipped — the daemon still runs as long as one source produces events.

#### Network egress

- Outbound TCP 443 to your ntfy server(s) (or 80 if you self-host).
- Outbound TCP to your SMTP server (587 / 465 / 25 / 2525, whatever you
  configured).

No inbound ports — deskbell never listens.

#### Filesystem

- Read `/etc/deskbell/deskbell.env` (mode 0640, owned `root:deskbell`).
- Read `/var/log/auth.log`, `/var/log/secure`, etc. (via `adm` group).
- Read `/var/run/utmp` (world-readable).
- Read `/proc/self/*` (for journald subprocess management).

Everything else is locked down by the unit:

- `ProtectSystem=strict` — entire `/usr`, `/boot`, `/etc` is read-only.
- `ProtectHome=yes` — `/home`, `/root`, `/run/user` invisible.
- `PrivateTmp=yes` — fresh empty `/tmp`.
- `PrivateDevices=yes` — only `/dev/null`, `/dev/zero`, `/dev/random`.
- `ProtectKernelTunables/Modules/Logs/Clock=yes` — no `/sys` or
  `/proc/kallsyms` writes, no `init_module`, no `kexec`, no clock changes.

### What deskbell explicitly does **not** need

- **No Linux capabilities.** The unit sets `CapabilityBoundingSet=` and
  `AmbientCapabilities=` to empty.
  - No `CAP_NET_BIND_SERVICE` (doesn't bind a port).
  - No `CAP_DAC_READ_SEARCH` (uses group membership for log access, not
    bypass).
  - No `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYSLOG`,
    etc.
- **No setuid / setgid bits** on the binary.
- **No root at runtime.** A bug in deskbell can't escalate.
- **No `AF_PACKET` / `AF_NETLINK` / `AF_BLUETOOTH`.**
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` only.
- **No `mmap(PROT_WRITE|PROT_EXEC)`.** `MemoryDenyWriteExecute=yes`.
- **No mount syscalls, no privileged syscalls, no resource-control
  syscalls.** `SystemCallFilter=@system-service` minus
  `@privileged @resources @mount`.

### Minimum-privilege footprint

If you want to run with the absolute least access, drop the `deskbell` user
from both `systemd-journal` and `adm` and rely solely on `who(1)` polling:

```sh
sudo gpasswd -d deskbell systemd-journal
sudo gpasswd -d deskbell adm
sudo systemctl restart deskbell
```

Trade-off: console and GDM/LightDM events show up only when `who(1)` next
snapshots them (within `-poll` seconds, default 5 s), and SSH events show
up the same way rather than instantly from the journal — but you're now
running with literally just network egress and utmp read access.

### Quick verification

```sh
# Confirm the running process is unprivileged + group-restricted:
ps -o user,group,cmd -C deskbell
id deskbell

# Confirm the sandbox is active:
systemd-analyze security deskbell
# (Should report a low-ish exposure level — the unit hardening is fairly strict.)
```

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
