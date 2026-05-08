//go:build linux

// Command deskbell sends a notification to ntfy whenever someone
// successfully logs in to this host. Covers SSH, console (util-linux
// login(1)), graphical sessions (GDM, LightDM, SDDM, XDM, KDM, greetd),
// and Cockpit web sessions.
//
// It can read events from three places:
//   - systemd-journald via "journalctl -f -o json" (preferred on systemd hosts)
//   - traditional log files such as /var/log/auth.log or /var/log/secure
//   - the who(1) command, polled (fallback when nothing else is available)
//
// Notifications are deduplicated within a sliding window and rate-limited
// via a token bucket; when the rate limit kicks in, queued events are
// coalesced into a single digest notification.
package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// version is the program version. Overridden at build time with
//
//	go build -ldflags "-X main.version=vX.Y.Z"
//
// When unset, versionString() falls back to the module version (set by
// `go install module@vX.Y.Z`) and finally to the embedded VCS revision.
var version = "dev"

func versionString() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if rev == "" {
		return "dev"
	}
	short := rev
	if len(short) > 12 {
		short = short[:12]
	}
	if modified == "true" {
		short += "-dirty"
	}
	return "git-" + short
}

// Tunables. These are deliberately not flags; flags are only added for
// settings users actually need to override.
const (
	notifyHTTPTimeout    = 10 * time.Second
	notifyMaxAttempts    = 3
	notifyInitialBackoff = 500 * time.Millisecond
	notifyMaxBackoff     = 10 * time.Second
	eventsBufferSize     = 256
	notifierQueueSize    = 64
	digestMaxEntries     = 20
	digestMaxRowLen      = 160  // (N5) keep digest body comfortably under ntfy.sh's 4 KB ceiling
	maxQueueSize         = 1000 // (N1) bound the rate-limited queue under sustained outages
	flushTimeout         = 5 * time.Second
	scannerBufferSize    = 1 << 20 // 1 MiB max token size for the journalctl stderr scanner
)

// -----------------------------------------------------------------------------
// Config / flags
// -----------------------------------------------------------------------------

// Hardcoded operational defaults. Exposed as constants rather than flags
// to keep the user-facing surface area small.
const (
	defaultDedupWindow    = 60 * time.Second
	defaultRateInterval   = 10 * time.Second // 1 token / 10 s = 6/min steady state
	defaultRateBurst      = 6
	defaultDigestInterval = 60 * time.Second

	defaultPollInterval = 5 * time.Second
	minPollInterval     = 1 * time.Second
	maxPollInterval     = 60 * time.Second
)

type Config struct {
	NtfyURL   string
	NtfyTopic string
	NtfyToken string // env-only; never a flag (would leak via /proc/*/cmdline)
	Hostname  string
	DryRun    bool
	Verbose   bool

	// PollInterval drives both the file tail and the who(1) snapshot loop.
	// Validated to [minPollInterval, maxPollInterval].
	PollInterval time.Duration
}

// (RateLimited helper removed: rate-limiting is always on with the
// hardcoded defaults; no toggle for users to inspect.)

func readConfig(args []string, getenv func(string) string) (Config, error) {
	hn, err := os.Hostname()
	if err != nil || strings.TrimSpace(hn) == "" {
		hn = "unknown-host"
	}
	cfg := Config{Hostname: hn}

	fs := flag.NewFlagSet("deskbell", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: deskbell [flags]\n\n")
		fmt.Fprintf(fs.Output(), "Watches login events on this host and posts notifications to ntfy.\n\n")
		fmt.Fprintf(fs.Output(), "Subcommands:\n")
		fmt.Fprintf(fs.Output(), "  install      install as a systemd service (root)\n")
		fmt.Fprintf(fs.Output(), "  uninstall    remove the systemd service (root)\n")
		fmt.Fprintf(fs.Output(), "  version      print version and exit\n")
		fmt.Fprintf(fs.Output(), "  help         print this help\n\n")
		fmt.Fprintf(fs.Output(), "Environment:\n")
		fmt.Fprintf(fs.Output(), "  DESKBELL_NTFY_URL    overrides -ntfy-url\n")
		fmt.Fprintf(fs.Output(), "  DESKBELL_NTFY_TOPIC  overrides -topic\n")
		fmt.Fprintf(fs.Output(), "  DESKBELL_NTFY_TOKEN  bearer token (env-only; never a flag)\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
	}
	fs.StringVar(&cfg.NtfyURL, "ntfy-url",
		cmp.Or(strings.TrimSpace(getenv("DESKBELL_NTFY_URL")), "https://ntfy.sh"),
		"ntfy server URL")
	fs.StringVar(&cfg.NtfyTopic, "topic",
		strings.TrimSpace(getenv("DESKBELL_NTFY_TOPIC")),
		"ntfy topic (required)")
	fs.DurationVar(&cfg.PollInterval, "poll", defaultPollInterval,
		"poll interval for log files and who(1); 1s–60s")
	fs.BoolVar(&cfg.DryRun, "dry-run", false,
		"print notifications instead of sending them")
	fs.BoolVar(&cfg.Verbose, "verbose", false,
		"verbose logging")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	// Token from env only, never a flag. (B15.)
	cfg.NtfyToken = strings.TrimSpace(getenv("DESKBELL_NTFY_TOKEN"))

	cfg.NtfyURL = strings.TrimRight(strings.TrimSpace(cfg.NtfyURL), "/")
	cfg.NtfyTopic = strings.Trim(strings.TrimSpace(cfg.NtfyTopic), "/")

	if cfg.NtfyURL == "" {
		return cfg, errors.New("ntfy URL is required (-ntfy-url or DESKBELL_NTFY_URL)")
	}
	if cfg.NtfyTopic == "" {
		return cfg, errors.New("ntfy topic is required (-topic or DESKBELL_NTFY_TOPIC)")
	}
	// (N13) ntfy topic names must be URL-safe. Reject anything that would
	// distort the request URL (slashes, query/fragment, whitespace, etc.)
	// rather than concatenating it blindly.
	if !ntfyTopicRE.MatchString(cfg.NtfyTopic) {
		return cfg, fmt.Errorf("ntfy topic must match [A-Za-z0-9_-]{1,64}, got %q", cfg.NtfyTopic)
	}
	// (#3) Validate the URL and refuse to send a bearer token over plain
	// HTTP. Localhost is exempt so self-hosted dev setups still work.
	u, err := url.Parse(cfg.NtfyURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return cfg, fmt.Errorf("invalid ntfy URL: %q", cfg.NtfyURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return cfg, fmt.Errorf("ntfy URL scheme must be http or https, got %q", u.Scheme)
	}
	if cfg.NtfyToken != "" && u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return cfg, errors.New("DESKBELL_NTFY_TOKEN refuses to be sent over plain HTTP; use https or set the URL to a localhost target")
	}
	if cfg.PollInterval < minPollInterval || cfg.PollInterval > maxPollInterval {
		return cfg, fmt.Errorf("-poll must be between %s and %s, got %s",
			minPollInterval, maxPollInterval, cfg.PollInterval)
	}
	return cfg, nil
}

// isLoopbackHost reports whether host is a literal loopback address or
// the string "localhost". Used to permit non-HTTPS bearer-token transport
// against locally-hosted ntfy servers. (#3)
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.IsLoopback()
	}
	return false
}

// ntfyTopicRE constrains the topic to ntfy's documented character set
// (alphanumeric, underscore, hyphen). 1–64 characters.
var ntfyTopicRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// (parseBool/parseDuration/parseInt removed: no longer used after the
// flag surface was reduced.)

// -----------------------------------------------------------------------------
// Events / parsing
// -----------------------------------------------------------------------------

type RawEvent struct {
	Source string
	Time   time.Time
	Line   string
}

type LoginEvent struct {
	Method string
	User   string
	IP     string // canonicalised via net.ParseIP where possible
	Port   string
	TTY    string // populated for console sessions and remote sessions seen via who(1)
	Raw    string
	Time   time.Time
	Source string
}

// Accepted publickey for root from 1.2.3.4 port 22 ssh2: ...
// (N7) sshd's "Accepted" line never carries the "invalid user" prefix —
// that only appears on Failed/Postponed lines. Dropped from the regex.
var acceptedSSHLoginRE = regexp.MustCompile(`Accepted (\S+) for (\S+) from (\S+) port (\d+)`)

// pam_unix(<service>:session): session opened for user alice(uid=1000) by ...
// Captures the PAM service name and the user. (uid=N) suffix on the user is
// optional and stripped.
var pamSessionRE = regexp.MustCompile(`pam_unix\(([a-zA-Z0-9._-]+):session\): session opened for user ([a-zA-Z0-9._-]+)`)

// util-linux login(1) console patterns:
//
//	login[1234]: ROOT LOGIN ON tty1
//	login[1234]: LOGIN ON tty1 BY alice
//
// (N22) Right-anchored at end-of-string or whitespace so trailing junk
// doesn't get captured into the user.
var loginConsoleRootRE = regexp.MustCompile(`(?:^|\s)login(?:\[\d+\])?:\s+ROOT LOGIN ON (\S+)(?:\s|$)`)
var loginConsoleUserRE = regexp.MustCompile(`(?:^|\s)login(?:\[\d+\])?:\s+LOGIN ON (\S+) BY (\S+?)(?:\s|$)`)

// Used internally by the WhoSource to encode polled sessions back through the
// same RawEvent pipeline. Host is "local" when the session has no remote peer.
var whoSessionRE = regexp.MustCompile(`^WHO_SESSION user=(\S+) tty=(\S+) host=(\S+)$`)

// methodConsole is the canonical Method value for any local console / TTY
// session, regardless of which parser detected it. Keeping this as a
// shared constant ensures parseConsoleLogin, parsePAMLogin, and
// parseWhoLogin all produce the same dedup key for the same login.
const methodConsole = "console"

// pamLoginServices is the set of PAM services that produce a "session opened"
// line we want to surface as a login. Excluded on purpose:
//   - sshd: caught more precisely by acceptedSSHLoginRE
//   - cron, systemd-user, polkit-1, runuser, at: not interactive logins
//   - su, sudo: privilege transitions, not logins (and very noisy)
//   - login: (#2) util-linux login(1) emits both a `login: LOGIN ON ttyN BY user`
//     syslog line (caught by parseConsoleLogin, which carries TTY) and a
//     PAM session-open line (which doesn't carry TTY). Trusting the
//     login(1) line and dropping the PAM duplicate avoids a known
//     false-positive against the TTY-aware dedup key.
//     Trade-off: on Alpine/BusyBox installs that build login without
//     util-linux's syslog format, console logins will not be detected
//     via this source. who(1) is the recommended fallback there.
var pamLoginServices = map[string]bool{
	"gdm-password": true,
	"lightdm":      true,
	"sddm":         true,
	"xdm":          true,
	"kdm":          true,
	"greetd":       true,
	"cockpit":      true,
}

func parseLoginEvent(raw RawEvent) (LoginEvent, bool) {
	// WhoSource encoding is checked first because it has a unique anchor
	// and we can short-circuit it cheaply.
	if ev, ok := parseWhoLogin(raw); ok {
		return ev, true
	}
	// Each parser returns quickly on a non-match (RE2 fails fast).
	if ev, ok := parseSSHLogin(raw.Line, raw.Time); ok {
		ev.Source = raw.Source
		return ev, true
	}
	if ev, ok := parsePAMLogin(raw.Line, raw.Time); ok {
		ev.Source = raw.Source
		return ev, true
	}
	if ev, ok := parseConsoleLogin(raw.Line, raw.Time); ok {
		ev.Source = raw.Source
		return ev, true
	}
	return LoginEvent{}, false
}

// parseSSHLogin extracts a successful SSH login from a single line. Sources
// are responsible for ensuring the line is sshd-related; we no longer require
// the line itself to literally contain "sshd" — under journalctl the program
// name lives in metadata fields, not in MESSAGE. (B8.)
func parseSSHLogin(line string, eventTime time.Time) (LoginEvent, bool) {
	// (N18) Cheap pre-filter so the regex isn't evaluated against every
	// log line on a busy server.
	if !strings.Contains(line, "Accepted ") {
		return LoginEvent{}, false
	}
	m := acceptedSSHLoginRE.FindStringSubmatch(line)
	if len(m) != 5 {
		return LoginEvent{}, false
	}
	if eventTime.IsZero() {
		eventTime = time.Now()
	}
	return LoginEvent{
		Method: m[1],
		User:   m[2],
		IP:     canonicalIP(m[3]),
		Port:   m[4],
		Raw:    line,
		Time:   eventTime,
	}, true
}

func parseWhoLogin(raw RawEvent) (LoginEvent, bool) {
	m := whoSessionRE.FindStringSubmatch(raw.Line)
	if len(m) != 4 {
		return LoginEvent{}, false
	}
	t := raw.Time
	if t.IsZero() {
		t = time.Now()
	}
	user, tty, host := m[1], m[2], m[3]
	if host == "local" {
		return LoginEvent{
			Method: methodConsole,
			User:   user,
			TTY:    tty,
			Raw:    raw.Line,
			Time:   t,
			Source: raw.Source,
		}, true
	}
	return LoginEvent{
		Method: "session",
		User:   user,
		IP:     canonicalIP(host),
		TTY:    tty,
		Raw:    raw.Line,
		Time:   t,
		Source: raw.Source,
	}, true
}

// parsePAMLogin matches "<service>: pam_unix(<service>:session): session
// opened for user <user>". Only services in pamLoginServices are surfaced;
// everything else (cron, systemd-user, sshd, sudo, ...) is ignored either
// because it's covered elsewhere or because it isn't a real login.
func parsePAMLogin(line string, eventTime time.Time) (LoginEvent, bool) {
	// Cheap pre-filter: skip the regex on the >99% of log lines that
	// aren't PAM session events.
	if !strings.Contains(line, "pam_unix(") {
		return LoginEvent{}, false
	}
	m := pamSessionRE.FindStringSubmatch(line)
	if len(m) != 3 {
		return LoginEvent{}, false
	}
	service, user := m[1], m[2]
	if !pamLoginServices[service] {
		return LoginEvent{}, false
	}
	if eventTime.IsZero() {
		eventTime = time.Now()
	}
	return LoginEvent{
		Method: service,
		User:   user,
		Raw:    line,
		Time:   eventTime,
	}, true
}

// parseConsoleLogin matches util-linux login(1) syslog patterns:
//
//	login[123]: ROOT LOGIN ON tty1
//	login[123]: LOGIN ON tty1 BY alice
func parseConsoleLogin(line string, eventTime time.Time) (LoginEvent, bool) {
	// Cheap pre-filter so we don't run two regexes against every line.
	if !strings.Contains(line, "LOGIN ON ") {
		return LoginEvent{}, false
	}
	if eventTime.IsZero() {
		eventTime = time.Now()
	}
	if m := loginConsoleUserRE.FindStringSubmatch(line); len(m) == 3 {
		return LoginEvent{
			Method: methodConsole,
			User:   m[2],
			TTY:    m[1],
			Raw:    line,
			Time:   eventTime,
		}, true
	}
	if m := loginConsoleRootRE.FindStringSubmatch(line); len(m) == 2 {
		return LoginEvent{
			Method: methodConsole,
			User:   "root",
			TTY:    m[1],
			Raw:    line,
			Time:   eventTime,
		}, true
	}
	return LoginEvent{}, false
}

// canonicalIP returns the canonical text form of the IP if parseable
// (collapses ::ffff:1.2.3.4 → 1.2.3.4, normalises IPv6 zero-runs, preserves
// zone identifiers) and otherwise returns the input unchanged. (B14, N8.)
func canonicalIP(s string) string {
	// netip.ParseAddr handles IPv6 zone identifiers like "fe80::1%eth0",
	// which net.ParseIP rejects.
	if a, err := netip.ParseAddr(s); err == nil {
		// Collapse IPv4-mapped IPv6 ("::ffff:1.2.3.4") to plain IPv4.
		return a.Unmap().String()
	}
	// Last resort for older inputs that net.ParseIP still accepts but
	// netip.ParseAddr doesn't (e.g. with leading zeros).
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return s
}

// -----------------------------------------------------------------------------
// Sources
// -----------------------------------------------------------------------------

type Source interface {
	Name() string
	Watch(ctx context.Context, events chan<- RawEvent) error
}

// sendEvent is a small helper that respects ctx cancellation when handing
// an event to the consumer. Every source uses it. (B17.)
func sendEvent(ctx context.Context, events chan<- RawEvent, ev RawEvent) bool {
	select {
	case events <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// --- JournalSource -----------------------------------------------------------

type JournalEntry struct {
	Message      string `json:"MESSAGE"`
	Comm         string `json:"_COMM"`
	SystemdUnit  string `json:"_SYSTEMD_UNIT"`
	SyslogID     string `json:"SYSLOG_IDENTIFIER"`
	RealtimeUsec string `json:"__REALTIME_TIMESTAMP"`
}

type JournalSource struct {
	Logger *slog.Logger
}

func (s JournalSource) Name() string { return "journal" }

func (s JournalSource) Watch(ctx context.Context, events chan<- RawEvent) error {
	cmd := exec.CommandContext(ctx, journalctlCmd, "-f", "-n", "0", "-o", "json")
	// On context cancel, send SIGTERM rather than SIGKILL, then force-kill
	// after WaitDelay so the goroutine never hangs on an unresponsive child.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open journalctl stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdout.Close()
		return fmt.Errorf("open journalctl stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		// Pipes never get auto-closed unless Wait() runs. (B22.)
		_ = stdout.Close()
		_ = stderr.Close()
		return fmt.Errorf("start journalctl: %w", err)
	}

	// Drain stderr to the logger so warnings from journalctl don't fill up
	// the kernel pipe and block. (B6: properly waited on now.)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), scannerBufferSize)
		for sc.Scan() {
			s.Logger.Warn("journalctl stderr", "line", sc.Text())
		}
		// (#9) Surface scanner errors (token-too-long, I/O errors) so
		// the operator can diagnose silent stalls.
		if err := sc.Err(); err != nil {
			s.Logger.Warn("journalctl stderr scanner stopped", "err", err)
		}
	}()

	// (N10) Read line-by-line and parse each line independently, so a
	// single malformed JSON entry doesn't terminate the source. journalctl
	// emits one JSON object per line.
	reader := bufio.NewReaderSize(stdout, 64*1024)
	for ctx.Err() == nil {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			var entry JournalEntry
			if jerr := json.Unmarshal([]byte(line), &entry); jerr != nil {
				s.Logger.Debug("journal line skipped", "err", jerr)
			} else if looksLikeAuthEvent(entry) {
				t := parseJournalTime(entry.RealtimeUsec)
				if t.IsZero() {
					t = time.Now()
				}
				if !sendEvent(ctx, events, RawEvent{Source: s.Name(), Time: t, Line: entry.Message}) {
					break
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.Logger.Warn("journal read", "err", err)
			break
		}
	}

	waitErr := cmd.Wait()
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if waitErr != nil {
		return fmt.Errorf("journalctl exited: %w", waitErr)
	}
	return nil
}

// authIdentifiers is the set of journal SYSLOG_IDENTIFIER / _COMM values that
// can produce a login event we care about. Kept as a small set for an O(1)
// lookup on the hot path. Cron, systemd-user, sudo, and similar high-volume
// non-login identifiers are deliberately excluded so they're filtered out at
// the journal-source level rather than wasting cycles in the parsers.
var authIdentifiers = map[string]bool{
	"sshd":         true,
	"sshd-session": true,
	"login":        true,
	"gdm-password": true,
	"lightdm":      true,
	"sddm":         true,
	"xdm":          true,
	"kdm":          true,
	"greetd":       true,
	"cockpit":      true,
}

// looksLikeAuthEvent checks the metadata fields that journald always
// populates for syslog-tagged messages. We deliberately do NOT fall back to
// a substring search of the message body — that lets unrelated entries
// through and is the kind of soft filter that surprises operators. (B23.)
func looksLikeAuthEvent(e JournalEntry) bool {
	if authIdentifiers[strings.ToLower(e.Comm)] {
		return true
	}
	if authIdentifiers[strings.ToLower(e.SyslogID)] {
		return true
	}
	switch strings.ToLower(e.SystemdUnit) {
	case "ssh.service", "sshd.service":
		return true
	}
	return false
}

func parseJournalTime(realtimeUsec string) time.Time {
	if realtimeUsec = strings.TrimSpace(realtimeUsec); realtimeUsec == "" {
		return time.Time{}
	}
	usec, err := strconv.ParseInt(realtimeUsec, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.UnixMicro(usec).Local()
}

// --- FileSource --------------------------------------------------------------

type FileSource struct {
	Path         string
	PollInterval time.Duration
	Logger       *slog.Logger
}

func (s FileSource) Name() string { return "file:" + s.Path }

func (s FileSource) Watch(ctx context.Context, events chan<- RawEvent) error {
	pollInterval := cmp.Or(s.PollInterval, time.Second)

	var (
		file      *os.File
		reader    *bufio.Reader
		offset    int64
		lastInode uint64
	)
	// (#1) On the very first open we seek to EOF so the daemon doesn't
	// fire a flood of historical notifications. On rotation or truncation
	// we seek to the START of the new file — anything written since
	// rotation is genuinely new and must not be silently skipped.
	open := func(atEnd bool) error {
		if file != nil {
			_ = file.Close()
			file = nil
		}
		f, err := os.Open(s.Path)
		if err != nil {
			return err
		}
		var pos int64
		if atEnd {
			pos, err = f.Seek(0, io.SeekEnd)
			if err != nil {
				_ = f.Close()
				return err
			}
		}
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return err
		}
		file = f
		reader = bufio.NewReader(f)
		offset = pos
		lastInode = inodeOf(info)
		return nil
	}
	if err := open(true); err != nil {
		return fmt.Errorf("open log file %s: %w", s.Path, err)
	}
	// Capture the file pointer indirectly so rotations don't leak the
	// most-recently-opened handle at function exit. (B4.)
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()

	t := time.NewTicker(pollInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}

		info, err := os.Stat(s.Path)
		if err != nil {
			s.Logger.Debug("stat failed", "path", s.Path, "err", err)
			continue
		}
		curIno := inodeOf(info)
		if curIno != 0 && lastInode != 0 && curIno != lastInode {
			s.Logger.Info("log rotation detected", "path", s.Path)
			// (#1) Read from the START of the new file, not EOF.
			if err := open(false); err != nil {
				s.Logger.Warn("reopen failed", "path", s.Path, "err", err)
				continue
			}
		} else if info.Size() < offset {
			s.Logger.Info("log truncation detected", "path", s.Path)
			// (#1) Truncation (e.g. logrotate's copytruncate) — read the
			// whole new file from byte 0 rather than skipping to EOF.
			if err := open(false); err != nil {
				s.Logger.Warn("reopen failed", "path", s.Path, "err", err)
				continue
			}
		}

		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				offset += int64(len(line))
				trimmed := strings.TrimRight(line, "\r\n")
				// (#5) Skip lines that aren't from a known auth program.
				// Without this, parseSSHLogin would match strings like
				// "Accepted password for X from Y port N" anywhere in
				// /var/log/messages, including non-sshd output.
				if !looksLikeAuthLine(trimmed) {
					continue
				}
				ev := RawEvent{
					Source: s.Name(),
					Time:   time.Now(),
					Line:   trimmed,
				}
				if !sendEvent(ctx, events, ev) {
					return ctx.Err()
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				s.Logger.Warn("read failed", "path", s.Path, "err", err)
				break
			}
		}
	}
}

// --- WhoSource ---------------------------------------------------------------

type WhoSource struct {
	Interval time.Duration
	Logger   *slog.Logger
}

type WhoSession struct {
	User string
	TTY  string
	Host string
}

func (s WhoSource) Name() string { return "who" }

func (s WhoSource) Watch(ctx context.Context, events chan<- RawEvent) error {
	interval := cmp.Or(s.Interval, 5*time.Second)

	// Seed previous from the current `who` snapshot. If the seed poll
	// fails we keep retrying on the ticker without emitting anything,
	// otherwise the first successful poll would falsely report every
	// existing logged-in session as a new login.
	previous, err := s.snapshot(ctx)
	seeded := err == nil
	if !seeded {
		s.Logger.Warn("who initial snapshot failed; will retry", "err", err)
	}

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		current, err := s.snapshot(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return ctx.Err()
			}
			s.Logger.Debug("who poll failed", "err", err)
			continue
		}
		if !seeded {
			previous = current
			seeded = true
			continue
		}
		for key, sess := range current {
			if _, was := previous[key]; was {
				continue
			}
			host := sess.Host
			if host == "" {
				host = "local"
			}
			ev := RawEvent{
				Source: s.Name(),
				Time:   time.Now(),
				Line:   fmt.Sprintf("WHO_SESSION user=%s tty=%s host=%s", sess.User, sess.TTY, host),
			}
			if !sendEvent(ctx, events, ev) {
				return ctx.Err()
			}
		}
		previous = current
	}
}

// snapshot runs `who(1)` with a bounded context so a hung lookup (rare:
// utmp lock contention, NFS-backed /var/run, broken libnss plugin) cannot
// stall daemon shutdown. (N2)
func (s WhoSource) snapshot(ctx context.Context) (map[string]WhoSession, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, whoCmd)
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	sessions := parseWhoOutput(string(out))
	m := make(map[string]WhoSession, len(sessions))
	for _, sess := range sessions {
		m[sess.User+"|"+sess.TTY+"|"+sess.Host] = sess
	}
	return m, nil
}

// ttyRE matches the TTY field of `who(1)` output: pseudo TTYs (pts/0),
// virtual consoles (tty1, ttyS0, ttyAMA0), or X11 display IDs (:0, :0.0).
// (N9) Used to reject header rows or other noise that happens to have ≥2
// fields.
var ttyRE = regexp.MustCompile(`^(pts/\S+|tty\S+|console|:[\d.]+)$`)

func parseWhoOutput(output string) []WhoSession {
	lines := strings.Split(output, "\n")
	sessions := make([]WhoSession, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if !ttyRE.MatchString(fields[1]) {
			continue
		}
		sess := WhoSession{User: fields[0], TTY: fields[1]}
		// Host appears as the trailing parenthesised field on remote sessions.
		// Local console sessions have no parens at all; we leave Host empty
		// and the caller fills in "local".
		for i := len(fields) - 1; i >= 0; i-- {
			f := fields[i]
			if strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")") {
				sess.Host = strings.Trim(f, "()")
				break
			}
		}
		sessions = append(sessions, sess)
	}
	return sessions
}

// authProgramPrefixes is the set of syslog program tags whose lines might
// contain a successful login. (#5) FileSource pre-filters by this set so we
// don't run login parsers against arbitrary lines in /var/log/messages /
// /var/log/syslog. Journal source already filters by SYSLOG_IDENTIFIER,
// which is the structured equivalent.
var authProgramPrefixes = []string{
	"sshd[", "sshd:",
	"sshd-session[", "sshd-session:",
	"login[", "login:",
	"pam_unix(",
	"gdm-password[", "gdm-password:",
	"lightdm[", "lightdm:",
	"sddm[", "sddm:",
	"xdm[", "xdm:",
	"kdm[", "kdm:",
	"greetd[", "greetd:",
	"cockpit[", "cockpit:", "cockpit-session[", "cockpit-session:",
}

// looksLikeAuthLine returns true if the syslog line carries one of the
// program tags we care about. The check is intentionally a substring scan
// rather than a regex anchor at column 0, because some syslog formats
// include a hostname before the tag.
func looksLikeAuthLine(line string) bool {
	for _, p := range authProgramPrefixes {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}
// inodeOf returns the inode number for a stat result on Linux. (Note the
// build tag at the top of the file.)
func inodeOf(info os.FileInfo) uint64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0
	}
	return st.Ino
}

// --- Source detection --------------------------------------------------------

// Hardcoded names of the helper commands. Looked up via $PATH.
const (
	journalctlCmd = "journalctl"
	whoCmd        = "who"
)

// detectSources picks the right combination of sources for this host:
//   - journalctl when systemd is present
//   - any of the well-known auth log files that exist
//   - who(1) as a last-resort fallback when neither of the above is available
//
// The "auto" behaviour is the only mode now; there are no flags to override.
func detectSources(cfg Config, logger *slog.Logger) []Source {
	// (linter: prealloc) Cap the source slice at its maximum possible size
	// (1 journal + 4 default log files + 1 who fallback).
	ss := make([]Source, 0, 6)

	if canUseJournal() {
		ss = append(ss, JournalSource{Logger: logger.With("source", "journal")})
	}

	for _, p := range defaultExistingLogFiles() {
		ss = append(ss, FileSource{
			Path:         p,
			PollInterval: cfg.PollInterval,
			Logger:       logger.With("source", "file:"+p),
		})
	}

	// who(1) is included only if nothing above worked AND who is available.
	// On systems where utmp is functional this catches local console
	// sessions; on Alpine/musl it returns nothing and the auth-log file
	// path above does the work instead.
	if len(ss) == 0 && hasCommand(whoCmd) {
		ss = append(ss, WhoSource{
			Interval: cfg.PollInterval,
			Logger:   logger.With("source", "who"),
		})
	}

	return ss
}

func defaultExistingLogFiles() []string {
	candidates := []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages", "/var/log/syslog"}
	var out []string
	for _, p := range candidates {
		if pathExists(p) {
			out = append(out, p)
		}
	}
	return out
}

func canUseJournal() bool { return hasCommand(journalctlCmd) && pathExists("/run/systemd/system") }

func hasCommand(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	if strings.ContainsRune(cmd, filepath.Separator) {
		// Trust exec to do the right thing rather than reimplementing
		// the executability check ourselves. (B19.)
		_, err := exec.LookPath(cmd)
		return err == nil
	}
	_, err := exec.LookPath(cmd)
	return err == nil
}

func pathExists(p string) bool { _, err := os.Stat(p); return err == nil }

// -----------------------------------------------------------------------------
// Deduper
// -----------------------------------------------------------------------------

type Deduper struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]time.Time
}

func NewDeduper(window time.Duration) *Deduper {
	if window <= 0 {
		window = 60 * time.Second
	}
	return &Deduper{window: window, seen: map[string]time.Time{}}
}

// Seen reports whether key was already seen inside the window. The cleanup
// is amortised across calls.
func (d *Deduper) Seen(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.IsZero() {
		now = time.Now()
	}
	cutoff := now.Add(-d.window)
	for k, ts := range d.seen {
		if ts.Before(cutoff) {
			delete(d.seen, k)
		}
	}
	if ts, ok := d.seen[key]; ok && ts.After(cutoff) {
		return true
	}
	d.seen[key] = now
	return false
}

// loginDedupKey produces a stable identifier for an event. (#2) TTY is
// part of the key so two distinct console sessions for the same user
// (e.g. tty1 and tty2 within the dedup window) don't collapse into one
// notification.
func loginDedupKey(ev LoginEvent) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{ev.User, ev.IP, ev.Port, ev.TTY, ev.Method}, "|")))
	return hex.EncodeToString(sum[:])
}

// -----------------------------------------------------------------------------
// Notifier: token bucket + retry + digest. The scheduler runs in one
// goroutine; the actual HTTP sends run on per-event goroutines so a slow
// or hung ntfy server can't block the scheduler from draining n.in. (#4)
// -----------------------------------------------------------------------------

type Notifier struct {
	cfg     Config
	logger  *slog.Logger
	http    *http.Client
	in      chan LoginEvent
	requeue chan LoginEvent // (#4) failed sends come back here
	done    chan struct{}
	sendWg  sync.WaitGroup // tracks in-flight HTTP sends
}

func newNotifier(cfg Config, logger *slog.Logger) *Notifier {
	return &Notifier{
		cfg:     cfg,
		logger:  logger,
		http:    &http.Client{Timeout: notifyHTTPTimeout},
		in:      make(chan LoginEvent, notifierQueueSize),
		requeue: make(chan LoginEvent, notifierQueueSize),
		done:    make(chan struct{}),
	}
}

// Submit hands an event to the notifier, dropping it on context cancel
// rather than blocking indefinitely.
func (n *Notifier) Submit(ctx context.Context, ev LoginEvent) {
	select {
	case n.in <- ev:
	case <-ctx.Done():
	}
}

// spawnSendOne runs sendOne on its own goroutine so the scheduler keeps
// reading from n.in. On failure the event is pushed to n.requeue, which
// the scheduler drains the same way it drains n.in. (#4)
func (n *Notifier) spawnSendOne(ctx context.Context, ev LoginEvent) {
	n.sendWg.Add(1)
	go func() {
		defer n.sendWg.Done()
		if err := n.sendOne(ctx, ev); err != nil {
			n.logger.Warn("notification failed; queuing for digest", "err", err, "user", ev.User, "ip", ev.IP)
			select {
			case n.requeue <- ev:
			case <-ctx.Done():
			}
		}
	}()
}

// spawnSendDigest is the digest equivalent of spawnSendOne. It works on
// its own snapshot of the queue, leaving the scheduler free to keep
// accepting new events. On failure every snapshot entry is pushed to
// requeue; the next digest tick will pick them up again. (#4)
func (n *Notifier) spawnSendDigest(ctx context.Context, snapshot []LoginEvent) {
	n.sendWg.Add(1)
	go func() {
		defer n.sendWg.Done()
		if err := n.sendDigest(ctx, snapshot); err != nil {
			n.logger.Warn("digest notification failed; will retry next tick",
				"err", err, "events", len(snapshot))
			for _, ev := range snapshot {
				select {
				case n.requeue <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
}

func (n *Notifier) Run(ctx context.Context) {
	defer close(n.done)

	tokens := defaultRateBurst
	var queue []LoginEvent

	refillT := time.NewTicker(defaultRateInterval)
	defer refillT.Stop()
	digestT := time.NewTicker(defaultDigestInterval)
	defer digestT.Stop()

	// enqueue appends to the rate-limit queue, dropping the oldest entry
	// if the queue is at its cap (N1).
	enqueue := func(ev LoginEvent) {
		if len(queue) >= maxQueueSize {
			n.logger.Warn("notifier queue full; dropping oldest",
				"dropped_user", queue[0].User, "dropped_ip", queue[0].IP)
			queue = queue[1:]
		}
		queue = append(queue, ev)
	}

	for {
		select {
		case <-ctx.Done():
			// Wait briefly for in-flight sends so events about to land
			// in requeue still have a chance to be flushed; bound at
			// flushTimeout so shutdown is never indefinite.
			waitDone := make(chan struct{})
			go func() {
				n.sendWg.Wait()
				close(waitDone)
			}()
			select {
			case <-waitDone:
			case <-time.After(flushTimeout):
			}
			// Drain anything that just arrived via requeue.
		drain:
			for {
				select {
				case ev := <-n.requeue:
					enqueue(ev)
				default:
					break drain
				}
			}
			n.flushFinal(queue)
			return

		case <-refillT.C:
			if tokens < defaultRateBurst {
				tokens++
			}
			// (N15) Drain one queued event per refill tick.
			if tokens > 0 && len(queue) > 0 {
				ev := queue[0]
				queue = queue[1:]
				tokens--
				n.spawnSendOne(ctx, ev)
			}

		case <-digestT.C:
			if len(queue) > 0 {
				// (#4) Snapshot and clear; if the spawned send fails,
				// the events come back through n.requeue. New events
				// arriving during the send go onto a fresh queue and
				// don't fight the snapshot for ordering.
				snapshot := queue
				queue = nil
				n.spawnSendDigest(ctx, snapshot)
			}

		case ev, ok := <-n.in:
			if !ok {
				// (#8) n.in closed by future producer.
				n.flushFinal(queue)
				return
			}
			if tokens > 0 {
				tokens--
				n.spawnSendOne(ctx, ev)
				continue
			}
			enqueue(ev)
			if n.cfg.Verbose {
				n.logger.Debug("rate-limited; queued", "user", ev.User, "ip", ev.IP, "queue_len", len(queue))
			}

		case ev := <-n.requeue:
			enqueue(ev)
		}
	}
}

// flushFinal makes a best-effort attempt to deliver any queued events when
// the notifier is shutting down. Uses a fresh context with a short timeout
// because the parent context is already cancelled.
//
// (N19) The parent's HTTP timeout (10 s) is longer than flushTimeout (5 s),
// so a single slow request can consume the whole flush budget. That's the
// intended trade-off — we'd rather lose a digest than block shutdown — but
// it does mean retries don't fire on the final flush.
func (n *Notifier) flushFinal(queue []LoginEvent) {
	if len(queue) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	if err := n.sendDigest(ctx, queue); err != nil {
		n.logger.Warn("final digest failed", "err", err, "events", len(queue))
	}
}

func (n *Notifier) sendOne(ctx context.Context, ev LoginEvent) error {
	title := fmt.Sprintf("Login on %s: %s via %s", n.cfg.Hostname, ev.User, ev.Method)
	body := formatBody(n.cfg, ev)
	if err := n.publishWithRetry(ctx, title, body, "high", tagsForLogin(ev)); err != nil {
		return err
	}
	n.logger.Info("notified login", "user", ev.User, "ip", ev.IP, "method", ev.Method, "source", ev.Source)
	return nil
}

// tagsForLogin chooses ntfy emoji-shortcode tags appropriate to the event
// type. (N14) — a console session at the operator's own keyboard shouldn't
// be tagged the same as a remote SSH login.
func tagsForLogin(ev LoginEvent) string {
	switch ev.Method {
	case "publickey", "password", "keyboard-interactive", "hostbased", "gssapi-with-mic", "none":
		return "key,bell"
	case methodConsole:
		return "desktop_computer"
	case "cockpit":
		return "globe_with_meridians"
	case "session":
		// who(1)-detected remote session without a known auth method.
		return "computer,bell"
	default:
		// Display managers (gdm-password, lightdm, sddm, xdm, kdm, greetd).
		return "computer"
	}
}

func (n *Notifier) sendDigest(ctx context.Context, queue []LoginEvent) error {
	title := fmt.Sprintf("%d logins on %s", len(queue), n.cfg.Hostname)
	var b strings.Builder
	fmt.Fprintf(&b, "%d logins on %s (rate-limited):\n\n", len(queue), n.cfg.Hostname)
	for i, ev := range queue {
		if i >= digestMaxEntries {
			fmt.Fprintf(&b, "... and %d more\n", len(queue)-digestMaxEntries)
			break
		}
		row := fmt.Sprintf("  %s @ %s — %s (%s) [%s]",
			ev.User, formatOrigin(ev), ev.Method, ev.Time.Format(time.RFC3339), ev.Source)
		// (#6) Cap each row to keep total body under ntfy.sh's 4 KB limit,
		// using a UTF-8-aware boundary so we don't split a multi-byte rune.
		if len(row) > digestMaxRowLen {
			row = truncateUTF8(row, digestMaxRowLen-1) + "…"
		}
		b.WriteString(row)
		b.WriteByte('\n')
	}
	if err := n.publishWithRetry(ctx, title, b.String(), "default", "warning,bell"); err != nil {
		return err
	}
	n.logger.Info("notified digest", "events", len(queue))
	return nil
}

// truncateUTF8 returns s truncated so the result is no more than maxBytes
// bytes long and ends on a UTF-8 rune boundary. (#6)
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Walk back to the start of the rune containing byte maxBytes.
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

func formatBody(cfg Config, ev LoginEvent) string {
	return fmt.Sprintf(
		"User: %s\nFrom: %s\nMethod: %s\nHost: %s\nSource: %s\nTime: %s\n\n%s",
		ev.User, formatOrigin(ev), ev.Method, cfg.Hostname, ev.Source,
		ev.Time.Format(time.RFC1123), ev.Raw,
	)
}

// formatOrigin renders the From: field, distinguishing remote IP+port,
// remote-without-port, and local console sessions.
func formatOrigin(ev LoginEvent) string {
	switch {
	case ev.IP != "" && ev.Port != "":
		// (#7) net.JoinHostPort brackets IPv6: "[2001:db8::1]:22" instead
		// of the ambiguous "2001:db8::1:22".
		hp := net.JoinHostPort(ev.IP, ev.Port)
		if ev.TTY != "" {
			return hp + " (" + ev.TTY + ")"
		}
		return hp
	case ev.IP != "":
		if ev.TTY != "" {
			return ev.IP + " (" + ev.TTY + ")"
		}
		return ev.IP
	case ev.TTY != "":
		return "console (" + ev.TTY + ")"
	default:
		return "console"
	}
}

// publishWithRetry sends a notification, retrying on transient failures
// with bounded jittered exponential backoff. (B5.)
func (n *Notifier) publishWithRetry(ctx context.Context, title, body, priority, tags string) error {
	backoff := notifyInitialBackoff
	var lastErr error
	for attempt := 1; attempt <= notifyMaxAttempts; attempt++ {
		err := n.publish(ctx, title, body, priority, tags)
		if err == nil {
			return nil
		}
		lastErr = err
		// Don't retry context errors or auth-class failures.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if isAuthFailure(err) {
			return err
		}
		if attempt == notifyMaxAttempts {
			break
		}
		// Non-cryptographic randomness is appropriate for retry jitter.
		jitter := time.Duration(rand.Int64N(int64(backoff / 2))) //nolint:gosec // G404
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff + jitter):
		}
		if backoff < notifyMaxBackoff {
			backoff *= 2
			if backoff > notifyMaxBackoff {
				backoff = notifyMaxBackoff
			}
		}
	}
	return fmt.Errorf("after %d attempts: %w", notifyMaxAttempts, lastErr)
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("ntfy returned HTTP %d", e.code) }

func isAuthFailure(err error) bool {
	var hse *httpStatusError
	if errors.As(err, &hse) {
		return hse.code == http.StatusUnauthorized || hse.code == http.StatusForbidden
	}
	return false
}

func (n *Notifier) publish(ctx context.Context, title, body, priority, tags string) error {
	if n.cfg.DryRun {
		fmt.Printf("DRY RUN ntfy notification\nTitle: %s\nPriority: %s\nTags: %s\n\n%s\n", title, priority, tags, body)
		return nil
	}
	url := n.cfg.NtfyURL + "/" + n.cfg.NtfyTopic
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		return fmt.Errorf("create ntfy request: %w", err)
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", priority)
	req.Header.Set("Tags", tags)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if n.cfg.NtfyToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.cfg.NtfyToken)
	}
	resp, err := n.http.Do(req)
	if err != nil {
		return fmt.Errorf("send ntfy request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return &httpStatusError{code: resp.StatusCode}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Install / uninstall (systemd)
// -----------------------------------------------------------------------------

const (
	defaultBinPath  = "/usr/local/bin/deskbell"
	defaultUnitPath = "/etc/systemd/system/deskbell.service"
	defaultEnvDir   = "/etc/deskbell"
	defaultEnvPath  = "/etc/deskbell/deskbell.env"
	defaultSvcUser  = "deskbell"
)

// systemdUnit is the unit-file template. Hardening flags follow systemd.exec(5)
// best practice for a process that only reads logs and makes outbound HTTP.
const systemdUnit = `[Unit]
Description=deskbell — login event notifier
After=network-online.target systemd-journald.service
Wants=network-online.target

[Service]
Type=simple
User={{USER}}
ExecStart={{BIN}}
EnvironmentFile={{ENV}}
Restart=on-failure
RestartSec=5s

# Sandboxing — see systemd.exec(5).
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount

[Install]
WantedBy=multi-user.target
`

// isSystemd reports whether this host is booted under systemd. Equivalent to
// libsystemd's sd_booted(3): the directory only exists when PID 1 is systemd.
func isSystemd() bool {
	fi, err := os.Stat("/run/systemd/system")
	return err == nil && fi.IsDir()
}

func runInstall(args []string, getenv func(string) string) error {
	fs := flag.NewFlagSet("deskbell install", flag.ContinueOnError)
	var (
		topic, ntfyURL, token, svcUser string
		binPath, unitPath, envPath     string
		force                          bool
	)
	fs.StringVar(&topic, "topic", strings.TrimSpace(getenv("DESKBELL_NTFY_TOPIC")), "ntfy topic (required; env: DESKBELL_NTFY_TOPIC)")
	fs.StringVar(&ntfyURL, "ntfy-url", cmp.Or(strings.TrimSpace(getenv("DESKBELL_NTFY_URL")), "https://ntfy.sh"), "ntfy server URL (env: DESKBELL_NTFY_URL)")
	fs.StringVar(&token, "token", strings.TrimSpace(getenv("DESKBELL_NTFY_TOKEN")), "ntfy bearer token (env: DESKBELL_NTFY_TOKEN)")
	fs.StringVar(&svcUser, "user", defaultSvcUser, "system user to run the service as (created if missing)")
	fs.StringVar(&binPath, "bin", defaultBinPath, "where to place the binary")
	fs.StringVar(&unitPath, "unit", defaultUnitPath, "where to write the systemd unit")
	fs.StringVar(&envPath, "env", defaultEnvPath, "where to write the environment file")
	fs.BoolVar(&force, "force", false, "overwrite existing env file if present")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: deskbell install [flags]\n\n")
		fmt.Fprintf(fs.Output(), "Installs deskbell as a hardened systemd service. Requires root.\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return errors.New("must be run as root (try: sudo deskbell install ...)")
	}
	if !isSystemd() {
		return errors.New("systemd not detected (no /run/systemd/system); for OpenRC/runit/s6 hosts, run deskbell directly under your supervisor of choice")
	}
	if topic == "" {
		return errors.New("-topic is required (or set DESKBELL_NTFY_TOPIC)")
	}
	if !ntfyTopicRE.MatchString(topic) {
		return fmt.Errorf("ntfy topic must match [A-Za-z0-9_-]{1,64}, got %q", topic)
	}
	u, err := url.Parse(ntfyURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid ntfy URL: %q", ntfyURL)
	}
	if token != "" && u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return errors.New("refusing to write a bearer token destined for plain HTTP; use https or a loopback URL")
	}

	// 1. Place the binary at binPath. If we're already running from there,
	//    skip the copy (re-running install on an installed host is a no-op
	//    here). Otherwise, copy with mode 0755.
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate own binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	if self != binPath {
		fmt.Printf("install: copying %s -> %s\n", self, binPath)
		if err := installBinary(self, binPath); err != nil {
			return err
		}
	} else {
		fmt.Printf("install: binary already at %s\n", binPath)
	}

	// 2. Ensure the service user exists and is in groups that can read
	//    journald and traditional log files. Group adds are best-effort —
	//    on hosts that lack one of these groups, the corresponding source
	//    will simply not produce events.
	if err := ensureSystemUser(svcUser); err != nil {
		return err
	}
	for _, g := range []string{"systemd-journal", "adm"} {
		if err := addUserToGroup(svcUser, g); err != nil {
			fmt.Printf("install: warning: could not add %s to group %s: %v\n", svcUser, g, err)
		}
	}

	// 3. Write env file (0640, root:<svcUser>) so only root and the service
	//    can read the token.
	if err := os.MkdirAll(filepath.Dir(envPath), 0o750); err != nil {
		return fmt.Errorf("create env dir: %w", err)
	}
	if _, err := os.Stat(envPath); err == nil && !force {
		fmt.Printf("install: env file %s already exists; leaving it alone (-force to overwrite)\n", envPath)
	} else {
		var b strings.Builder
		fmt.Fprintf(&b, "DESKBELL_NTFY_URL=%s\n", strings.TrimRight(ntfyURL, "/"))
		fmt.Fprintf(&b, "DESKBELL_NTFY_TOPIC=%s\n", topic)
		if token != "" {
			fmt.Fprintf(&b, "DESKBELL_NTFY_TOKEN=%s\n", token)
		}
		if err := writeFileAtomic(envPath, []byte(b.String()), 0o640); err != nil {
			return fmt.Errorf("write env file: %w", err)
		}
		if u, err := user.Lookup(svcUser); err == nil {
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(u.Gid)
			_ = os.Chown(envPath, 0, gid)
			_ = os.Chown(filepath.Dir(envPath), 0, gid)
			_ = uid // silence unused if Chown fails
		}
		fmt.Printf("install: wrote %s\n", envPath)
	}

	// 4. Render and write the unit file.
	unit := strings.NewReplacer(
		"{{USER}}", svcUser,
		"{{BIN}}", binPath,
		"{{ENV}}", envPath,
	).Replace(systemdUnit)
	if err := writeFileAtomic(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	fmt.Printf("install: wrote %s\n", unitPath)

	// 5. daemon-reload, enable --now.
	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := runCmd("systemctl", "enable", "--now", "deskbell.service"); err != nil {
		return err
	}
	fmt.Println("install: deskbell.service is enabled and running.")
	fmt.Println("install: tail logs with `journalctl -u deskbell -f`")
	return nil
}

func runUninstall(args []string) error {
	fs := flag.NewFlagSet("deskbell uninstall", flag.ContinueOnError)
	var (
		purge                      bool
		svcUser, binPath, unitPath string
		envDir                     string
	)
	fs.BoolVar(&purge, "purge", false, "also remove env file/dir, system user, and binary")
	fs.StringVar(&svcUser, "user", defaultSvcUser, "system user to remove with -purge")
	fs.StringVar(&binPath, "bin", defaultBinPath, "binary path to remove with -purge")
	fs.StringVar(&unitPath, "unit", defaultUnitPath, "systemd unit path")
	fs.StringVar(&envDir, "env-dir", defaultEnvDir, "env-file directory to remove with -purge")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: deskbell uninstall [flags]\n\n")
		fmt.Fprintf(fs.Output(), "Stops the service and removes the systemd unit. Use -purge to also delete\n")
		fmt.Fprintf(fs.Output(), "the env file, system user, and installed binary.\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("must be run as root (try: sudo deskbell uninstall ...)")
	}

	// disable --now is fine even if the unit doesn't exist; ignore errors so
	// uninstall is idempotent.
	_ = runCmd("systemctl", "disable", "--now", "deskbell.service")
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove unit: %w", err)
	}
	_ = runCmd("systemctl", "daemon-reload")
	fmt.Println("uninstall: service stopped and unit removed.")

	if purge {
		if err := os.RemoveAll(envDir); err != nil {
			fmt.Printf("uninstall: warning: could not remove %s: %v\n", envDir, err)
		} else {
			fmt.Printf("uninstall: removed %s\n", envDir)
		}
		if err := os.Remove(binPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Printf("uninstall: warning: could not remove %s: %v\n", binPath, err)
		} else if err == nil {
			fmt.Printf("uninstall: removed %s\n", binPath)
		}
		if _, err := user.Lookup(svcUser); err == nil {
			if err := runCmd("userdel", svcUser); err != nil {
				fmt.Printf("uninstall: warning: could not remove user %s: %v\n", svcUser, err)
			} else {
				fmt.Printf("uninstall: removed user %s\n", svcUser)
			}
		}
	}
	return nil
}

// installBinary copies src to dst atomically with mode 0755.
func installBinary(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 — src is os.Executable().
	if err != nil {
		return fmt.Errorf("open binary: %w", err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create bindir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".deskbell-*.tmp")
	if err != nil {
		return fmt.Errorf("create tempfile: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close tempfile: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// writeFileAtomic writes data to path atomically with the given mode. The
// destination directory must already exist.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".deskbell-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// ensureSystemUser creates a system user with no home and a nologin shell, if
// it does not already exist. Idempotent.
func ensureSystemUser(name string) error {
	if _, err := user.Lookup(name); err == nil {
		return nil
	}
	shell := "/usr/sbin/nologin"
	if _, err := os.Stat(shell); err != nil {
		if _, err := os.Stat("/sbin/nologin"); err == nil {
			shell = "/sbin/nologin"
		}
	}
	return runCmd("useradd", "--system", "--no-create-home", "--shell", shell, name)
}

// addUserToGroup is idempotent: usermod -aG is a no-op when the user is
// already a member.
func addUserToGroup(svcUser, group string) error {
	// Skip cleanly if the group doesn't exist on this host.
	if _, err := user.LookupGroup(group); err != nil {
		return fmt.Errorf("group %s not present", group)
	}
	return runCmd("usermod", "-aG", group, svcUser)
}

// runCmd runs a command, attaching its stdout/stderr to the process's so the
// operator sees what the install steps actually did.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...) // #nosec G204 — args are program-internal constants.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Wiring
// -----------------------------------------------------------------------------

func main() {
	os.Exit(realMain())
}

// realMain returns an exit code; main() is just `os.Exit(realMain())` so all
// of realMain's defers (signal handlers, etc.) run before process exit.
// (linter: gocritic exitAfterDefer.)
func realMain() int {
	args := os.Args[1:]
	// Subcommand dispatch. The first positional arg, if it's a known verb,
	// selects an alternate entry point. Anything else (including bare flags
	// like `-topic foo`) falls through to the daemon path so existing
	// invocations remain backwards-compatible.
	if len(args) > 0 {
		switch args[0] {
		case "install":
			if err := runInstall(args[1:], os.Getenv); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return 0
				}
				fmt.Fprintln(os.Stderr, "install:", err)
				return 1
			}
			return 0
		case "uninstall":
			if err := runUninstall(args[1:]); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return 0
				}
				fmt.Fprintln(os.Stderr, "uninstall:", err)
				return 1
			}
			return 0
		case "version", "-version", "--version":
			fmt.Println("deskbell", versionString())
			return 0
		case "help", "-help", "--help", "-h":
			// Re-run readConfig with -h so the standard flag-package help
			// path (with our custom Usage) prints to stdout.
			_, _ = readConfig([]string{"-h"}, os.Getenv)
			return 0
		}
	}
	cfg, err := readConfig(args, os.Getenv)
	if err != nil {
		// (N6) -help/-h is not an error from the user's perspective; the
		// flag package has already printed usage to stderr.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	level := slog.LevelInfo
	if cfg.Verbose {
		level = slog.LevelDebug
	}
	// (N11) Daemons write logs to stderr by convention; stdout is reserved
	// for primary output. systemd captures both, but `journalctl -u` shows
	// the correct stream this way.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})).With("app", "deskbell")

	// Topic-as-secret warning for the public ntfy server. (B13.)
	if strings.Contains(cfg.NtfyURL, "ntfy.sh") && len(cfg.NtfyTopic) < 16 {
		logger.Warn("topic is short; on the public ntfy.sh server the topic is the only secret. Use a long, random topic, or self-host with a token.",
			"topic_len", len(cfg.NtfyTopic))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("exiting", "err", err)
		return 1
	}
	return 0
}

func run(ctx context.Context, cfg Config, logger *slog.Logger) error {
	sources := detectSources(cfg, logger)
	if len(sources) == 0 {
		return errors.New("no usable sources found on this host; deskbell needs systemd-journald, /var/log/auth.log, /var/log/secure, /var/log/messages, /var/log/syslog, or a working who(1)")
	}
	names := make([]string, 0, len(sources))
	for _, s := range sources {
		names = append(names, s.Name())
	}
	slices.Sort(names)
	logger.Info("starting", "sources", strings.Join(names, ","), "poll", cfg.PollInterval)

	// Notifier runs on its own context so we can shut it down cleanly even
	// when run() returns due to "all sources exited" rather than a parent
	// cancellation.
	notifierCtx, notifierCancel := context.WithCancel(context.Background())
	notifier := newNotifier(cfg, logger.With("component", "notifier"))
	go func() {
		// (N17) Recover so a panic in the notifier doesn't take the daemon
		// down. notifier.Run's own `defer close(n.done)` fires before this
		// recover sees the panic, so the wait-for-done in the cleanup
		// defer below still completes.
		defer func() {
			if r := recover(); r != nil {
				logger.Error("notifier panic", "panic", fmt.Sprint(r))
			}
		}()
		notifier.Run(notifierCtx)
	}()
	defer func() {
		notifierCancel()
		<-notifier.done
	}()

	events := make(chan RawEvent, eventsBufferSize)
	sourceCtx, sourceCancel := context.WithCancel(ctx)
	defer sourceCancel()

	var wg sync.WaitGroup
	for _, src := range sources {
		wg.Add(1)
		go func(src Source) {
			defer wg.Done()
			// (N17) A panic in any source must not crash the daemon —
			// treat it like a normal exit so the closer goroutine and
			// shutdown sequence still fire.
			defer func() {
				if r := recover(); r != nil {
					logger.Error("source panic", "source", src.Name(), "panic", fmt.Sprint(r))
				}
			}()
			err := src.Watch(sourceCtx, events)
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("source exited", "source", src.Name(), "err", err)
				return
			}
			logger.Debug("source stopped", "source", src.Name())
		}(src)
	}
	// Closer goroutine: when every source has returned, close the events
	// channel so the consumer sees ok=false rather than blocking forever.
	// (B1.)
	go func() {
		wg.Wait()
		close(events)
	}()

	deduper := NewDeduper(defaultDedupWindow)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case raw, ok := <-events:
			if !ok {
				return errors.New("all sources exited; nothing to monitor")
			}
			ev, ok := parseLoginEvent(raw)
			if !ok {
				continue
			}
			// (N12) parseLoginEvent already populates Source; no fallback needed.
			key := loginDedupKey(ev)
			if deduper.Seen(key, time.Now()) {
				logger.Debug("deduplicated", "key", key, "user", ev.User, "ip", ev.IP)
				continue
			}
			notifier.Submit(ctx, ev)
		}
	}
}
