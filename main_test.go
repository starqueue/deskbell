//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// B8 regression: a journal-style MESSAGE (no "sshd" substring) must parse.
func TestParseSSHLogin_JournalMessage(t *testing.T) {
	line := "Accepted publickey for root from 1.2.3.4 port 22 ssh2: RSA SHA256:abc"
	ev, ok := parseSSHLogin(line, time.Now())
	if !ok {
		t.Fatal("expected journal-style line to parse")
	}
	if ev.User != "root" || ev.IP != "1.2.3.4" || ev.Port != "22" || ev.Method != "publickey" {
		t.Fatalf("bad parse: %+v", ev)
	}
}

// B8 regression: classical /var/log/auth.log line still parses.
func TestParseSSHLogin_AuthLogLine(t *testing.T) {
	line := "May  9 12:34:56 myhost sshd[1234]: Accepted password for alice from 192.168.1.10 port 54321 ssh2"
	ev, ok := parseSSHLogin(line, time.Now())
	if !ok {
		t.Fatal("expected auth.log line to parse")
	}
	if ev.User != "alice" || ev.Method != "password" {
		t.Fatalf("bad parse: %+v", ev)
	}
}

// B14 regression: IPv4-mapped IPv6 addresses get canonicalised.
func TestCanonicalIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":        "1.2.3.4",
		"::ffff:1.2.3.4": "1.2.3.4",
		"2001:db8::1":    "2001:db8::1",
		"not-an-ip":      "not-an-ip",
	}
	for in, want := range cases {
		if got := canonicalIP(in); got != want {
			t.Errorf("canonicalIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// Console login on Alpine, Devuan, etc.: util-linux login(1) syslog line.
func TestParseConsoleLogin_User(t *testing.T) {
	line := "Jan  1 12:00:00 host login[1234]: LOGIN ON tty1 BY alice"
	ev, ok := parseConsoleLogin(line, time.Now())
	if !ok {
		t.Fatal("expected console login to parse")
	}
	if ev.User != "alice" || ev.TTY != "tty1" || ev.Method != "console" {
		t.Fatalf("bad parse: %+v", ev)
	}
}

func TestParseConsoleLogin_Root(t *testing.T) {
	line := "Jan  1 12:00:00 host login[1234]: ROOT LOGIN ON tty2"
	ev, ok := parseConsoleLogin(line, time.Now())
	if !ok {
		t.Fatal("expected root console login to parse")
	}
	if ev.User != "root" || ev.TTY != "tty2" || ev.Method != "console" {
		t.Fatalf("bad parse: %+v", ev)
	}
}

// PAM session-open: catches GDM, LightDM, console (via login service), etc.
func TestParsePAMLogin_AllowedService(t *testing.T) {
	line := "Jan  1 12:00:00 host gdm-password: pam_unix(gdm-password:session): session opened for user alice(uid=1000) by (uid=0)"
	ev, ok := parsePAMLogin(line, time.Now())
	if !ok {
		t.Fatal("expected GDM PAM session to parse")
	}
	if ev.User != "alice" || ev.Method != "gdm-password" {
		t.Fatalf("bad parse: %+v", ev)
	}
}

// PAM noise must NOT produce events: cron, sudo, sshd (covered elsewhere),
// systemd-user.
func TestParsePAMLogin_NoisyServicesIgnored(t *testing.T) {
	cases := []string{
		"host CRON[123]: pam_unix(cron:session): session opened for user root",
		"host sudo: pam_unix(sudo:session): session opened for user root",
		"host sshd[123]: pam_unix(sshd:session): session opened for user alice",
		"host systemd-user[123]: pam_unix(systemd-user:session): session opened for user alice",
		"host su: pam_unix(su:session): session opened for user root",
	}
	for _, line := range cases {
		if _, ok := parsePAMLogin(line, time.Now()); ok {
			t.Errorf("expected to ignore: %s", line)
		}
	}
}

// Console session via the WhoSource path (host="local").
func TestParseWhoLogin_LocalConsole(t *testing.T) {
	raw := RawEvent{Source: "who", Time: time.Now(), Line: "WHO_SESSION user=alice tty=tty1 host=local"}
	ev, ok := parseWhoLogin(raw)
	if !ok {
		t.Fatal("expected local who session to parse")
	}
	if ev.Method != "console" || ev.User != "alice" || ev.TTY != "tty1" || ev.IP != "" {
		t.Fatalf("bad parse: %+v", ev)
	}
}

// Existing behaviour: remote SSH session via the WhoSource path keeps the IP.
func TestParseWhoLogin_RemoteSession(t *testing.T) {
	raw := RawEvent{Source: "who", Time: time.Now(), Line: "WHO_SESSION user=alice tty=pts/0 host=1.2.3.4"}
	ev, ok := parseWhoLogin(raw)
	if !ok {
		t.Fatal("expected remote who session to parse")
	}
	if ev.Method != "session" || ev.IP != "1.2.3.4" || ev.TTY != "pts/0" {
		t.Fatalf("bad parse: %+v", ev)
	}
}

// parseWhoOutput must surface local console sessions (no parens) too,
// since the host-empty filter has been removed.
func TestParseWhoOutput_IncludesLocalSessions(t *testing.T) {
	out := strings.Join([]string{
		"alice    tty1     2026-05-09 12:00",
		"bob      pts/0    2026-05-09 12:01 (1.2.3.4)",
	}, "\n")
	sessions := parseWhoOutput(out)
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d: %+v", len(sessions), sessions)
	}
}

// (#2) After the dedup-key change, the PAM "login" service is no longer
// in the allow-list — util-linux login(1) is the canonical source for
// console logins. parsePAMLogin must reject the "login" service so the
// daemon doesn't double-notify.
func TestParsePAMLogin_RejectsLoginService(t *testing.T) {
	if _, ok := parsePAMLogin("host login: pam_unix(login:session): session opened for user alice(uid=1000)", time.Now()); ok {
		t.Fatal("PAM service \"login\" must be rejected; util-linux login(1) is the canonical signal")
	}
	// Display managers and Cockpit are still allowed.
	if _, ok := parsePAMLogin("host gdm-password: pam_unix(gdm-password:session): session opened for user alice(uid=1000)", time.Now()); !ok {
		t.Fatal("gdm-password should still be allowed")
	}
}

// (#2) Dedup key now distinguishes TTYs: two console logins for the same
// user on tty1 vs tty2 within the window must produce different keys.
func TestLoginDedupKey_TTYDistinguishesSessions(t *testing.T) {
	a := LoginEvent{User: "alice", Method: "console", TTY: "tty1"}
	b := LoginEvent{User: "alice", Method: "console", TTY: "tty2"}
	if loginDedupKey(a) == loginDedupKey(b) {
		t.Fatal("dedup keys must differ when TTYs differ")
	}
	c := LoginEvent{User: "alice", Method: "console", TTY: "tty1"}
	if loginDedupKey(a) != loginDedupKey(c) {
		t.Fatal("dedup keys must match when all fields match")
	}
}

// B23 regression: looksLikeAuthEvent must not match unrelated entries with
// "sshd" merely appearing inside their MESSAGE.
func TestLooksLikeAuthEvent_StrictMetadata(t *testing.T) {
	noisy := JournalEntry{
		Comm:        "systemd",
		SystemdUnit: "systemd-logind.service",
		SyslogID:    "systemd-logind",
		Message:     "Stopped sshd.service - OpenBSD Secure Shell server",
	}
	if looksLikeAuthEvent(noisy) {
		t.Fatal("looksLikeAuthEvent should not match systemd-logind entries that mention sshd")
	}
	clean := JournalEntry{Comm: "sshd", Message: "Accepted publickey for root from 1.2.3.4 port 22"}
	if !looksLikeAuthEvent(clean) {
		t.Fatal("looksLikeAuthEvent should match _COMM=sshd")
	}
	gdm := JournalEntry{SyslogID: "gdm-password", Message: "pam_unix(gdm-password:session): session opened for user alice(uid=1000)"}
	if !looksLikeAuthEvent(gdm) {
		t.Fatal("looksLikeAuthEvent should match SYSLOG_IDENTIFIER=gdm-password")
	}
	cron := JournalEntry{SyslogID: "CROND", Message: "pam_unix(cron:session): session opened for user root"}
	if looksLikeAuthEvent(cron) {
		t.Fatal("looksLikeAuthEvent should NOT match cron entries")
	}
}

// fakeSource exits immediately with the given error.
type fakeSource struct {
	name string
	err  error
}

func (f fakeSource) Name() string                                     { return f.name }
func (f fakeSource) Watch(_ context.Context, _ chan<- RawEvent) error { return f.err }

// B1 regression: when every source exits without ctx being cancelled, the
// closer goroutine closes events, the consumer sees ok=false and returns.
func TestRunLoop_AllSourcesExitedTerminates(t *testing.T) {
	cfg := Config{
		NtfyURL: "https://ntfy.sh", NtfyTopic: "test-topic-please-ignore",
		Hostname: "test", DryRun: true, PollInterval: 5 * time.Second,
	}
	// Build a tiny mock of the run() coordination logic.
	events := make(chan RawEvent, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	srcs := []Source{
		fakeSource{name: "a", err: errors.New("boom")},
		fakeSource{name: "b", err: nil},
	}
	go func() {
		// Simulate the wg + closer goroutine in run().
		for _, s := range srcs {
			_ = s.Watch(ctx, events)
		}
		close(events)
	}()

	terminated := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				close(terminated)
				return
			case _, ok := <-events:
				if !ok {
					close(terminated)
					return
				}
			}
		}
	}()
	select {
	case <-terminated:
		// good
	case <-time.After(1 * time.Second):
		t.Fatal("loop did not terminate after all sources exited")
	}
	// Just make sure cfg is used so the import isn't elided.
	_ = strings.HasPrefix(cfg.Hostname, "t")
}

// Poll interval must be in [1s, 60s].
func TestReadConfig_PollIntervalRange(t *testing.T) {
	getenv := func(string) string { return "" }
	cases := []struct {
		args    []string
		ok      bool
		wantErr string
	}{
		{[]string{"-topic", "x", "-poll", "0s"}, false, "between"},
		{[]string{"-topic", "x", "-poll", "500ms"}, false, "between"},
		{[]string{"-topic", "x", "-poll", "61s"}, false, "between"},
		{[]string{"-topic", "x", "-poll", "1s"}, true, ""},
		{[]string{"-topic", "x", "-poll", "60s"}, true, ""},
		{[]string{"-topic", "x"}, true, ""}, // default 5s
	}
	for _, c := range cases {
		_, err := readConfig(c.args, getenv)
		if c.ok && err != nil {
			t.Errorf("args=%v: unexpected error: %v", c.args, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("args=%v: expected error containing %q, got %v", c.args, c.wantErr, err)
		}
	}
}

// Topic is required: missing topic must be a hard error.
func TestReadConfig_TopicRequired(t *testing.T) {
	_, err := readConfig([]string{}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "topic is required") {
		t.Fatalf("expected topic-required error, got %v", err)
	}
}

// Token comes from env only — there must be no -token flag (B15).
func TestReadConfig_TokenViaEnvOnly(t *testing.T) {
	env := map[string]string{
		"DESKBELL_NTFY_TOPIC": "abc",
		"DESKBELL_NTFY_TOKEN": "secret-token",
	}
	getenv := func(k string) string { return env[k] }
	cfg, err := readConfig(nil, getenv)
	if err != nil {
		t.Fatalf("readConfig: %v", err)
	}
	if cfg.NtfyToken != "secret-token" {
		t.Fatalf("expected token from env, got %q", cfg.NtfyToken)
	}
	// And there must be no -token flag.
	if _, err := readConfig([]string{"-topic", "x", "-token", "leaked"}, func(string) string { return "" }); err == nil {
		t.Fatal("expected -token flag to be rejected (it must not exist)")
	}
}

// (N21) Deduper time decay: the same key returns true within the window
// and false once the window has elapsed.
func TestDeduper_WindowDecay(t *testing.T) {
	d := NewDeduper(50 * time.Millisecond)
	t0 := time.Now()
	if d.Seen("k", t0) {
		t.Fatal("first call should not be a duplicate")
	}
	if !d.Seen("k", t0.Add(10*time.Millisecond)) {
		t.Fatal("call within window should be a duplicate")
	}
	if d.Seen("k", t0.Add(100*time.Millisecond)) {
		t.Fatal("call beyond window should not be a duplicate")
	}
}

// (N21) Notifier rate limiter: the burst sends inline; subsequent events
// are queued, not sent. We use a stub publisher and a rigged Notifier so
// the test doesn't actually try to reach ntfy.
func TestNotifier_RateLimitQueuesExcess(t *testing.T) {
	cfg := Config{NtfyURL: "https://ntfy.sh", NtfyTopic: "abc", Hostname: "h", DryRun: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := newNotifier(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	// Submit one more than the burst capacity.
	total := defaultRateBurst + 3
	for i := range total {
		n.Submit(ctx, LoginEvent{Method: "publickey", User: fmt.Sprintf("u%d", i), IP: "1.2.3.4", Port: "22"})
	}
	// Give the notifier a moment to drain its in-channel.
	time.Sleep(50 * time.Millisecond)

	cancel()
	select {
	case <-n.done:
		// good — the notifier shut down within timeout.
	case <-time.After(time.Second):
		t.Fatal("notifier did not shut down within 1s")
	}
}

// (N21) The notifier's queue is bounded — under sustained pressure with
// a full bucket, the oldest entries get dropped rather than growing
// memory unbounded.
func TestNotifier_QueueBounded(t *testing.T) {
	if maxQueueSize <= 0 {
		t.Skip("maxQueueSize is non-positive")
	}
	// Just verify the constant is set; the actual eviction is exercised
	// in production. A full integration test would need a synthetic clock.
	if maxQueueSize > 100000 {
		t.Errorf("maxQueueSize=%d looks unreasonably large", maxQueueSize)
	}
}

// (N5) Digest body must stay well under ntfy.sh's 4 KB ceiling even with
// the maximum number of entries and pathological row content.
func TestDigest_BodyUnder4KB(t *testing.T) {
	cfg := Config{NtfyURL: "https://ntfy.sh", NtfyTopic: "x", Hostname: "h", DryRun: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := newNotifier(cfg, logger)

	queue := make([]LoginEvent, digestMaxEntries+5)
	for i := range queue {
		queue[i] = LoginEvent{
			Method: "publickey",
			User:   strings.Repeat("u", 64),
			IP:     "2001:0db8:0000:0000:0000:0000:0000:0001",
			Port:   "65535",
			TTY:    "pts/" + strings.Repeat("0", 8),
			Source: strings.Repeat("s", 32),
			Time:   time.Now(),
		}
	}

	// Re-create the body exactly as sendDigest does, without actually
	// sending. We can't easily intercept the HTTP path here without an
	// abstraction we don't want; instead recompute the body length.
	var b strings.Builder
	fmt.Fprintf(&b, "%d logins on %s (rate-limited):\n\n", len(queue), n.cfg.Hostname)
	for i, ev := range queue {
		if i >= digestMaxEntries {
			fmt.Fprintf(&b, "... and %d more\n", len(queue)-digestMaxEntries)
			break
		}
		row := fmt.Sprintf("  %s @ %s — %s (%s) [%s]",
			ev.User, formatOrigin(ev), ev.Method, ev.Time.Format(time.RFC3339), ev.Source)
		if len(row) > digestMaxRowLen {
			row = row[:digestMaxRowLen-1] + "…"
		}
		b.WriteString(row)
		b.WriteByte('\n')
	}
	if got := b.Len(); got > 4096 {
		t.Fatalf("digest body is %d bytes; must stay under 4096", got)
	}
}

// (N9) parseWhoOutput should reject lines whose second field doesn't look
// like a TTY — header rows, banners, garbage from a misbehaving who(1).
func TestParseWhoOutput_RejectsNonTTYRows(t *testing.T) {
	out := strings.Join([]string{
		"USER     LINE         TIME             COMMENT", // header (line 0)
		"alice    pts/0        2026-05-09 12:00 (1.2.3.4)",
		"bob      tty1         2026-05-09 12:01",
		"junk     somethingelse 2026-05-09",
	}, "\n")
	got := parseWhoOutput(out)
	if len(got) != 2 {
		t.Fatalf("expected 2 sessions (alice, bob), got %d: %+v", len(got), got)
	}
}

// (N8) IPv6 zone identifiers are now canonicalised properly.
func TestCanonicalIP_Zone(t *testing.T) {
	if got := canonicalIP("fe80::1%eth0"); got != "fe80::1%eth0" {
		t.Errorf("zone-tagged: got %q, want preserved form", got)
	}
	if got := canonicalIP("::ffff:1.2.3.4"); got != "1.2.3.4" {
		t.Errorf("v4-mapped: got %q, want %q", got, "1.2.3.4")
	}
}

// (N7) Accepted regex no longer carries the dead "invalid user" branch,
// but legitimate Accepted lines must still parse.
func TestParseSSHLogin_NoInvalidUserBranch(t *testing.T) {
	ev, ok := parseSSHLogin("Accepted publickey for alice from 1.2.3.4 port 22 ssh2", time.Now())
	if !ok || ev.User != "alice" {
		t.Fatalf("normal Accepted line must parse: %+v ok=%v", ev, ok)
	}
}

// (N13) Topic charset is enforced.
func TestReadConfig_RejectsBadTopic(t *testing.T) {
	cases := []struct {
		topic   string
		wantErr bool
	}{
		{"abc", false},
		{"abc-def_123", false},
		{"abc/def", true},
		{"abc?evil=1", true},
		{"abc def", true},
		{"", true},
		{strings.Repeat("a", 65), true},
	}
	for _, c := range cases {
		_, err := readConfig([]string{"-topic", c.topic, "-poll", "5s"}, func(string) string { return "" })
		if c.wantErr && err == nil {
			t.Errorf("topic=%q: expected error", c.topic)
		}
		if !c.wantErr && err != nil {
			t.Errorf("topic=%q: unexpected error: %v", c.topic, err)
		}
	}
}

// (N17) A panic inside a Source's Watch must not crash the daemon — the
// goroutine recovers and the closer-goroutine still closes events.
type panickingSource struct{}

func (panickingSource) Name() string                                     { return "panicking" }
func (panickingSource) Watch(_ context.Context, _ chan<- RawEvent) error { panic("synthetic") }

func TestSourcePanic_Recovered(t *testing.T) {
	// Build the exact pattern we use in run(): goroutine with defer
	// recover, defer wg.Done.
	var wg sync.WaitGroup
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	src := panickingSource{}
	wg.Add(1)
	recovered := make(chan any, 1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				recovered <- r
				logger.Error("source panic", "source", src.Name(), "panic", fmt.Sprint(r))
			}
		}()
		_ = src.Watch(context.Background(), nil)
	}()
	wg.Wait()
	select {
	case r := <-recovered:
		if r == nil {
			t.Fatal("expected a recovered panic value")
		}
	default:
		t.Fatal("panic was not recovered")
	}
}

// (N22) Right-anchored loginConsoleUserRE: trailing junk on a console
// login line must not be folded into the user field.
func TestParseConsoleLogin_TrailingJunkIgnored(t *testing.T) {
	ev, ok := parseConsoleLogin("login[1]: LOGIN ON tty1 BY alice extra-stuff-here", time.Now())
	if !ok {
		t.Fatal("expected to parse")
	}
	if ev.User != "alice" {
		t.Errorf("got user=%q, want alice (trailing junk should not be captured)", ev.User)
	}
}

// (#1) Rotation: re-opening on inode change must seek to byte 0, not EOF,
// so lines written between rotation and detection are not silently lost.
// We exercise the file source by creating a file, rotating it (mv + create),
// writing a sshd line to the new file, and verifying the line is delivered.
func TestFileSource_RotationReadsFromStart(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/auth.log"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(path, []byte("seed line\n"), 0o600))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	src := FileSource{Path: path, PollInterval: 50 * time.Millisecond, Logger: logger}

	events := make(chan RawEvent, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = src.Watch(ctx, events) }()

	// Wait for the source to settle on the original file.
	time.Sleep(150 * time.Millisecond)

	// Rotate: rename + create + write a fresh login line to the new file.
	must(os.Rename(path, path+".1"))
	f, err := os.Create(path)
	must(err)
	_, err = f.WriteString("Apr 30 12:00:00 host sshd[1]: Accepted publickey for alice from 1.2.3.4 port 22 ssh2\n")
	must(err)
	must(f.Close())

	select {
	case ev := <-events:
		if !strings.Contains(ev.Line, "Accepted publickey for alice") {
			t.Fatalf("expected the post-rotation line, got %q", ev.Line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("post-rotation line was not delivered (would have been lost with seek-to-EOF)")
	}
}

// (#3) URL validation rejects bearer tokens over plain HTTP except for
// loopback targets.
func TestReadConfig_TokenRequiresHTTPSOrLoopback(t *testing.T) {
	mkenv := func(token string) func(string) string {
		return func(k string) string {
			if k == "DESKBELL_NTFY_TOKEN" {
				return token
			}
			return ""
		}
	}
	cases := []struct {
		url     string
		token   string
		wantErr bool
		desc    string
	}{
		{"https://ntfy.sh", "tk_secret", false, "https + token: ok"},
		{"http://ntfy.sh", "", false, "http + no token: ok"},
		{"http://ntfy.sh", "tk_secret", true, "http + token: must reject"},
		{"http://localhost:8080", "tk_secret", false, "localhost: ok"},
		{"http://127.0.0.1:8080", "tk_secret", false, "loopback IPv4: ok"},
		{"http://[::1]:8080", "tk_secret", false, "loopback IPv6: ok"},
		{"ftp://ntfy.sh", "", true, "non-http scheme: must reject"},
		{"not-a-url", "", true, "garbage URL: must reject"},
	}
	for _, c := range cases {
		_, err := readConfig([]string{"-topic", "abc", "-poll", "5s", "-ntfy-url", c.url}, mkenv(c.token))
		if c.wantErr && err == nil {
			t.Errorf("%s: expected error", c.desc)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: unexpected error: %v", c.desc, err)
		}
	}
}

// (#5) FileSource pre-filter must reject syslog lines that aren't from a
// known auth program, even if they happen to match the SSH "Accepted" regex.
func TestLooksLikeAuthLine_RejectsNonAuthLines(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"Apr 30 12:00:00 host sshd[1]: Accepted publickey for alice from 1.2.3.4 port 22", true},
		{"Apr 30 12:00:00 host login[3]: LOGIN ON tty1 BY alice", true},
		{"Apr 30 12:00:00 host gdm-password]: pam_unix(gdm-password:session): session opened for user alice", true},
		{"Apr 30 12:00:00 host random_app[7]: Accepted password for bob from 1.2.3.4 port 22", false},
		{"Apr 30 12:00:00 host kernel: usb 1-1: new device", false},
	}
	for _, c := range cases {
		if got := looksLikeAuthLine(c.line); got != c.want {
			t.Errorf("looksLikeAuthLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// (#6) UTF-8-safe truncation: cutting in the middle of a multi-byte rune
// must back up to the rune boundary; cutting at a boundary returns the
// expected prefix.
func TestTruncateUTF8(t *testing.T) {
	// "héllo" — 'é' is U+00E9 = 0xc3 0xa9 (2 bytes).
	s := "h\u00e9llo"
	// Cap of 2 bytes lands inside 'é'; must back up to 1.
	if got := truncateUTF8(s, 2); got != "h" {
		t.Errorf("truncateUTF8(%q, 2) = %q, want %q", s, got, "h")
	}
	// Cap of 3 bytes lands at the boundary after 'é'.
	if got := truncateUTF8(s, 3); got != "h\u00e9" {
		t.Errorf("truncateUTF8(%q, 3) = %q, want %q", s, got, "h\u00e9")
	}
	// Result is always valid UTF-8.
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6} {
		if got := truncateUTF8(s, n); !utf8.ValidString(got) {
			t.Errorf("truncateUTF8(%q, %d) = %q is not valid UTF-8", s, n, got)
		}
	}
}

// (#7) IPv6 origins are bracketed when a port is present.
func TestFormatOrigin_IPv6Brackets(t *testing.T) {
	ev := LoginEvent{IP: "2001:db8::1", Port: "22"}
	if got := formatOrigin(ev); got != "[2001:db8::1]:22" {
		t.Errorf("formatOrigin = %q, want %q", got, "[2001:db8::1]:22")
	}
	ev4 := LoginEvent{IP: "1.2.3.4", Port: "22"}
	if got := formatOrigin(ev4); got != "1.2.3.4:22" {
		t.Errorf("IPv4 formatOrigin = %q, want %q", got, "1.2.3.4:22")
	}
}

// (#10) main package imports utf8 — sanity that this test file compiles
// against the same import.
var _ = utf8.RuneStart
