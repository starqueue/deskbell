//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// versionString
// -----------------------------------------------------------------------------

func TestVersionString_LdflagsValueWins(t *testing.T) {
	saved := version
	defer func() { version = saved }()
	version = "v9.9.9"
	if got := versionString(); got != "v9.9.9" {
		t.Errorf("versionString = %q, want v9.9.9", got)
	}
}

func TestVersionString_FallsBackWhenDev(t *testing.T) {
	saved := version
	defer func() { version = saved }()
	version = "dev"
	got := versionString()
	// Either the test binary has BuildInfo with a version (rare) or we get
	// "git-<rev>[-dirty]" or "dev". Any of those is fine — we just need to
	// confirm it doesn't panic and returns something.
	if got == "" {
		t.Error("versionString returned empty string in dev mode")
	}
}

// -----------------------------------------------------------------------------
// parseBoolEnv
// -----------------------------------------------------------------------------

func TestParseBoolEnv(t *testing.T) {
	cases := []struct {
		in   string
		def  bool
		want bool
	}{
		{"", true, true},
		{"", false, false},
		{"1", false, true},
		{"0", true, false},
		{"true", false, true},
		{"True", false, true},
		{"TRUE", false, true},
		{"yes", false, true},
		{"no", true, false},
		{"on", false, true},
		{"OFF", true, false},
		{"   t  ", false, true},
		{"f", true, false},
		{"garbage", true, true},   // unrecognised → default
		{"garbage", false, false}, // unrecognised → default
	}
	for _, c := range cases {
		if got := parseBoolEnv(c.in, c.def); got != c.want {
			t.Errorf("parseBoolEnv(%q, %v) = %v, want %v", c.in, c.def, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Config.destinations() backwards-compat fallback
// -----------------------------------------------------------------------------

func TestConfigDestinations_FallsBackToLegacyFields(t *testing.T) {
	cfg := Config{NtfyURL: "https://ntfy.sh", NtfyTopic: "abc", NtfyToken: "tk"}
	d := cfg.destinations()
	if len(d) != 1 {
		t.Fatalf("expected 1 dest, got %d", len(d))
	}
	if d[0].URL != "https://ntfy.sh" || d[0].Topic != "abc" || d[0].Token != "tk" {
		t.Errorf("unexpected dest: %+v", d[0])
	}
}

func TestConfigDestinations_NewListWinsOverLegacy(t *testing.T) {
	cfg := Config{
		NtfyURL:   "https://legacy.example",
		NtfyTopic: "legacy",
		NtfyDests: []NtfyDest{{URL: "https://new.example", Topic: "new"}},
	}
	d := cfg.destinations()
	if len(d) != 1 || d[0].Topic != "new" {
		t.Errorf("expected new dest to win, got %+v", d)
	}
}

func TestConfigDestinations_EmptyWhenUnset(t *testing.T) {
	cfg := Config{}
	if d := cfg.destinations(); len(d) != 0 {
		t.Errorf("expected empty, got %+v", d)
	}
}

// -----------------------------------------------------------------------------
// parseLoginEvent dispatcher
// -----------------------------------------------------------------------------

func TestParseLoginEvent_DispatchesAcrossParsers(t *testing.T) {
	cases := []struct {
		name       string
		raw        RawEvent
		wantOK     bool
		wantUser   string
		wantMethod string
	}{
		{
			name:       "ssh accepted line",
			raw:        RawEvent{Source: "journal", Line: "Accepted publickey for alice from 1.2.3.4 port 22 ssh2: RSA SHA256:abc"},
			wantOK:     true,
			wantUser:   "alice",
			wantMethod: "publickey",
		},
		{
			name:       "console login",
			raw:        RawEvent{Source: "file", Line: "Apr 12 10:00:00 host login[123]: LOGIN ON tty1 BY bob"},
			wantOK:     true,
			wantUser:   "bob",
			wantMethod: methodConsole,
		},
		{
			name:       "console root",
			raw:        RawEvent{Source: "file", Line: "Apr 12 10:00:00 host login[123]: ROOT LOGIN ON tty2"},
			wantOK:     true,
			wantUser:   "root",
			wantMethod: methodConsole,
		},
		{
			name:       "pam gdm session",
			raw:        RawEvent{Source: "journal", Line: "gdm-password: pam_unix(gdm-password:session): session opened for user carol(uid=1000) by (uid=0)"},
			wantOK:     true,
			wantUser:   "carol",
			wantMethod: "gdm-password",
		},
		{
			name:       "who session local",
			raw:        RawEvent{Source: "who", Line: "WHO_SESSION user=dave tty=tty1 host=local"},
			wantOK:     true,
			wantUser:   "dave",
			wantMethod: methodConsole,
		},
		{
			name:       "who session remote",
			raw:        RawEvent{Source: "who", Line: "WHO_SESSION user=eve tty=pts/0 host=10.0.0.5"},
			wantOK:     true,
			wantUser:   "eve",
			wantMethod: "session",
		},
		{
			name:   "noise line",
			raw:    RawEvent{Source: "journal", Line: "kernel: random unrelated message"},
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := parseLoginEvent(c.raw)
			if ok != c.wantOK {
				t.Fatalf("parseLoginEvent ok = %v, want %v", ok, c.wantOK)
			}
			if !c.wantOK {
				return
			}
			if ev.User != c.wantUser {
				t.Errorf("User = %q, want %q", ev.User, c.wantUser)
			}
			if ev.Method != c.wantMethod {
				t.Errorf("Method = %q, want %q", ev.Method, c.wantMethod)
			}
			if ev.Source != c.raw.Source {
				t.Errorf("Source = %q, want %q", ev.Source, c.raw.Source)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// parseJournalTime
// -----------------------------------------------------------------------------

func TestParseJournalTime(t *testing.T) {
	// 2024-01-01 00:00:00 UTC = 1704067200 seconds = 1704067200000000 microseconds.
	got := parseJournalTime("1704067200000000")
	want := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parseJournalTime = %v, want %v", got, want)
	}
}

func TestParseJournalTime_InvalidReturnsZero(t *testing.T) {
	cases := []string{"", "not-a-number", "abc123"}
	for _, in := range cases {
		if got := parseJournalTime(in); !got.IsZero() {
			t.Errorf("parseJournalTime(%q) = %v, want zero", in, got)
		}
	}
}

// -----------------------------------------------------------------------------
// canonicalIP — gap-filling cases
// -----------------------------------------------------------------------------

func TestCanonicalIP_AdditionalCases(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"::ffff:1.2.3.4", "1.2.3.4"},
		{"::1", "::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"not-an-ip", "not-an-ip"},
		{"", ""},
		{"10.0.0.1", "10.0.0.1"},
	}
	for _, c := range cases {
		if got := canonicalIP(c.in); got != c.want {
			t.Errorf("canonicalIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// tagsForLogin — every branch
// -----------------------------------------------------------------------------

func TestTagsForLogin_AllMethods(t *testing.T) {
	cases := map[string]string{
		"publickey":            "key,bell",
		"password":             "key,bell",
		"keyboard-interactive": "key,bell",
		"hostbased":            "key,bell",
		"gssapi-with-mic":      "key,bell",
		"none":                 "key,bell",
		methodConsole:          "desktop_computer",
		"cockpit":              "globe_with_meridians",
		"session":              "computer,bell",
		"gdm-password":         "computer", // default branch
		"sddm":                 "computer",
		"unknown-method":       "computer",
	}
	for method, want := range cases {
		if got := tagsForLogin(LoginEvent{Method: method}); got != want {
			t.Errorf("tagsForLogin(%q) = %q, want %q", method, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// formatOrigin — every branch
// -----------------------------------------------------------------------------

func TestFormatOrigin_AllBranches(t *testing.T) {
	cases := []struct {
		ev   LoginEvent
		want string
	}{
		{LoginEvent{IP: "1.2.3.4", Port: "22"}, "1.2.3.4:22"},
		{LoginEvent{IP: "1.2.3.4", Port: "22", TTY: "pts/0"}, "1.2.3.4:22 (pts/0)"},
		{LoginEvent{IP: "2001:db8::1", Port: "22"}, "[2001:db8::1]:22"},
		{LoginEvent{IP: "1.2.3.4"}, "1.2.3.4"},
		{LoginEvent{IP: "1.2.3.4", TTY: "pts/0"}, "1.2.3.4 (pts/0)"},
		{LoginEvent{TTY: "tty1"}, "console (tty1)"},
		{LoginEvent{}, "console"},
	}
	for _, c := range cases {
		if got := formatOrigin(c.ev); got != c.want {
			t.Errorf("formatOrigin(%+v) = %q, want %q", c.ev, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// formatBody content
// -----------------------------------------------------------------------------

func TestFormatBody_IncludesEveryField(t *testing.T) {
	cfg := Config{Hostname: "myhost"}
	ev := LoginEvent{
		User:   "alice",
		IP:     "10.0.0.5",
		Port:   "22",
		Method: "publickey",
		Source: "journal",
		Time:   time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		Raw:    "Accepted publickey for alice from 10.0.0.5 port 22 ssh2",
	}
	body := formatBody(cfg, ev)
	for _, want := range []string{"User: alice", "From: 10.0.0.5:22", "Method: publickey", "Host: myhost", "Source: journal", "Accepted publickey"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}

// -----------------------------------------------------------------------------
// loginDedupKey
// -----------------------------------------------------------------------------

// Port is part of the dedup key by design. Each distinct SSH connection
// uses its own ephemeral source port, so two reconnects from the same
// client get separate notifications — which is the intended behaviour.
// The deduper is only there to suppress the *same* single login event
// being reported by two sources (journald + who(1)) within the 60 s
// window, not to collapse genuinely distinct sign-ins.
func TestLoginDedupKey_PortDistinguishesSessions(t *testing.T) {
	a := LoginEvent{User: "alice", IP: "1.2.3.4", Method: "publickey", Port: "22"}
	b := LoginEvent{User: "alice", IP: "1.2.3.4", Method: "publickey", Port: "23"}
	if loginDedupKey(a) == loginDedupKey(b) {
		t.Errorf("expected different ports to produce different keys")
	}
}

// Same single login surfacing in journal AND who(1) within the 60 s
// window must collapse to one notification — that's what the deduper is
// for. Same User+IP+Port+TTY+Method = same key.
func TestLoginDedupKey_SameEventInTwoSourcesCollapses(t *testing.T) {
	fromJournal := LoginEvent{User: "alice", IP: "1.2.3.4", Method: "publickey", Port: "22", Source: "journal"}
	fromWho := LoginEvent{User: "alice", IP: "1.2.3.4", Method: "publickey", Port: "22", Source: "who"}
	if loginDedupKey(fromJournal) != loginDedupKey(fromWho) {
		t.Error("the same login event reported by two sources must produce the same key")
	}
}

// Different machines must always fire separately, regardless of how
// quickly the second login follows.
func TestLoginDedupKey_DifferentIPDifferentKey(t *testing.T) {
	a := LoginEvent{User: "alice", IP: "1.2.3.4", Method: "publickey", Port: "22"}
	b := LoginEvent{User: "alice", IP: "10.0.0.5", Method: "publickey", Port: "22"}
	if loginDedupKey(a) == loginDedupKey(b) {
		t.Errorf("expected different IPs to produce different keys")
	}
}

func TestLoginDedupKey_DifferentMethodDifferentKey(t *testing.T) {
	a := LoginEvent{User: "alice", IP: "1.2.3.4", Method: "publickey"}
	b := LoginEvent{User: "alice", IP: "1.2.3.4", Method: "password"}
	if loginDedupKey(a) == loginDedupKey(b) {
		t.Errorf("different methods should yield different dedup keys")
	}
}

func TestLoginDedupKey_DifferentUserDifferentKey(t *testing.T) {
	a := LoginEvent{User: "alice", IP: "1.2.3.4", Method: "publickey"}
	b := LoginEvent{User: "bob", IP: "1.2.3.4", Method: "publickey"}
	if loginDedupKey(a) == loginDedupKey(b) {
		t.Errorf("different users should yield different dedup keys")
	}
}

// -----------------------------------------------------------------------------
// sendStartupPing toggle
// -----------------------------------------------------------------------------

func TestSendStartupPing_DisabledSkipsTransports(t *testing.T) {
	tr := newFakeTransport("t")
	cfg := Config{Hostname: "h", StartupPing: false}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := newNotifier(cfg, logger)
	n.transports = []Transport{tr}

	sendStartupPing(t.Context(), n, []string{"journal"})
	if tr.calls() != 0 {
		t.Errorf("StartupPing=false should skip; got %d calls", tr.calls())
	}
}

func TestSendStartupPing_EnabledFiresOnce(t *testing.T) {
	tr := newFakeTransport("t")
	cfg := Config{Hostname: "h", StartupPing: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := newNotifier(cfg, logger)
	n.transports = []Transport{tr}

	sendStartupPing(t.Context(), n, []string{"journal", "file"})
	if tr.calls() != 1 {
		t.Fatalf("expected 1 call, got %d", tr.calls())
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if !strings.Contains(tr.sent[0].Title, "deskbell started on h") {
		t.Errorf("startup ping title = %q", tr.sent[0].Title)
	}
	if !strings.Contains(tr.sent[0].Body, "journal, file") {
		t.Errorf("startup ping body should list sources, got: %q", tr.sent[0].Body)
	}
}

// -----------------------------------------------------------------------------
// End-to-end: feed a raw line through the full pipeline
// -----------------------------------------------------------------------------

// This wires a test ntfy server (httptest), builds a Notifier with that
// destination as its transport, and verifies that a raw SSH log line
// flowing through parseLoginEvent → notifier.Submit → notifier.Run
// results in exactly one POST to the ntfy server.
func TestEndToEnd_SSHLineProducesNotification(t *testing.T) {
	var hits atomic.Int32
	var (
		mu        sync.Mutex
		seenTitle string
		seenBody  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mu.Lock()
		seenTitle = r.Header.Get("Title")
		body, _ := io.ReadAll(r.Body)
		seenBody = string(body)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := Config{Hostname: "myhost"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := newNotifier(cfg, logger)
	n.transports = []Transport{&ntfyTransport{
		dest:   NtfyDest{URL: srv.URL, Topic: "t"},
		client: srv.Client(),
		name:   "test",
	}}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go n.Run(ctx)

	raw := RawEvent{
		Source: "journal",
		Time:   time.Now(),
		Line:   "Accepted publickey for alice from 10.0.0.5 port 22 ssh2: RSA SHA256:abc",
	}
	ev, ok := parseLoginEvent(raw)
	if !ok {
		t.Fatal("parseLoginEvent failed")
	}
	n.Submit(ctx, ev)

	// Wait for at least one delivery.
	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-n.done

	if hits.Load() == 0 {
		t.Fatal("notification never reached the ntfy server")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(seenTitle, "alice") || !strings.Contains(seenTitle, "publickey") {
		t.Errorf("title missing user/method: %q", seenTitle)
	}
	if !strings.Contains(seenBody, "10.0.0.5:22") {
		t.Errorf("body missing origin: %q", seenBody)
	}
}

// -----------------------------------------------------------------------------
// Deduper edge cases
// -----------------------------------------------------------------------------

func TestDeduper_SameKeyTwiceInWindow(t *testing.T) {
	d := NewDeduper(1 * time.Second)
	now := time.Now()
	if d.Seen("k", now) {
		t.Error("first call should not be Seen")
	}
	if !d.Seen("k", now.Add(500*time.Millisecond)) {
		t.Error("second call within window should be Seen")
	}
}

func TestDeduper_DifferentKeysIndependent(t *testing.T) {
	d := NewDeduper(1 * time.Second)
	now := time.Now()
	if d.Seen("a", now) {
		t.Error("a first call should not be Seen")
	}
	if d.Seen("b", now) {
		t.Error("b first call should not be Seen")
	}
}

// -----------------------------------------------------------------------------
// Subcommand dispatch via realMain
// -----------------------------------------------------------------------------

func TestRealMain_VersionSubcommand(t *testing.T) {
	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"deskbell", "version"}
	if got := realMain(); got != 0 {
		t.Errorf("realMain('version') = %d, want 0", got)
	}
}

func TestRealMain_HelpSubcommand(t *testing.T) {
	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"deskbell", "help"}
	if got := realMain(); got != 0 {
		t.Errorf("realMain('help') = %d, want 0", got)
	}
}

// -----------------------------------------------------------------------------
// runCheck behavior
// -----------------------------------------------------------------------------

func TestRunCheck_ReportsTransportSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	env := map[string]string{
		"DESKBELL_NTFY_URL":   srv.URL,
		"DESKBELL_NTFY_TOPIC": "test-topic-1234567890",
	}
	getenv := func(k string) string { return env[k] }

	if err := runCheck(nil, getenv); err != nil {
		t.Errorf("runCheck: %v", err)
	}
}

func TestRunCheck_ReportsTransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401) // permanent error
	}))
	defer srv.Close()

	env := map[string]string{
		"DESKBELL_NTFY_URL":   srv.URL,
		"DESKBELL_NTFY_TOPIC": "test-topic-1234567890",
	}
	getenv := func(k string) string { return env[k] }

	err := runCheck(nil, getenv)
	if err == nil {
		t.Error("runCheck should fail when a transport returns 401")
	}
}

func TestRunCheck_HelpFlagExits(t *testing.T) {
	if err := runCheck([]string{"-h"}, func(string) string { return "" }); err != nil {
		t.Errorf("runCheck -h should not error, got %v", err)
	}
}

func TestRunCheck_RejectsBadConfig(t *testing.T) {
	err := runCheck(nil, func(string) string { return "" })
	if err == nil {
		t.Error("runCheck should fail when no transports configured")
	}
	// flag.ErrHelp must NOT be returned for plain config errors.
	if errors.Is(err, flag.ErrHelp) {
		t.Errorf("config error must not surface as ErrHelp: %v", err)
	}
}

// -----------------------------------------------------------------------------
// truncateUTF8 edge cases
// -----------------------------------------------------------------------------

func TestTruncateUTF8_NoTruncationWhenShort(t *testing.T) {
	if got := truncateUTF8("hello", 10); got != "hello" {
		t.Errorf("truncateUTF8 modified short string: %q", got)
	}
}

func TestTruncateUTF8_DoesNotSplitMultibyteRune(t *testing.T) {
	// "héllo" — é is two bytes (0xc3 0xa9). Truncating to 2 bytes would
	// land mid-rune; the function should walk back to a rune boundary.
	got := truncateUTF8("héllo", 2)
	if got == "h\xc3" || strings.Contains(got, "\xc3") {
		t.Errorf("truncateUTF8 split a multibyte rune: %q", got)
	}
}
