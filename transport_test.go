//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

// fakeTransport records every Send call and returns a configurable error /
// optional artificial delay. Concurrent-safe so it can be used to verify
// fan-out parallelism.
type fakeTransport struct {
	name  string
	delay time.Duration

	mu   sync.Mutex
	sent []Notification
	err  error // returned by Send (snapshot under mu)
}

func newFakeTransport(name string) *fakeTransport {
	return &fakeTransport{name: name}
}

func (f *fakeTransport) Name() string { return f.name }

func (f *fakeTransport) Send(ctx context.Context, n Notification) error {
	f.mu.Lock()
	delay := f.delay
	err := f.err
	f.sent = append(f.sent, n)
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (f *fakeTransport) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeTransport) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// flakyTransport fails the first failN calls (with a transient error) and
// succeeds afterwards. Useful for exercising retry loops.
type flakyTransport struct {
	failN     int
	failErr   error
	mu        sync.Mutex
	attempts  int
}

func (f *flakyTransport) Name() string { return "flaky" }

func (f *flakyTransport) Send(_ context.Context, _ Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.attempts <= f.failN {
		return f.failErr
	}
	return nil
}

// -----------------------------------------------------------------------------
// sendWithRetry
// -----------------------------------------------------------------------------

func TestSendWithRetry_SucceedsFirstTry(t *testing.T) {
	tr := newFakeTransport("ok")
	if err := sendWithRetry(t.Context(), tr, Notification{}); err != nil {
		t.Fatalf("sendWithRetry: %v", err)
	}
	if tr.calls() != 1 {
		t.Errorf("expected 1 call, got %d", tr.calls())
	}
}

func TestSendWithRetry_RetriesTransientThenSucceeds(t *testing.T) {
	tr := &flakyTransport{failN: 2, failErr: errors.New("temporary network glitch")}
	start := time.Now()
	if err := sendWithRetry(t.Context(), tr, Notification{}); err != nil {
		t.Fatalf("sendWithRetry: %v", err)
	}
	elapsed := time.Since(start)
	if tr.attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", tr.attempts)
	}
	// Two backoff sleeps (~500 ms + ~1 s + jitter); ceiling at notifyMaxBackoff.
	// Loosely assert it did wait between attempts.
	if elapsed < 400*time.Millisecond {
		t.Errorf("retry returned too quickly (%s); backoff should have applied", elapsed)
	}
}

func TestSendWithRetry_GivesUpAfterMaxAttempts(t *testing.T) {
	tr := &flakyTransport{failN: notifyMaxAttempts + 5, failErr: errors.New("still broken")}
	err := sendWithRetry(t.Context(), tr, Notification{})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("after %d attempts", notifyMaxAttempts)) {
		t.Errorf("error should mention attempt count: %v", err)
	}
	if tr.attempts != notifyMaxAttempts {
		t.Errorf("expected %d attempts, got %d", notifyMaxAttempts, tr.attempts)
	}
}

func TestSendWithRetry_AbortsOnPermanentError(t *testing.T) {
	tr := &flakyTransport{failN: 99, failErr: &permanentError{err: errors.New("auth")}}
	start := time.Now()
	err := sendWithRetry(t.Context(), tr, Notification{})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error")
	}
	var pe *permanentError
	if !errors.As(err, &pe) {
		t.Errorf("expected permanentError, got %T: %v", err, err)
	}
	if tr.attempts != 1 {
		t.Errorf("permanent error must not retry: attempts=%d", tr.attempts)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("permanent error path slept (%s); should short-circuit", elapsed)
	}
}

func TestSendWithRetry_AbortsOnContextCancel(t *testing.T) {
	tr := &flakyTransport{failN: 99, failErr: errors.New("transient")}
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := sendWithRetry(ctx, tr, Notification{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Notifier.dispatch fan-out semantics
// -----------------------------------------------------------------------------

func newTestNotifier(transports ...Transport) *Notifier {
	cfg := Config{Hostname: "h"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := newNotifier(cfg, logger)
	n.transports = transports
	return n
}

func TestDispatch_AllTransportsReceive(t *testing.T) {
	t1 := newFakeTransport("t1")
	t2 := newFakeTransport("t2")
	t3 := newFakeTransport("t3")
	n := newTestNotifier(t1, t2, t3)

	msg := Notification{Title: "T", Body: "B", Priority: "high", Tags: "bell"}
	if err := n.dispatch(t.Context(), msg); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	for _, tr := range []*fakeTransport{t1, t2, t3} {
		if tr.calls() != 1 {
			t.Errorf("%s got %d calls, want 1", tr.name, tr.calls())
		}
	}
}

func TestDispatch_PartialSuccessIsSuccess(t *testing.T) {
	good := newFakeTransport("good")
	bad := newFakeTransport("bad")
	bad.setErr(&permanentError{err: errors.New("nope")})
	n := newTestNotifier(good, bad)

	if err := n.dispatch(t.Context(), Notification{Title: "T", Body: "B"}); err != nil {
		t.Fatalf("partial success should not error, got: %v", err)
	}
}

func TestDispatch_AllFailIsError(t *testing.T) {
	bad1 := newFakeTransport("bad1")
	bad1.setErr(&permanentError{err: errors.New("a")})
	bad2 := newFakeTransport("bad2")
	bad2.setErr(&permanentError{err: errors.New("b")})
	n := newTestNotifier(bad1, bad2)

	err := n.dispatch(t.Context(), Notification{Title: "T", Body: "B"})
	if err == nil {
		t.Fatal("expected error when all transports fail")
	}
	if !strings.Contains(err.Error(), "all 2 transports failed") {
		t.Errorf("error should report transport count: %v", err)
	}
}

// fan-out runs in parallel: with three 200 ms-delayed transports, the
// total dispatch time should be ~200 ms, not 600.
func TestDispatch_ParallelFanOut(t *testing.T) {
	delay := 200 * time.Millisecond
	t1 := &fakeTransport{name: "t1", delay: delay}
	t2 := &fakeTransport{name: "t2", delay: delay}
	t3 := &fakeTransport{name: "t3", delay: delay}
	n := newTestNotifier(t1, t2, t3)

	start := time.Now()
	if err := n.dispatch(t.Context(), Notification{}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	elapsed := time.Since(start)
	// Allow generous slack for slow CI; serial would be ~600 ms.
	if elapsed > delay*2 {
		t.Errorf("dispatch took %s — likely serial, not parallel (each transport takes %s)", elapsed, delay)
	}
}

func TestDispatch_DryRunSkipsTransports(t *testing.T) {
	tr := newFakeTransport("t")
	cfg := Config{Hostname: "h", DryRun: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := newNotifier(cfg, logger)
	n.transports = []Transport{tr}

	if err := n.dispatch(t.Context(), Notification{Title: "T", Body: "B"}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if tr.calls() != 0 {
		t.Errorf("dry-run should not invoke any transport, got %d calls", tr.calls())
	}
}

func TestDispatch_NoTransportsReturnsError(t *testing.T) {
	n := newTestNotifier()
	err := n.dispatch(t.Context(), Notification{})
	if err == nil || !strings.Contains(err.Error(), "no transports configured") {
		t.Errorf("expected 'no transports configured', got %v", err)
	}
}

// -----------------------------------------------------------------------------
// ntfy transport — additional coverage
// -----------------------------------------------------------------------------

func TestNtfyTransport_5xxIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	tr := &ntfyTransport{
		dest:   NtfyDest{URL: srv.URL, Topic: "t"},
		client: srv.Client(),
		name:   "test",
	}
	err := tr.Send(t.Context(), Notification{Title: "T", Body: "B"})
	if err == nil {
		t.Fatal("expected error from 503")
	}
	var pe *permanentError
	if errors.As(err, &pe) {
		t.Errorf("5xx must NOT be permanent (so retry kicks in); got: %v", err)
	}
}

func TestNtfyTransport_429IsTransient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(429)
	}))
	defer srv.Close()
	tr := &ntfyTransport{
		dest:   NtfyDest{URL: srv.URL, Topic: "t"},
		client: srv.Client(),
		name:   "test",
	}
	err := tr.Send(t.Context(), Notification{Title: "T", Body: "B"})
	var pe *permanentError
	if errors.As(err, &pe) {
		t.Errorf("429 must NOT be permanent; got: %v", err)
	}
}

func TestNtfyTransport_OmitsEmptyHeaders(t *testing.T) {
	var seenPriority, seenTags string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPriority = r.Header.Get("Priority")
		seenTags = r.Header.Get("Tags")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	tr := &ntfyTransport{
		dest:   NtfyDest{URL: srv.URL, Topic: "t"},
		client: srv.Client(),
		name:   "test",
	}
	if err := tr.Send(t.Context(), Notification{Title: "T", Body: "B"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if seenPriority != "" {
		t.Errorf("Priority header should be absent when empty, got %q", seenPriority)
	}
	if seenTags != "" {
		t.Errorf("Tags header should be absent when empty, got %q", seenTags)
	}
}

// -----------------------------------------------------------------------------
// Email transport against an embedded fake SMTP server
// -----------------------------------------------------------------------------

// fakeSMTPServer speaks just enough SMTP to accept (or reject) a single
// MAIL FROM / RCPT TO / DATA exchange. Plain text only — TLSMode=none on
// loopback, which is the only TLS mode net/smtp's stdlib client lets us
// drive without a real cert.
type fakeSMTPServer struct {
	addr     string
	listener net.Listener

	mu          sync.Mutex
	received    []receivedEmail
	rejectAuth  atomic.Bool
	rejectMail  atomic.Bool
}

type receivedEmail struct {
	auth string
	from string
	to   []string
	data string
}

func startFakeSMTP(t *testing.T) *fakeSMTPServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSMTPServer{
		addr:     l.Addr().String(),
		listener: l,
	}
	go s.serve()
	t.Cleanup(func() { _ = l.Close() })
	return s
}

func (s *fakeSMTPServer) port() int {
	_, p, _ := net.SplitHostPort(s.addr)
	n, _ := strconv.Atoi(p)
	return n
}

func (s *fakeSMTPServer) messages() []receivedEmail {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]receivedEmail, len(s.received))
	copy(out, s.received)
	return out
}

func (s *fakeSMTPServer) serve() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *fakeSMTPServer) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	w := bufio.NewWriter(c)
	r := bufio.NewReader(c)
	writeLine := func(line string) { _, _ = w.WriteString(line + "\r\n"); _ = w.Flush() }

	writeLine("220 fake.smtp ESMTP")

	var msg receivedEmail
	var inData bool
	var dataBuf strings.Builder

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if inData {
			if line == "." {
				msg.data = dataBuf.String()
				dataBuf.Reset()
				inData = false
				s.mu.Lock()
				s.received = append(s.received, msg)
				s.mu.Unlock()
				msg = receivedEmail{}
				writeLine("250 2.0.0 Ok: queued")
				continue
			}
			if strings.HasPrefix(line, "..") {
				line = line[1:] // un-stuff
			}
			dataBuf.WriteString(line)
			dataBuf.WriteString("\r\n")
			continue
		}

		switch {
		case strings.HasPrefix(line, "EHLO ") || strings.HasPrefix(line, "HELO "):
			writeLine("250-fake.smtp")
			writeLine("250 AUTH PLAIN LOGIN")
		case strings.HasPrefix(line, "AUTH PLAIN"):
			msg.auth = line
			if s.rejectAuth.Load() {
				writeLine("535 5.7.8 Authentication failed")
			} else {
				writeLine("235 2.7.0 Authentication successful")
			}
		case strings.HasPrefix(line, "MAIL FROM:"):
			if s.rejectMail.Load() {
				writeLine("550 5.1.0 Sender rejected")
				continue
			}
			msg.from = trimAngle(strings.TrimPrefix(line, "MAIL FROM:"))
			writeLine("250 2.1.0 Ok")
		case strings.HasPrefix(line, "RCPT TO:"):
			msg.to = append(msg.to, trimAngle(strings.TrimPrefix(line, "RCPT TO:")))
			writeLine("250 2.1.5 Ok")
		case line == "DATA":
			writeLine("354 End data with <CR><LF>.<CR><LF>")
			inData = true
		case line == "QUIT":
			writeLine("221 2.0.0 Bye")
			return
		case line == "RSET":
			msg = receivedEmail{}
			writeLine("250 2.0.0 Ok")
		case line == "NOOP":
			writeLine("250 2.0.0 Ok")
		default:
			writeLine("500 5.5.1 Command unrecognized")
		}
	}
}

func trimAngle(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}

func TestEmailTransport_HappyPath(t *testing.T) {
	s := startFakeSMTP(t)

	tr := &emailTransport{
		cfg: EmailConfig{
			Host:    "127.0.0.1",
			Port:    s.port(),
			User:    "user@example.com",
			Pass:    "pw",
			From:    "alerts@example.com",
			To:      []string{"a@example.com", "b@example.com"},
			TLSMode: "none",
		},
		name: "email-test",
	}
	err := tr.Send(t.Context(), Notification{
		Title: "Login on host: alice",
		Body:  "User: alice\nFrom: 1.2.3.4\n",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	msgs := s.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	got := msgs[0]
	if got.from != "alerts@example.com" {
		t.Errorf("from = %q", got.from)
	}
	if len(got.to) != 2 || got.to[0] != "a@example.com" || got.to[1] != "b@example.com" {
		t.Errorf("to = %v", got.to)
	}
	if !strings.Contains(got.data, "Subject: Login on host: alice") {
		t.Errorf("subject missing from message body:\n%s", got.data)
	}
	if !strings.Contains(got.data, "From: alerts@example.com") {
		t.Errorf("From: header missing")
	}
	if !strings.Contains(got.data, "User: alice") {
		t.Errorf("body missing")
	}
}

func TestEmailTransport_AuthFailureIsPermanent(t *testing.T) {
	s := startFakeSMTP(t)
	s.rejectAuth.Store(true)

	tr := &emailTransport{
		cfg: EmailConfig{
			Host:    "127.0.0.1",
			Port:    s.port(),
			User:    "user@example.com",
			Pass:    "wrong",
			From:    "alerts@example.com",
			To:      []string{"a@example.com"},
			TLSMode: "none",
		},
		name: "email-test",
	}
	err := tr.Send(t.Context(), Notification{Title: "T", Body: "B"})
	if err == nil {
		t.Fatal("expected auth failure")
	}
	var pe *permanentError
	if !errors.As(err, &pe) {
		t.Errorf("auth failure should be permanent, got %T: %v", err, err)
	}
}

func TestEmailTransport_NoAuthWhenUserEmpty(t *testing.T) {
	s := startFakeSMTP(t)

	tr := &emailTransport{
		cfg: EmailConfig{
			Host:    "127.0.0.1",
			Port:    s.port(),
			From:    "alerts@example.com",
			To:      []string{"a@example.com"},
			TLSMode: "none",
		},
		name: "email-test",
	}
	if err := tr.Send(t.Context(), Notification{Title: "T", Body: "B"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msgs := s.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].auth != "" {
		t.Errorf("AUTH should not be sent when User is empty; got %q", msgs[0].auth)
	}
}

func TestEmailTransport_RcptRejectionIsTransient(t *testing.T) {
	s := startFakeSMTP(t)
	s.rejectMail.Store(true)

	tr := &emailTransport{
		cfg: EmailConfig{
			Host:    "127.0.0.1",
			Port:    s.port(),
			From:    "alerts@example.com",
			To:      []string{"a@example.com"},
			TLSMode: "none",
		},
		name: "email-test",
	}
	err := tr.Send(t.Context(), Notification{Title: "T", Body: "B"})
	if err == nil {
		t.Fatal("expected error from rejected MAIL FROM")
	}
	// Server's 550 reply is not flagged as permanent by our transport, so
	// retry would fire — that's the intended behaviour for transient SMTP
	// rejections (greylisting, temporary policy denials).
	var pe *permanentError
	if errors.As(err, &pe) {
		t.Errorf("MAIL FROM rejection should not be permanent; got: %v", err)
	}
}
