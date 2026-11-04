package approval

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Ntfy pushes held requests to a phone through an ntfy server (ntfy.sh or
// self-hosted). Approve/Deny buttons POST "approve <id> <nonce>" to a reply
// topic that twokey subscribes to. No account or app server needed.
//
// Security model: the topic name is the shared secret. It is never passed
// to the agent's environment; use a long random topic (`twokey ntfy-topic`).
type Ntfy struct {
	server string
	topic  string
	broker *Broker
	client *http.Client
	logf   func(string, ...any)
}

// MinTopicLen is the shortest topic accepted: on a public server anyone who
// guesses the topic can read the approval nonces and approve.
const MinTopicLen = 16

// maxTopicLen is ntfy's own topic length limit.
const maxTopicLen = 64

// ValidateNtfy checks the phone channel settings before any secret is sent:
// the server must use https (plain http only to this machine), and the
// topic must be long and use ntfy's topic characters. Errors never contain
// the topic.
func ValidateNtfy(server, topic string) error {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("ntfy server %q: want a URL like https://ntfy.sh", server)
	}
	if u.User != nil {
		return errors.New("ntfy server URL must not contain credentials")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("ntfy server %q: use https — over plain http the topic and approval nonces travel in cleartext (http is allowed only for localhost)", server)
		}
	default:
		return fmt.Errorf("ntfy server %q: want an https:// URL", server)
	}
	if len(topic) < MinTopicLen {
		return fmt.Errorf("ntfy topic is too short (%d characters, need %d): anyone who guesses it can approve; use `twokey phone`", len(topic), MinTopicLen)
	}
	if len(topic) > maxTopicLen {
		return fmt.Errorf("ntfy topic is too long (%d characters, max %d)", len(topic), maxTopicLen)
	}
	for _, r := range topic {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return errors.New("ntfy topic may contain only letters, digits, '-' and '_'")
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RedactTopic shows only the end of a topic, enough to tell topics apart
// in a banner or log without revealing the secret.
func RedactTopic(topic string) string {
	const keep = 4
	if len(topic) <= keep {
		return "…"
	}
	return "…" + topic[len(topic)-keep:]
}

// redact removes the topic from diagnostic text (url.Error embeds the URL).
func (n *Ntfy) redact(err error) string {
	if err == nil {
		return "<nil>"
	}
	return strings.ReplaceAll(err.Error(), n.topic, RedactTopic(n.topic))
}

// NewNtfy builds the phone channel. server is e.g. "https://ntfy.sh".
func NewNtfy(server, topic string, b *Broker) *Ntfy {
	return &Ntfy{
		server: strings.TrimRight(server, "/"),
		topic:  topic,
		broker: b,
		// Never route our own traffic through a proxy (possibly ourselves).
		client: &http.Client{Transport: &http.Transport{Proxy: nil}},
		logf:   log.Printf,
	}
}

const publishTimeout = 15 * time.Second

// SetLogf redirects diagnostics (e.g. away from an agent's TUI).
func (n *Ntfy) SetLogf(f func(string, ...any)) { n.logf = f }

func (n *Ntfy) replyTopic() string { return n.topic + "-reply" }

type ntfyAction struct {
	Action string `json:"action"`
	Label  string `json:"label"`
	URL    string `json:"url"`
	Method string `json:"method"`
	Body   string `json:"body"`
	Clear  bool   `json:"clear"`
}

type ntfyMessage struct {
	Topic    string       `json:"topic"`
	Title    string       `json:"title"`
	Message  string       `json:"message"`
	Priority int          `json:"priority"`
	Tags     []string     `json:"tags"`
	Actions  []ntfyAction `json:"actions,omitempty"`
}

// maxNtfyMessage keeps a notification under ntfy's message size limit
// (4096 bytes by default) so an agent-sized URL cannot make it fail.
const maxNtfyMessage = 3000

// holdMessage is the notification text for a held request, bounded in size.
func holdMessage(r Request) string {
	tail := "\nHold #" + r.ID
	head := truncateBytes(fmt.Sprintf("%s\n%s %s", r.Summary(), Clean(r.Method), Clean(r.URL)), maxNtfyMessage-len(tail))
	return head + tail
}

// truncateBytes cuts s to at most n bytes on a rune boundary.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const ellipsis = "…"
	cut := n - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}

// Notify publishes an urgent notification with Deny/Approve buttons.
func (n *Ntfy) Notify(r Request) {
	reply := n.server + "/" + n.replyTopic()
	msg := ntfyMessage{
		Topic:    n.topic,
		Title:    "🛑 Agent wants to run a destructive action",
		Message:  holdMessage(r),
		Priority: 5,
		Tags:     []string{"rotating_light"},
		Actions: []ntfyAction{
			{Action: "http", Label: "Deny", URL: reply, Method: "POST", Body: "deny " + r.ID + " " + r.Nonce, Clear: true},
			{Action: "http", Label: "Approve", URL: reply, Method: "POST", Body: "approve " + r.ID + " " + r.Nonce, Clear: true},
		},
	}
	go func() { // network I/O must not delay the broker or other channels
		if err := n.publish(msg); err != nil {
			n.logf("ntfy: notify #%s failed: %s", r.ID, n.redact(err))
		}
	}()
}

// Closed is a no-op: tapping a button clears the notification on the phone.
func (n *Ntfy) Closed(Request, Decision) {}

// Granted tells the phone that a timed approval let a request through, so
// a phone-only user sees every destructive call, held or not. No buttons:
// there is nothing left to decide.
func (n *Ntfy) Granted(r Request, d Decision) {
	msg := ntfyMessage{
		Topic:    n.topic,
		Title:    "✓ Auto-approved by a timed approval",
		Message:  truncateBytes(fmt.Sprintf("%s\n%s %s\n%s", r.Summary(), Clean(r.Method), Clean(r.URL), d.Reason), maxNtfyMessage),
		Priority: 3,
		Tags:     []string{"hourglass"},
	}
	go func() {
		if err := n.publish(msg); err != nil {
			n.logf("ntfy: grant notice #%s failed: %s", r.ID, n.redact(err))
		}
	}()
}

func (n *Ntfy) publish(msg ntfyMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	// Bounded so a hung ntfy server cannot pile up one goroutine per hold.
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.server, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

const (
	// idleLimit: ntfy sends a keepalive every ~45s; silence longer than this
	// means a dead (half-open) connection.
	idleLimit = 90 * time.Second
	// healthyAfter: a connection that lived this long resets the backoff.
	healthyAfter = time.Minute
	maxBackoff   = 30 * time.Second
)

// Listen subscribes to the reply topic until ctx ends, reconnecting on
// errors. Reconnects replay everything since the last event we saw, so a
// tap made while the connection was silently dead is not lost.
func (n *Ntfy) Listen(ctx context.Context) {
	since := time.Now().Unix()
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		last, err := n.listenOnce(ctx, since)
		if last > since {
			since = last
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > healthyAfter {
			backoff = time.Second
		}
		n.logf("ntfy: subscription dropped (%s), retrying in %s", n.redact(err), backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// listenOnce streams replies; it returns the unix time of the last event
// seen (message or keepalive) for replay on reconnect.
func (n *Ntfy) listenOnce(ctx context.Context, since int64) (int64, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	watchdog := time.AfterFunc(idleLimit, cancel)
	defer watchdog.Stop()

	url := n.server + "/" + n.replyTopic() + "/json?since=" + strconv.FormatInt(since, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return since, err
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return since, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return since, fmt.Errorf("subscribe: %s", resp.Status)
	}
	last := since
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		watchdog.Reset(idleLimit)
		var ev struct {
			Event   string `json:"event"`
			Time    int64  `json:"time"`
			Message string `json:"message"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		if ev.Time > last {
			last = ev.Time
		}
		if ev.Event == "message" {
			n.handleReply(ev.Message)
		}
	}
	if err := sc.Err(); err != nil {
		return last, err
	}
	return last, io.EOF
}

// handleReply applies "approve <id> <nonce>" / "deny <id> <nonce>".
func (n *Ntfy) handleReply(text string) {
	f := strings.Fields(text)
	if len(f) != 3 {
		return
	}
	switch f[0] {
	case "approve":
		n.broker.ResolveWithNonce(f[1], f[2], Decision{Approved: true, By: "ntfy", Reason: "approved from phone"})
	case "deny":
		n.broker.ResolveWithNonce(f[1], f[2], Decision{Approved: false, By: "ntfy", Reason: "denied from phone"})
	}
}
