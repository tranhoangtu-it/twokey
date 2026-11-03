package approval

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
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

// Notify publishes an urgent notification with Deny/Approve buttons.
func (n *Ntfy) Notify(r Request) {
	reply := n.server + "/" + n.replyTopic()
	msg := ntfyMessage{
		Topic:    n.topic,
		Title:    "🛑 Agent wants to run a destructive action",
		Message:  fmt.Sprintf("%s\n%s %s\nHold #%s", r.Summary(), r.Method, r.URL, r.ID),
		Priority: 5,
		Tags:     []string{"rotating_light"},
		Actions: []ntfyAction{
			{Action: "http", Label: "Deny", URL: reply, Method: "POST", Body: "deny " + r.ID + " " + r.Nonce, Clear: true},
			{Action: "http", Label: "Approve", URL: reply, Method: "POST", Body: "approve " + r.ID + " " + r.Nonce, Clear: true},
		},
	}
	go func() { // network I/O must not delay the broker or other channels
		if err := n.publish(msg); err != nil {
			n.logf("ntfy: notify #%s failed: %v", r.ID, err)
		}
	}()
}

// Closed is a no-op: tapping a button clears the notification on the phone.
func (n *Ntfy) Closed(Request, Decision) {}

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
		n.logf("ntfy: subscription dropped (%v), retrying in %s", err, backoff)
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
