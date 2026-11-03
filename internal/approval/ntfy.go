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
	if err := n.publish(msg); err != nil {
		n.logf("ntfy: notify #%s failed: %v", r.ID, err)
	}
}

// Closed is a no-op: tapping a button clears the notification on the phone.
func (n *Ntfy) Closed(Request, Decision) {}

func (n *Ntfy) publish(msg ntfyMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	resp, err := n.client.Post(n.server, "application/json", bytes.NewReader(body))
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

// Listen subscribes to the reply topic until ctx ends, reconnecting on errors.
func (n *Ntfy) Listen(ctx context.Context) {
	since := strconv.FormatInt(time.Now().Unix(), 10)
	backoff := time.Second
	for ctx.Err() == nil {
		err := n.listenOnce(ctx, since)
		if ctx.Err() != nil {
			return
		}
		n.logf("ntfy: subscription dropped (%v), retrying in %s", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
		// Only replay replies sent while we were disconnected.
		since = strconv.FormatInt(time.Now().Add(-backoff).Unix(), 10)
	}
}

func (n *Ntfy) listenOnce(ctx context.Context, since string) error {
	url := n.server + "/" + n.replyTopic() + "/json?since=" + since
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("subscribe: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var ev struct {
			Event   string `json:"event"`
			Message string `json:"message"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.Event != "message" {
			continue
		}
		n.handleReply(ev.Message)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.EOF
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
