package approval

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Observer is told about requests that observe mode let through. Channels
// that only implement Notifier are not called in observe mode.
type Observer interface {
	Observed(Request)
}

// ObserveLog prints one line per request observe mode would have held.
type ObserveLog struct {
	mu sync.Mutex
	w  io.Writer
}

// NewObserveLog writes "would hold" lines to w.
func NewObserveLog(w io.Writer) *ObserveLog { return &ObserveLog{w: w} }

// Notify and Closed are no-ops: in observe mode nothing is really held.
func (*ObserveLog) Notify(Request)           {}
func (*ObserveLog) Closed(Request, Decision) {}

// Observed prints the request that would have been held.
func (l *ObserveLog) Observed(r Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s 👁  WOULD HOLD [%s] %s — %s %s (observe mode: forwarded, NOT PROTECTED)\n",
		r.Created.Format(time.TimeOnly), r.ID, r.Summary(), Clean(r.Method), Clean(r.URL))
}
