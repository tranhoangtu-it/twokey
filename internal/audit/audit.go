// Package audit appends one JSON line per held request to a local log.
package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// Entry is one held request and its outcome.
type Entry struct {
	Time          time.Time     `json:"time"`
	ID            string        `json:"id"`
	Method        string        `json:"method"`
	URL           string        `json:"url"`
	Matches       []rules.Match `json:"matches,omitempty"`
	Uninspectable string        `json:"uninspectable,omitempty"`
	Approved      bool          `json:"approved"`
	By            string        `json:"by"`
	Reason        string        `json:"reason"`
}

const (
	// DefaultMaxSize is the size at which the log rotates.
	DefaultMaxSize = 20 << 20
	// DefaultKeep is how many rotated files (audit.jsonl.1 …) are kept.
	DefaultKeep = 3
	// maxField caps one agent-controlled field (URL, SQL text, …) so a
	// single entry cannot be megabytes.
	maxField = 8 << 10
	// maxRotated bounds how many rotated files Files looks for.
	maxRotated = 9
)

// Options bound the log's size on disk.
type Options struct {
	MaxSize int64 // rotate when the next entry would exceed this
	Keep    int   // rotated files kept (path.1 is the newest)
}

// Log is an append-only JSONL file with size-based rotation. A nil *Log
// discards entries.
type Log struct {
	mu     sync.Mutex
	path   string
	opts   Options
	f      *os.File
	closed bool
}

// Open opens (or creates) path for appending with the default limits.
func Open(path string) (*Log, error) {
	return OpenWith(path, Options{MaxSize: DefaultMaxSize, Keep: DefaultKeep})
}

// OpenWith opens (or creates) path for appending with explicit limits.
func OpenWith(path string, o Options) (*Log, error) {
	if o.Keep < 1 {
		o.Keep = 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := openAppend(path)
	if err != nil {
		return nil, err
	}
	return &Log{path: path, opts: o, f: f}, nil
}

func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}

// Write appends e as one line. Errors are returned so callers can surface
// them. Writes after Close (a hold denied during shutdown that finished
// late) still land: the file is opened for that one append.
func (l *Log) Write(e Entry) error {
	if l == nil {
		return nil
	}
	line, err := json.Marshal(bounded(e))
	if err != nil {
		return err
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		f, err := openAppend(l.path)
		if err != nil {
			return err
		}
		werr := writeLine(f, line)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		return werr
	}
	if l.f == nil { // reopening after a rotation failed: retry now
		f, err := openAppend(l.path)
		if err != nil {
			return err
		}
		l.f = f
	}
	l.rotateIfNeeded(int64(len(line)))
	if l.f == nil {
		return errors.New("audit log: could not reopen after rotation")
	}
	return writeLine(l.f, line)
}

// writeLine writes one line with a single Write (O_APPEND keeps lines from
// several processes whole). After a short write (disk full) it terminates
// the torn line so the next entry starts on its own line.
func writeLine(f *os.File, line []byte) error {
	n, err := f.Write(line)
	if err != nil && n > 0 && n < len(line) {
		_, _ = f.Write([]byte{'\n'})
	}
	return err
}

// rotateIfNeeded moves the log aside when the next line would push it over
// MaxSize. Another process (the database guard next to the proxy) may have
// rotated already: then the current path is reopened. Rotation failures
// (e.g. Windows refusing to rename a file another process holds open) keep
// appending to the current file rather than losing entries.
func (l *Log) rotateIfNeeded(next int64) {
	if cur, err := os.Stat(l.path); err != nil || !sameFile(l.f, cur) {
		if f, err := openAppend(l.path); err == nil {
			l.f.Close()
			l.f = f
		}
	}
	st, err := l.f.Stat()
	if err != nil || st.Size() == 0 || st.Size()+next <= l.opts.MaxSize {
		return
	}
	l.f.Close()
	for i := l.opts.Keep - 1; i >= 1; i-- {
		_ = os.Rename(rotated(l.path, i), rotated(l.path, i+1))
	}
	_ = os.Rename(l.path, rotated(l.path, 1))
	l.f = nil // Write retries the open on the next entry
	if f, err := openAppend(l.path); err == nil {
		l.f = f
	}
}

func sameFile(f *os.File, fi os.FileInfo) bool {
	st, err := f.Stat()
	return err == nil && os.SameFile(st, fi)
}

func rotated(path string, i int) string { return path + "." + strconv.Itoa(i) }

// Files returns path and its rotated files that exist, oldest first.
func Files(path string) []string {
	var out []string
	for i := maxRotated; i >= 1; i-- {
		if _, err := os.Stat(rotated(path, i)); err == nil {
			out = append(out, rotated(path, i))
		}
	}
	if _, err := os.Stat(path); err == nil {
		out = append(out, path)
	}
	return out
}

// bounded returns a copy of e with agent-controlled fields capped.
func bounded(e Entry) Entry {
	e.URL = capField(e.URL)
	e.Reason = capField(e.Reason)
	e.Uninspectable = capField(e.Uninspectable)
	if len(e.Matches) > 0 {
		ms := make([]rules.Match, len(e.Matches))
		for i, m := range e.Matches {
			m.Message = capField(m.Message)
			m.Resource = capField(m.Resource)
			m.Operation = capField(m.Operation)
			ms[i] = m
		}
		e.Matches = ms
	}
	return e
}

const truncatedMark = "…[truncated]"

func capField(s string) string {
	if len(s) <= maxField {
		return s
	}
	cut := maxField - len(truncatedMark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncatedMark
}

// Close closes the underlying file. Later writes reopen it per entry.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}
