// Package audit appends one JSON line per held request to a local log.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

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

// Log is an append-only JSONL file. A nil *Log discards entries.
type Log struct {
	mu sync.Mutex
	f  *os.File
}

// Open opens (or creates) path for appending.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{f: f}, nil
}

// Write appends e. Errors are returned so callers can surface them.
func (l *Log) Write(e Entry) error {
	if l == nil {
		return nil
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.f.Write(append(line, '\n'))
	return err
}

// Close closes the underlying file.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	return l.f.Close()
}
