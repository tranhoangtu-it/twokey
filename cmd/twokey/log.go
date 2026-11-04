package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/approval"
	"github.com/tranhoangtu-it/twokey/internal/audit"
)

type logOptions struct {
	n        int
	provider string
	denied   bool
	since    time.Duration
	json     bool
	now      time.Time
}

// maxAuditLine bounds one audit entry (SQL statements can be long).
const maxAuditLine = 1 << 20

func cmdLog(args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	var o logOptions
	fs.IntVar(&o.n, "n", 20, "show the last N entries")
	fs.StringVar(&o.provider, "provider", "", "only this provider (github, railway, postgres, …)")
	fs.BoolVar(&o.denied, "denied", false, "only requests that were not approved")
	fs.DurationVar(&o.since, "since", 0, "only entries newer than this (e.g. 24h)")
	fs.BoolVar(&o.json, "json", false, "print the raw JSON lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := homeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, "audit.jsonl")
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("no audit log yet at", path, "— nothing has been held.")
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	o.now = time.Now()
	return printLog(os.Stdout, f, o)
}

type logLine struct {
	raw   string
	entry audit.Entry
}

func printLog(w io.Writer, r io.Reader, o logOptions) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxAuditLine)
	var kept []logLine
	malformed := 0
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			malformed++
			continue
		}
		if keepEntry(e, o) {
			kept = append(kept, logLine{raw, e})
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if o.n > 0 && len(kept) > o.n {
		kept = kept[len(kept)-o.n:]
	}
	for _, l := range kept {
		if o.json {
			fmt.Fprintln(w, l.raw)
		} else {
			fmt.Fprintln(w, formatEntry(l.entry))
		}
	}
	if !o.json {
		if len(kept) == 0 {
			fmt.Fprintln(w, "no matching entries")
		}
		if malformed > 0 {
			fmt.Fprintf(w, "(skipped %d malformed line(s))\n", malformed)
		}
	}
	return nil
}

func keepEntry(e audit.Entry, o logOptions) bool {
	if o.denied && e.Approved {
		return false
	}
	if o.since > 0 && e.Time.Before(o.now.Add(-o.since)) {
		return false
	}
	if o.provider != "" {
		for _, m := range e.Matches {
			if strings.EqualFold(m.Provider, o.provider) {
				return true
			}
		}
		return false
	}
	return true
}

func decisionLabel(e audit.Entry) string {
	switch {
	case e.By == "observe":
		return "OBSERVED"
	case e.By == "allowlist":
		return "ALLOWLIST"
	case e.Approved:
		return "APPROVED"
	default:
		return "DENIED"
	}
}

func formatEntry(e audit.Entry) string {
	what := approval.Clean(e.Uninspectable)
	if len(e.Matches) > 0 {
		m := e.Matches[0]
		res := m.Resource
		if res == "" {
			res = "(unknown resource)"
		}
		what = approval.Clean(fmt.Sprintf("%s %s %s", m.Provider, m.Operation, res))
		if n := len(e.Matches) - 1; n > 0 {
			what += fmt.Sprintf(" (+%d more)", n)
		}
	}
	return fmt.Sprintf("%s  %-9s %s  [%s: %s]", e.Time.Local().Format("2006-01-02 15:04:05"), decisionLabel(e),
		what, approval.Clean(e.By), approval.Clean(e.Reason))
}
