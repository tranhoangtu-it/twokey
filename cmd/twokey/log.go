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

// maxAuditLine is the longest entry `twokey log` shows; longer ones (an
// agent can send a huge URL) are counted as skipped, not printed.
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
	if o.n < 0 {
		return fmt.Errorf("-n must be 0 (everything) or more, got %d", o.n)
	}
	if o.since < 0 {
		return fmt.Errorf("--since must be a positive duration such as 24h, got %s", o.since)
	}
	home, err := homeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, "audit.jsonl")
	files := audit.Files(path) // rotated files first: oldest entries first
	if len(files) == 0 {
		fmt.Println("no audit log yet at", path, "— nothing has been held.")
		return nil
	}
	o.now = time.Now()
	return printLogFiles(os.Stdout, files, o)
}

// printLogFiles prints entries from several files (oldest first) as one log.
func printLogFiles(w io.Writer, paths []string, o logOptions) error {
	p := newLogPrinter(w, o)
	for _, path := range paths {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue // rotated away while we were reading
		}
		if err != nil {
			return err
		}
		err = p.read(f)
		f.Close()
		if err != nil {
			return err
		}
	}
	return p.finish()
}

type logLine struct {
	raw   string
	entry audit.Entry
}

// printLog prints the entries of one audit stream.
func printLog(w io.Writer, r io.Reader, o logOptions) error {
	p := newLogPrinter(w, o)
	if err := p.read(r); err != nil {
		return err
	}
	return p.finish()
}

// logPrinter streams entries: with -n it keeps only the last n matching
// entries (a ring), so memory stays bounded however large the log is.
type logPrinter struct {
	w         io.Writer
	o         logOptions
	ring      []logLine
	next      int
	printed   int
	malformed int
	err       error // first error re-encoding an entry
}

func newLogPrinter(w io.Writer, o logOptions) *logPrinter { return &logPrinter{w: w, o: o} }

// read consumes one file. Lines longer than maxAuditLine are skipped
// without being held in memory.
func (p *logPrinter) read(r io.Reader) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var line []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > maxAuditLine+1 {
				tooLong, line = true, line[:0]
			} else {
				line = append(line, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // the line goes on
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		p.line(line, tooLong)
		line, tooLong = line[:0], false
		if err != nil { // io.EOF; an unterminated last line was handled above
			return nil
		}
	}
}

func (p *logPrinter) line(b []byte, tooLong bool) {
	raw := strings.TrimSpace(string(b))
	if raw == "" && !tooLong {
		return
	}
	var e audit.Entry
	switch {
	case tooLong: // agent-sized URL: skip, don't flood the terminal
		p.malformed++
	case json.Unmarshal([]byte(raw), &e) != nil:
		p.malformed++
	case keepEntry(e, p.o):
		p.keep(logLine{raw, e})
	}
}

func (p *logPrinter) keep(l logLine) {
	if p.o.n <= 0 { // everything: print as we go
		p.print(l)
		return
	}
	if len(p.ring) < p.o.n {
		p.ring = append(p.ring, l)
		return
	}
	p.ring[p.next] = l
	p.next = (p.next + 1) % p.o.n
}

func (p *logPrinter) print(l logLine) {
	p.printed++
	if p.o.json {
		// Re-encode: encoding/json escapes control characters, so a
		// tampered log cannot send raw escape sequences to the terminal.
		out, err := json.Marshal(l.entry)
		if err != nil {
			if p.err == nil {
				p.err = err
			}
			return
		}
		fmt.Fprintln(p.w, string(out))
		return
	}
	fmt.Fprintln(p.w, formatEntry(l.entry))
}

func (p *logPrinter) finish() error {
	for i := range p.ring {
		p.print(p.ring[(p.next+i)%len(p.ring)])
	}
	if !p.o.json {
		if p.printed == 0 {
			fmt.Fprintln(p.w, "no matching entries")
		}
		if p.malformed > 0 {
			fmt.Fprintf(p.w, "(skipped %d malformed line(s))\n", p.malformed)
		}
	}
	return p.err
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
