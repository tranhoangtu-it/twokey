package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/rules"
)

// The log is bounded: past maxSize it rotates to .1, .2, .3 and older data
// is dropped, so an agent looping on an allowed call cannot fill the disk.
func TestLogRotatesAndKeepsThreeFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := OpenWith(path, Options{MaxSize: 4096, Keep: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 200; i++ {
		if err := l.Write(Entry{Time: time.Now(), ID: "x", URL: strings.Repeat("u", 200)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{path, path + ".1", path + ".2", path + ".3"} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if st.Size() > 4096 {
			t.Errorf("%s is %d bytes, over the cap", p, st.Size())
		}
		if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", p, st.Mode().Perm())
		}
	}
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Fatal("only three rotated files are kept")
	}
}

func TestDefaultRotationLimits(t *testing.T) {
	if DefaultMaxSize != 20<<20 || DefaultKeep != 3 {
		t.Fatalf("defaults: %d bytes, keep %d", DefaultMaxSize, DefaultKeep)
	}
}

// Every line is a complete JSON object even with concurrent writers.
func TestConcurrentWritesStayWholeLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := OpenWith(path, Options{MaxSize: 1 << 30, Keep: 1})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = l.Write(Entry{ID: "c", URL: strings.Repeat("z", 300)})
			}
		}()
	}
	wg.Wait()
	l.Close()
	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("torn line %d: %v", n, err)
		}
		n++
	}
	if n != 1000 {
		t.Fatalf("want 1000 lines, got %d", n)
	}
}

// Agent-controlled fields are capped so one entry cannot be megabytes.
func TestLongFieldsAreTruncated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	matches := []rules.Match{{RuleID: "postgres.drop-table", Message: strings.Repeat("m", 100000), Resource: strings.Repeat("r", 100000)}}
	if err := l.Write(Entry{URL: strings.Repeat("a", 100000), Matches: matches, Reason: strings.Repeat("q", 100000)}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if len(matches[0].Message) != 100000 {
		t.Fatal("Write must not modify the caller's matches")
	}
	st, _ := os.Stat(path)
	if st.Size() > 5*maxField+1024 {
		t.Fatalf("entry is %d bytes", st.Size())
	}
}

// Holds denied at shutdown may be audited just after Close: the row must
// still land in the file instead of being lost.
func TestWriteAfterCloseStillAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Entry{ID: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Entry{ID: "2", By: "shutdown"}); err != nil {
		t.Fatalf("late write: %v", err)
	}
	data, _ := os.ReadFile(path)
	if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) != 2 || !strings.Contains(lines[1], `"shutdown"`) {
		t.Fatalf("late shutdown row lost: %q", data)
	}
}

// Files lists the log and its rotations, oldest first, for `twokey log`.
func TestFilesOldestFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	for _, p := range []string{path, path + ".1", path + ".3"} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := Files(path)
	want := []string{path + ".3", path + ".1", path}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Files = %v, want %v", got, want)
	}
}
