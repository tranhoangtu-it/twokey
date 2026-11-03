package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteAppendsJSONLinesAndFailsAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"1", "2"} {
		if err := l.Write(Entry{Time: time.Unix(0, 0).UTC(), ID: id, Method: "POST", By: "terminal"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Entry{ID: "3"}); err == nil {
		t.Fatal("write after close must fail, not race the close")
	}
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
	var e Entry
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil || e.ID != "2" {
		t.Fatalf("bad line %q: %v", lines[1], err)
	}
	var nilLog *Log
	if err := nilLog.Write(Entry{}); err != nil {
		t.Fatal("nil log must discard")
	}
}
