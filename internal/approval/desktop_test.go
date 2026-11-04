package approval

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tranhoangtu-it/twokey/internal/rules"
)

const evil = `x"; Remove-Item C:\ -Recurse; $(calc) '` + "`" + `whoami` + "`"

func evilRequest() Request {
	return Request{ID: "7", Method: "DELETE", URL: "https://api.github.com/repos/a/b",
		Matches: []rules.Match{{Provider: "github", Operation: "delete repository", Resource: evil}}}
}

func TestDesktopNotifyNeverBlocks(t *testing.T) {
	d := NewDesktop(func(string, ...any) {})
	d.goos = "linux"
	d.run = func(ctx context.Context, _ []string, _ []string) error {
		<-ctx.Done() // a hung notification daemon
		return ctx.Err()
	}
	start := time.Now()
	d.Notify(evilRequest())
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("Notify blocked the broker")
	}
}

func TestDesktopCommandsNeverInterpolateRequestText(t *testing.T) {
	r := evilRequest()
	for _, goos := range []string{"windows", "darwin", "linux"} {
		argv, env := desktopCommand(goos, r)
		if len(argv) == 0 {
			t.Fatalf("%s: no command", goos)
		}
		switch goos {
		case "windows":
			for _, a := range argv {
				if strings.Contains(a, "Remove-Item") || strings.Contains(a, "whoami") {
					t.Fatalf("windows: request text reached the script: %q", a)
				}
			}
			if !strings.Contains(strings.Join(env, "\n"), "Remove-Item") {
				t.Fatal("windows: text must travel in the environment")
			}
		default:
			// Request text may only appear as a whole argv element of its own.
			for _, a := range argv[:len(argv)-2] {
				if strings.Contains(a, "whoami") {
					t.Fatalf("%s: request text inside script/flag %q", goos, a)
				}
			}
		}
	}
}

func TestDesktopIgnoresObserveAndCloses(t *testing.T) {
	d := NewDesktop(func(string, ...any) {})
	calls := 0
	d.run = func(context.Context, []string, []string) error { calls++; return nil }
	d.Closed(evilRequest(), Decision{})
	if calls != 0 {
		t.Fatal("Closed must not notify")
	}
}
