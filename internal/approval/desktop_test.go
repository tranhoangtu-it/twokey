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

func TestDesktopRunsAtMostOneNotificationAtATime(t *testing.T) {
	d := NewDesktop(func(string, ...any) {})
	d.goos = "linux"
	started := make(chan struct{}, 100)
	release := make(chan struct{})
	d.run = func(context.Context, []string, []string) error {
		started <- struct{}{}
		<-release
		return nil
	}
	for i := 0; i < 50; i++ {
		d.Notify(evilRequest())
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	if n := len(started); n != 1 {
		t.Fatalf("a burst of holds started %d notification processes", n)
	}
}

func TestDesktopDropsPSModulePath(t *testing.T) {
	got := withoutPSModulePath([]string{"PATH=x", "PSModulePath=C:\\pwsh7\\Modules", "psmodulepath=y", "HOME=h"})
	if len(got) != 2 || got[0] != "PATH=x" || got[1] != "HOME=h" {
		t.Fatalf("got %v", got)
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
