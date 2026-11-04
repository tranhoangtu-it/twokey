package approval

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// desktopTimeout bounds one notification command; a hung notification
// daemon must never delay a hold.
const desktopTimeout = 5 * time.Second

// maxToastText keeps notification text short.
const maxToastText = 240

// windowsToastScript shows a toast with WinRT from Windows PowerShell 5.1.
// It is constant: title and body arrive only through environment variables,
// never spliced into the script. The AppUserModelID is PowerShell's own, as
// toasts from unregistered app ids are silently dropped.
const windowsToastScript = `$ErrorActionPreference='Stop'; ` +
	`[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; ` +
	`$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); ` +
	`$t = $x.GetElementsByTagName('text'); ` +
	`$null = $t.Item(0).AppendChild($x.CreateTextNode($env:TWOKEY_TOAST_TITLE)); ` +
	`$null = $t.Item(1).AppendChild($x.CreateTextNode($env:TWOKEY_TOAST_BODY)); ` +
	`$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'; ` +
	`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($x))`

// Desktop pops a native notification when a request is held, so a hold is
// noticed even when the twokey window is buried. Best effort: failures are
// logged once and never affect the decision.
type Desktop struct {
	goos string
	run  func(ctx context.Context, argv, env []string) error
	logf func(string, ...any)
	once sync.Once
	// busy allows one notification process at a time: a burst of holds
	// (which the agent controls) must not spawn a process per request.
	busy chan struct{}
}

// NewDesktop returns a desktop notifier for this OS.
func NewDesktop(logf func(string, ...any)) *Desktop {
	return &Desktop{goos: runtime.GOOS, run: runCommand, logf: logf, busy: make(chan struct{}, 1)}
}

func runCommand(ctx context.Context, argv, env []string) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// Notify shows the held request without blocking the broker.
func (d *Desktop) Notify(r Request) {
	argv, env := desktopCommand(d.goos, r)
	if len(argv) == 0 {
		return
	}
	select {
	case d.busy <- struct{}{}:
	default:
		return // one is already on screen; the terminal and phone list them all
	}
	go func() {
		defer func() { <-d.busy }()
		ctx, cancel := context.WithTimeout(context.Background(), desktopTimeout)
		defer cancel()
		if err := d.run(ctx, argv, env); err != nil {
			d.once.Do(func() { d.logf("desktop notifications unavailable: %v", err) })
		}
	}()
}

// Closed is a no-op: the outcome is shown in the twokey window.
func (*Desktop) Closed(Request, Decision) {}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// desktopCommand builds the notification command. Request-derived text is
// passed as whole argv elements (macOS, Linux) or environment variables
// (Windows), never interpolated into a script.
func desktopCommand(goos string, r Request) (argv, env []string) {
	title := truncate(Clean(fmt.Sprintf("twokey: approval needed (#%s)", r.ID)), maxToastText)
	body := truncate(Clean(r.Summary()+" — approve or deny in the twokey window or on your phone"), maxToastText)
	switch goos {
	case "windows":
		return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command", windowsToastScript},
			[]string{"TWOKEY_TOAST_TITLE=" + title, "TWOKEY_TOAST_BODY=" + body}
	case "darwin":
		return []string{"osascript",
			"-e", "on run argv",
			"-e", "display notification (item 2 of argv) with title (item 1 of argv) sound name \"Ping\"",
			"-e", "end run", title, body}, nil
	case "linux", "freebsd", "openbsd", "netbsd":
		return []string{"notify-send", "--app-name=twokey", "--urgency=critical", "--", title, body}, nil
	default:
		return nil, nil
	}
}
