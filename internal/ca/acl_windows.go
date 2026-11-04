//go:build windows

package ca

import (
	"fmt"
	"os/exec"
	"os/user"
)

// restrictKeyACL removes inherited ACEs from the CA key and grants full
// control to the current user only (by SID, so localized group names and
// domain accounts work). Windows ignores the 0600 mode Go passes.
func restrictKeyACL(path string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	out, err := exec.Command("icacls", path, "/inheritance:r", "/grant:r", "*"+u.Uid+":F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %v: %s", err, out)
	}
	return nil
}
