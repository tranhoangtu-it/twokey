//go:build !windows

package ca

// restrictKeyACL is a no-op off Windows: the key is written with mode 0600.
func restrictKeyACL(string) error { return nil }
