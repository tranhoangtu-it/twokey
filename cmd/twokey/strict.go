package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"

	"github.com/tranhoangtu-it/twokey/internal/ca"
	"github.com/tranhoangtu-it/twokey/internal/runenv"
)

// Strict mode runs the agent in a Docker container attached only to an
// --internal network. Its single way out is a small gateway container that
// forwards to the twokey proxy on the host, so even an agent that unsets
// HTTPS_PROXY or opens raw sockets cannot reach the internet directly.
const (
	strictNetwork = "twokey-strict"
	// gatewayImage carries all agent egress, so it is pinned by digest
	// (alpine/socat:latest multi-arch index as of 2026-11-05) instead of
	// following a mutable tag.
	gatewayImage = "alpine/socat@sha256:466c8a0383e16463fabdb7df01008292fb78d07da60224a46cb5d3142ce122ed"
	gatewayPort  = "7171"
	mountDir     = "/twokey"
)

// newGatewayName names a gateway for one strict run. Gateways are per run
// and removed when the agent exits; the "twokey-gw-" prefix is what
// `twokey uninstall` cleans up after a crash.
func newGatewayName(hostPort string) string { return "twokey-gw-" + hostPort + "-" + randomHex(4) }

// strictRunArgs builds the `docker run` argument list for the agent. Only
// public material is mounted: the CA certificate, the bundle and the Java
// truststore — never the CA key or the phone topic. A project allow file
// is mounted read-only so the agent cannot rewrite it.
func strictRunArgs(image, workdir, home, gateway string, interactive, tty bool, argv []string) []string {
	proxyURL := "http://" + gateway + ":" + gatewayPort
	args := []string{"run", "--rm", "--network", strictNetwork}
	if interactive {
		args = append(args, "-i")
	}
	if tty {
		args = append(args, "-t")
	}
	for _, f := range []string{"ca.pem", "bundle.pem", "truststore.p12"} {
		args = append(args, "-v", filepath.Join(home, f)+":"+mountDir+"/"+f+":ro")
	}
	args = append(args, "-v", workdir+":/work", "-w", "/work")
	if allow := filepath.Join(workdir, defaultAllowFile); fileExists(allow) {
		args = append(args, "-v", allow+":/work/"+defaultAllowFile+":ro")
	}
	vars := runenv.Vars(runenv.Config{ProxyURL: proxyURL, CACert: mountDir + "/ca.pem", Bundle: mountDir + "/bundle.pem"})
	vars = append(vars, runenv.KV{Key: "JAVA_TOOL_OPTIONS", Value: runenv.JavaToolOptions(
		gateway+":"+gatewayPort, mountDir+"/truststore.p12", ca.JavaTrustStorePassword, "")})
	for _, kv := range vars {
		args = append(args, "-e", kv.Key+"="+kv.Value)
	}
	args = append(args, image)
	return append(args, argv...)
}

// runStrict prepares the network and gateway, then runs the agent.
func runStrict(proxyAddr, image string, argv []string) error {
	if image == "" {
		return setupFailure(errors.New("--strict needs --image (the container image that has your agent, e.g. node:22)"))
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		return setupFailure(errors.New("--strict needs a running Docker daemon"))
	}
	_, port, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return setupFailure(err)
	}
	// agentEnv (re)writes bundle.pem and truststore.p12 that we mount.
	if _, err := agentEnv(proxyAddr); err != nil {
		return setupFailure(err)
	}
	home, err := homeDir()
	if err != nil {
		return setupFailure(err)
	}
	if err := ensureStrictNetwork(); err != nil {
		return setupFailure(err)
	}
	gateway := newGatewayName(port)
	if err := startGateway(gateway, port); err != nil {
		removeGateway(gateway)
		return setupFailure(err)
	}
	defer removeGateway(gateway)
	// Ctrl+C belongs to the agent in the container; twokey stays alive to
	// remove the gateway when it exits.
	signal.Notify(make(chan os.Signal, 1), os.Interrupt)
	wd, err := os.Getwd()
	if err != nil {
		return setupFailure(err)
	}
	tty := isTerminal(os.Stdin) && isTerminal(os.Stdout)
	cmd := exec.Command("docker", strictRunArgs(image, wd, home, gateway, true, tty, argv)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	fmt.Fprintf(os.Stderr, "twokey: strict mode — %s runs in %s on network %s; its only egress is twokey\n", argv[0], image, strictNetwork)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() > 0 {
			return exitCode(ee.ExitCode())
		}
		return setupFailure(fmt.Errorf("docker run: %w", err))
	}
	return nil
}

func ensureStrictNetwork() error {
	if exec.Command("docker", "network", "inspect", strictNetwork).Run() == nil {
		return nil
	}
	out, err := exec.Command("docker", "network", "create", "--internal", strictNetwork).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create network %s: %v: %s", strictNetwork, err, out)
	}
	return nil
}

// gatewayRunArgs starts the socat gateway that forwards strictNetwork
// traffic to the twokey proxy on the host. No restart policy: it lives only
// as long as this run.
func gatewayRunArgs(name, hostPort string) []string {
	return []string{"run", "-d", "--name", name,
		"--add-host", "host.docker.internal:host-gateway", gatewayImage,
		"tcp-listen:" + gatewayPort + ",fork,reuseaddr", "tcp:host.docker.internal:" + hostPort}
}

// startGateway starts this run's gateway and attaches it to strictNetwork.
func startGateway(name, hostPort string) error {
	out, err := exec.Command("docker", gatewayRunArgs(name, hostPort)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("start gateway: %v: %s", err, out)
	}
	if out, err := exec.Command("docker", "network", "connect", strictNetwork, name).CombinedOutput(); err != nil {
		return fmt.Errorf("attach gateway: %v: %s", err, out)
	}
	return nil
}

// removeGateway deletes this run's gateway container.
func removeGateway(name string) {
	if out, err := exec.Command("docker", "rm", "-f", name).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "twokey: could not remove gateway %s (%v: %s); `twokey uninstall` removes it\n", name, err, out)
	}
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
