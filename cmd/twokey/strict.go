package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
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
	gatewayImage  = "alpine/socat"
	gatewayPort   = "7171"
	mountDir      = "/twokey"
)

func gatewayName(hostPort string) string { return "twokey-gw-" + hostPort }

// strictRunArgs builds the `docker run` argument list for the agent. Only
// public material is mounted: the CA certificate, the bundle and the Java
// truststore — never the CA key or the phone topic.
func strictRunArgs(image, workdir, home, hostPort string, interactive, tty bool, argv []string) []string {
	proxyURL := "http://" + gatewayName(hostPort) + ":" + gatewayPort
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
	vars := runenv.Vars(runenv.Config{ProxyURL: proxyURL, CACert: mountDir + "/ca.pem", Bundle: mountDir + "/bundle.pem"})
	vars = append(vars, runenv.KV{Key: "JAVA_TOOL_OPTIONS", Value: runenv.JavaToolOptions(
		gatewayName(hostPort)+":"+gatewayPort, mountDir+"/truststore.p12", ca.JavaTrustStorePassword, "")})
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
	if err := ensureGateway(port); err != nil {
		return setupFailure(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		return setupFailure(err)
	}
	tty := isTerminal(os.Stdin) && isTerminal(os.Stdout)
	cmd := exec.Command("docker", strictRunArgs(image, wd, home, port, true, tty, argv)...)
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

// ensureGateway starts (or reuses) the socat gateway that forwards
// strictNetwork traffic to the twokey proxy on the host.
func ensureGateway(hostPort string) error {
	name := gatewayName(hostPort)
	running, _ := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output()
	if string(running) == "true\n" {
		return nil
	}
	_ = exec.Command("docker", "rm", "-f", name).Run()
	out, err := exec.Command("docker", "run", "-d", "--name", name, "--restart", "unless-stopped",
		"--add-host", "host.docker.internal:host-gateway", gatewayImage,
		"tcp-listen:"+gatewayPort+",fork,reuseaddr", "tcp:host.docker.internal:"+hostPort).CombinedOutput()
	if err != nil {
		return fmt.Errorf("start gateway: %v: %s", err, out)
	}
	if out, err := exec.Command("docker", "network", "connect", strictNetwork, name).CombinedOutput(); err != nil {
		return fmt.Errorf("attach gateway: %v: %s", err, out)
	}
	return nil
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
