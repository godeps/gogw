//go:build gogwprocess

package gogw_test

import (
	"bufio"
	"bytes"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGatewayProcesses(t *testing.T) {
	binary := os.Getenv("GOGW_TEST_BINARY")
	require.NotEmpty(t, binary)
	c := newCluster(t)
	c.cancel()
	for _, done := range c.done {
		<-done
	}
	for _, server := range c.servers {
		server.Close()
	}
	routingFiles := make([]string, 0, 2)
	processes := make([]*exec.Cmd, 0, 2)
	exits := make([]chan error, 0, 2)
	for i, cfg := range c.cfgs {
		dir := t.TempDir()
		configFile := filepath.Join(dir, "gogw.json")
		data, err := json.Marshal(cfg)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(configFile, data, 0o600))
		dynamic := fmt.Sprintf("http:\n  routers:\n    app:\n      rule: 'PathPrefix(`/`)'\n      entryPoints: [websecure]\n      service: checkout@gogw\n      tls: {}\ntls:\n  certificates:\n    - certFile: %q\n      keyFile: %q\n  options:\n    default:\n      clientAuth:\n        caFiles: [%q]\n        clientAuthType: VerifyClientCertIfGiven\n", cfg.CertFile, cfg.KeyFile, cfg.CAFile)
		routing := filepath.Join(dir, "routing.yaml")
		routingFiles = append(routingFiles, routing)
		require.NoError(t, os.WriteFile(routing, []byte(dynamic), 0o600))
		install := fmt.Sprintf("entryPoints:\n  websecure:\n    address: %q\n    transport:\n      lifeCycle:\n        graceTimeOut: 2s\nproviders:\n  file:\n    watch: true\n    filename: %q\nlog:\n  level: ERROR\nglobal:\n  checkNewVersion: false\n  sendAnonymousUsage: false\n", strings.TrimPrefix(c.servers[i].URL, "https://"), routing)
		installFile := filepath.Join(dir, "traefik.yaml")
		require.NoError(t, os.WriteFile(installFile, []byte(install), 0o600))
		command := exec.Command(binary, "--configFile="+installFile)
		command.Env = append(os.Environ(), "GOGW_CONFIG="+configFile)
		output := new(bytes.Buffer)
		command.Stdout = output
		command.Stderr = output
		require.NoError(t, command.Start())
		processes = append(processes, command)
		done := make(chan error, 1)
		exits = append(exits, done)
		go func() { done <- command.Wait() }()
		t.Cleanup(func() {
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				_ = command.Process.Kill()
				<-done
			}
			if t.Failed() {
				t.Log(output.String())
			}
		})
	}
	require.Eventually(t, func() bool {
		for _, server := range c.servers {
			response, err := c.public.Get(server.URL + "/__gogw/ready")
			if err != nil {
				return false
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				return false
			}
		}
		return true
	}, 20*time.Second, 100*time.Millisecond)
	for _, subject := range []string{"ordinary", "canary-user"} {
		response := c.request(t, 0, http.MethodGet, "/encoded%2Fpath?a=b%2Fc", subject, "", nil)
		require.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, 2, response.ProtoMajor)
		expected := "stable"
		if subject == "canary-user" {
			expected = "canary"
		}
		assert.Equal(t, expected, response.Header.Get("X-Actual-Build"))
		response.Body.Close()
	}
	c.control.Close()
	c.controlHTTP.Close()
	for _, path := range routingFiles {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		updated := strings.Replace(string(data), "http:\n  routers:", "http:\n  middlewares:\n    reloaded:\n      headers:\n        customResponseHeaders:\n          X-Route-Reload: yes\n  routers:", 1)
		updated = strings.Replace(updated, "      service: checkout@gogw", "      middlewares: [reloaded]\n      service: checkout@gogw", 1)
		require.NoError(t, os.WriteFile(path, []byte(updated), 0o600))
	}
	require.Eventually(t, func() bool {
		response, err := c.public.Get(c.servers[0].URL + "/__gogw/ready")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusNoContent && response.Header.Get("X-Route-Reload") == "yes"
	}, 10*time.Second, 100*time.Millisecond)
	forged := c.request(t, 0, http.MethodGet, "/", "ordinary", "", http.Header{"X-Gogw-Ticket": []string{"fake"}})
	assert.Equal(t, 403, forged.StatusCode)
	forged.Body.Close()
	response := c.request(t, 0, http.MethodGet, "/sse", "canary-user", "", nil)
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "data: canary\n", line)
	require.NoError(t, response.Body.Close())
	select {
	case <-c.canceled:
	case <-time.After(time.Second):
		t.Fatal("process SSE cancellation failed")
	}
	draining := c.request(t, 0, http.MethodGet, "/sse", "canary-user", "", nil)
	line, err = bufio.NewReader(draining.Body).ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "data: canary\n", line)
	require.NoError(t, processes[0].Process.Signal(syscall.SIGTERM))
	select {
	case err := <-exits[0]:
		assert.NoError(t, err)
		exits[0] <- err
	case <-time.After(8 * time.Second):
		t.Fatal("process shutdown timed out")
	}
	select {
	case <-c.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not cancel upstream SSE")
	}
	require.NoError(t, draining.Body.Close())
}
