//go:build gogwprocess

package gogw_test

// process_test.go runs the acceptance matrix against the built binary instead of an
// in-process gateway. What it adds is everything only a process can show: the
// listener the membership artifact advertises, HTTP/2 over that listener, the mTLS
// hop between two processes carrying a signed ticket, SSE across that hop, and
// termination through the same shutdown hook a deployment uses.
//
// The control plane, the relay and the applications stay in-process: they are
// fakes either way, and keeping them here means the test observes the failure of a
// gateway process rather than of its scaffolding.

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"io"
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

// processStopTimeout bounds the wait for a terminated process. Traefik stops the
// entrypoints inside the grace time the install configuration sets, and the gateway
// drains before that, so a process that outlives this is hung rather than slow.
const processStopTimeout = 20 * time.Second

// gatewayProcess is one running binary with the output it produced, kept so a
// failure can be read from the test log.
type gatewayProcess struct {
	command *exec.Cmd
	output  *bytes.Buffer
	exited  chan error
}

// TestGatewayProcesses starts one real gateway process per published member and
// drives the traffic matrix through them.
func TestGatewayProcesses(t *testing.T) {
	binary := os.Getenv("GOGW_TEST_BINARY")
	require.NotEmpty(t, binary, "GOGW_TEST_BINARY must name the built traefik binary")

	c := newCluster(t)
	c.activate(t, release(1, nil, nil))

	// The in-process gateways hand their listeners over to the processes. The port is
	// part of the identity the control plane published, so an instance is only
	// reachable at the address its own membership artifact names if the process
	// serves on the same port the harness reserved.
	for _, in := range c.members {
		in.stop(t)
		in.server.Close()
	}
	c.public.CloseIdleConnections()

	processes := make([]*gatewayProcess, 0, len(c.members))
	for index, in := range c.members {
		processes = append(processes, startGatewayProcess(t, binary, c, index, in))
	}

	// Readiness is the process's own claim, and it is reached from the state the
	// stopped gateways persisted: the process re-reads the approved release and its
	// membership before the control plane is asked for anything.
	await(t, "the readiness of every process", func() bool {
		for _, in := range c.members {
			response, err := c.public.Get(in.server.URL + "/__gogw/ready")
			if err != nil {
				return false
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				return false
			}
		}
		return true
	})

	// A request the instance decides itself is served over HTTP/2 on its own
	// listener, with the hop marker of a local decision.
	response := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, 2, response.ProtoMajor)
	assert.Equal(t, "stable", response.Header.Get("X-Actual-Build"))
	assert.Equal(t, "local", response.Header.Get("X-Actual-Hop"))
	body(t, response)

	// The canary build is served by the peer process, so this request crosses the
	// internal face: one hop, over mTLS between two binaries, carrying the final
	// ticket the first process minted.
	response = c.request(t, 0, http.MethodGet, "/orders", "canary-user", "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, 2, response.ProtoMajor)
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
	assert.Equal(t, "1", response.Header.Get("X-Actual-Hop"))
	body(t, response)

	// A ticket this process did not mint is refused before it is forwarded, so the
	// internal face is not reachable with a caller-supplied marker.
	forged := c.request(t, 0, http.MethodGet, "/orders", "user-1", "", http.Header{"X-Gogw-Ticket": []string{"forged"}})
	assert.Equal(t, http.StatusForbidden, forged.StatusCode)
	body(t, forged)

	// A stream is served through the process as well, and it is the same forwarded
	// hop: the consumer's connection ends at this process, the upstream one at the
	// peer's application.
	stream := c.stream(t, 0, "/sse", "canary-user")
	assert.Equal(t, "canary", event(t, stream))

	// Termination is the deployment path: the signal runs the shutdown hook, which
	// drains, cancels what it was streaming upstream instead of leaking it, hands the
	// lease back, and lets the binary exit cleanly.
	terminated := processes[0]
	require.NoError(t, terminated.command.Process.Signal(syscall.SIGTERM))
	select {
	case build := <-c.canceled:
		assert.Equal(t, "canary", build)
	case <-time.After(processStopTimeout):
		t.Fatal("the terminated process left its upstream stream open")
	}
	select {
	case err := <-terminated.exited:
		assert.NoError(t, err, terminated.output.String())
		terminated.exited <- err
	case <-time.After(processStopTimeout):
		t.Fatal(terminated.output.String())
	}
	assert.True(t, c.journalContains("Deregister", "stable-0"))

	// Nothing new is served by an instance that is going away: the entrypoint either
	// refuses the connection or answers a failure, never a 200.
	stale, err := c.public.Get(c.members[0].server.URL + "/__gogw/ready")
	if err == nil {
		assert.GreaterOrEqual(t, stale.StatusCode, http.StatusInternalServerError)
		body(t, stale)
	}

	// The process that is still running keeps serving, which is what makes the
	// termination a replacement rather than an outage.
	response = c.request(t, 1, http.MethodGet, "/orders", "canary-user", "", nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, "canary", response.Header.Get("X-Actual-Build"))
	assert.Equal(t, "local", response.Header.Get("X-Actual-Hop"))
	body(t, response)
	require.NoError(t, stream.Body.Close())
}

// startGatewayProcess writes the install and routing configuration for one member
// and starts the binary on the port that member already advertises.
func startGatewayProcess(t *testing.T, binary string, c *cluster, index int, in *instance) *gatewayProcess {
	t.Helper()
	dir := t.TempDir()
	config, err := json.Marshal(in.cfg)
	require.NoError(t, err)
	configFile := filepath.Join(dir, "gogw.json")
	require.NoError(t, os.WriteFile(configFile, config, 0o600))

	// The gateway service is the only router, and it verifies client certificates
	// when a peer presents one: the same listener serves applications and the
	// internal face, which is what the advertised address promises.
	routing := fmt.Sprintf(`http:
  routers:
    app:
      rule: 'PathPrefix(`+"`/`"+`)'
      entryPoints: [websecure]
      service: checkout@gogw
      tls: {}
tls:
  certificates:
    - certFile: %q
      keyFile: %q
  options:
    default:
      clientAuth:
        caFiles: [%q]
        clientAuthType: VerifyClientCertIfGiven
`, in.cfg.CertFile, in.cfg.KeyFile, in.cfg.CAFile)
	routingFile := filepath.Join(dir, "routing.yaml")
	require.NoError(t, os.WriteFile(routingFile, []byte(routing), 0o600))

	install := fmt.Sprintf(`entryPoints:
  websecure:
    address: %q
    transport:
      lifeCycle:
        graceTimeOut: 2s
providers:
  file:
    watch: true
    filename: %q
log:
  level: ERROR
global:
  checkNewVersion: false
  sendAnonymousUsage: false
`, strings.TrimPrefix(in.server.URL, "https://"), routingFile)
	installFile := filepath.Join(dir, "traefik.yaml")
	require.NoError(t, os.WriteFile(installFile, []byte(install), 0o600))

	command := exec.Command(binary, "--configFile="+installFile)
	command.Env = append(os.Environ(), "GOGW_CONFIG="+configFile)
	output := new(bytes.Buffer)
	command.Stdout, command.Stderr = output, output
	require.NoError(t, command.Start())
	process := &gatewayProcess{command: command, output: output, exited: make(chan error, 1)}
	go func() { process.exited <- command.Wait() }()

	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-process.exited:
			process.exited <- err
		case <-time.After(processStopTimeout):
			_ = command.Process.Kill()
			<-process.exited
		}
		if t.Failed() {
			t.Logf("gateway process %d output:\n%s", index, output.String())
		}
	})
	return process
}
