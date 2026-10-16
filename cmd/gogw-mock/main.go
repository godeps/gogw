package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/saker-ai/grayling/pkg/agent"
	"github.com/traefik/traefik/v3/pkg/gogw"
	"github.com/traefik/traefik/v3/pkg/gogw/mock"
)

const (
	// discoveryInterval is how often the membership of the current release is
	// republished. It is short on purpose: an acceptance run must observe a
	// registration in discovery without waiting for a production refresh period.
	discoveryInterval = time.Second

	// shutdownBudget bounds how long an open session may hold up the exit.
	shutdownBudget = 5 * time.Second
)

func main() {
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("Mock Grayling failed")
	}
}

func run() error {
	address := flag.String("address", "127.0.0.1:9443", "HTTPS listener")
	cert := flag.String("cert", "", "TLS certificate PEM")
	key := flag.String("key", "", "TLS private key PEM")
	signing := flag.String("signing-key", "", "file containing hex Ed25519 signing seed")
	token := flag.String("token-file", "", "Agent token file")
	releasePath := flag.String("release", "", "release JSON file; SIGHUP reloads it")
	workspace := flag.String("workspace", "demo", "workspace ID")
	environment := flag.String("environment", "test", "environment ID")
	service := flag.String("service", "checkout", "service key and runtime name")
	keyID := flag.String("key-id", "mock", "resource signing key ID")
	flag.Parse()
	if *releasePath == "" {
		return errors.New("mock: -release is required")
	}
	seed, err := readHexSeed(*signing)
	if err != nil {
		return err
	}
	secret, err := os.ReadFile(*token)
	if err != nil {
		return err
	}
	control, err := mock.New(mock.Options{
		Scope:      agent.Scope{WorkspaceID: *workspace, EnvironmentID: *environment, ServiceKey: *service},
		Token:      strings.TrimSpace(string(secret)),
		KeyID:      *keyID,
		SigningKey: ed25519.NewKeyFromSeed(seed),
	})
	if err != nil {
		return err
	}
	// The listener address is the origin the gateway reaches the mock on, so
	// every download reference is stamped with the same host it connected to.
	control.SetOrigin("https://" + *address)
	defer control.Close()
	pub := &publisher{server: control, path: *releasePath}
	if err := pub.load(); err != nil {
		return err
	}
	srv := &http.Server{Addr: *address, Handler: control.Handler(), ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServeTLS(*cert, *key) }()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	log.Info().Str("address", *address).Str("release", pub.releaseID).Uint64("generation", pub.generation).Msg("Mock Grayling listening")
	ticker := time.NewTicker(discoveryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Sessions are terminated before the listener stops, because a
			// WebSocket handler cannot be shut down gracefully without being
			// asked to end first.
			control.Close()
			budget, stop := context.WithTimeout(context.WithoutCancel(ctx), shutdownBudget)
			defer stop()
			return srv.Shutdown(budget)
		case err := <-done:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-reload:
			if err := pub.load(); err != nil {
				log.Error().Err(err).Msg("Rejected mock release reload")
				continue
			}
			log.Info().Str("release", pub.releaseID).Uint64("generation", pub.generation).Msg("Reloaded mock release")
		case <-ticker.C:
			if err := pub.publishDiscovery(); err != nil {
				log.Error().Err(err).Msg("Failed to publish mock discovery")
			}
		}
	}
}

// publisher owns the state a reload replaces: the release that is published, the
// membership overrides the file supplies and the revisions the mock has reached.
// It runs on the process's control goroutine only, so it needs no lock.
type publisher struct {
	server *mock.Server
	path   string

	releaseID    string
	generation   uint64
	bundle       mock.Resource
	overrides    []gogw.Member
	discoveryTTL time.Duration
	revocation   uint64

	// discovery counts every membership publication of this process, so the
	// revision of the artifact never regresses even across a release reload.
	discovery uint64
}

// load reads the release file and publishes what it describes. Both the release
// generation and the revocation epoch must advance, because a subscriber refuses
// a regression and a reload that was silently dropped would leave the run
// verifying a state that was never published.
func (p *publisher) load() error {
	file, err := mock.LoadReleaseFile(p.path)
	if err != nil {
		return err
	}
	if file.Release.Generation <= p.generation {
		return fmt.Errorf("mock: release generation %d does not advance %d", file.Release.Generation, p.generation)
	}
	epoch := uint64(0)
	if file.Revocation != nil {
		epoch = file.Revocation.Epoch
		if epoch <= p.revocation {
			return fmt.Errorf("mock: revocation epoch %d does not advance %d", epoch, p.revocation)
		}
	}
	if file.Revocation != nil {
		hashes, err := file.Revocation.BundleDigests()
		if err != nil {
			return err
		}
		if _, err := p.server.PublishRevocation(epoch, 0, file.Revocation.CancelActiveStreams, hashes...); err != nil {
			return err
		}
		p.revocation = epoch
	}
	bundle, err := p.server.PublishBundle(file.Release)
	if err != nil {
		return err
	}
	p.releaseID = file.Release.ReleaseID
	p.generation = file.Release.Generation
	p.bundle = bundle
	p.overrides = file.Members
	p.discoveryTTL = time.Duration(file.Release.DiscoveryMaxAgeSeconds) * time.Second
	return nil
}

// publishDiscovery republishes the membership of the current release for every
// instance the mock has registered, with the file's endpoints overriding the
// addresses the mock synthesized from a registration.
func (p *publisher) publishDiscovery() error {
	if p.bundle.Key == "" {
		return nil
	}
	members := mock.OverlayMembers(p.server.Members(p.bundle.Hash), p.overrides)
	p.discovery++
	_, err := p.server.PublishDiscovery(p.bundle.Hash, p.discovery, p.discoveryTTL, members)
	return err
}

// readHexSeed reads the Ed25519 signing seed the mock signs resources with.
func readHexSeed(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing key must be a hex Ed25519 seed")
	}
	return seed, nil
}
