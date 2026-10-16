package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
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
	bundlePath := flag.String("bundle", "", "bundle JSON file; SIGHUP reloads it")
	workspace := flag.String("workspace", "demo", "workspace ID")
	environment := flag.String("environment", "test", "environment ID")
	service := flag.String("service", "checkout", "service key and runtime name")
	keyID := flag.String("key-id", "mock", "resource signing key ID")
	flag.Parse()
	b, err := os.ReadFile(*signing)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("signing key must be a hex Ed25519 seed")
	}
	secret, err := os.ReadFile(*token)
	if err != nil {
		return err
	}
	control := &mock.Server{Scope: agent.Scope{WorkspaceID: *workspace, EnvironmentID: *environment, ServiceKey: *service}, Service: *service, Token: strings.TrimSpace(string(secret)), KeyID: *keyID, PrivateKey: ed25519.NewKeyFromSeed(seed)}
	load := func() error {
		data, err := os.ReadFile(*bundlePath)
		if err != nil {
			return err
		}
		var b gogw.Bundle
		if err = json.Unmarshal(data, &b, json.RejectUnknownMembers(true)); err != nil {
			return err
		}
		return control.Publish(b)
	}
	if err = load(); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	srv := &http.Server{Addr: *address, Handler: control, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServeTLS(*cert, *key) }()
	defer control.Close()
	for {
		select {
		case <-ctx.Done():
			budget, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			return srv.Shutdown(budget)
		case err := <-done:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-reload:
			if err = load(); err != nil {
				log.Error().Err(err).Msg("Rejected mock bundle reload")
			}
		}
	}
}
