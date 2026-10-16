package gogw

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/rs/zerolog/log"
	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
)

// Run owns the SDK lifecycle and cleans up all proxy pools on shutdown.
func (g *Gateway) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	g.checkHealth(ctx)
	var probes sync.WaitGroup
	probes.Go(func() { g.probe(ctx) })
	defer func() { cancel(); probes.Wait() }()
	defer func() {
		g.Drain()
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.active != nil {
			g.active.retire()
		}
		if g.candidate != nil {
			g.candidate.retire()
		}
		g.control.CloseIdleConnections()
	}()
	err := agent.Run(ctx, func(context.Context) (agent.Options, error) {
		token, err := os.ReadFile(g.cfg.TokenFile)
		if err != nil {
			return agent.Options{}, err
		}
		return agent.Options{URL: g.cfg.GraylingURL, Token: strings.TrimSpace(string(token)), HTTPClient: g.control, Hello: &agentv1.Hello{AgentId: g.cfg.Instance, InstanceId: g.cfg.Instance, BootId: g.cfg.Boot}}, nil
	}, func(client *agent.Client) error {
		welcome := client.Welcome().GetWelcome()
		if welcome.GetScope().GetWorkspaceId() != g.cfg.Scope.WorkspaceID || welcome.GetScope().GetEnvironmentId() != g.cfg.Scope.EnvironmentID || welcome.GetScope().GetServiceKey() != g.cfg.Scope.ServiceKey {
			return errors.New("control-plane scope mismatch")
		}
		if err := client.Subscribe(ctx, "runtime", &agentv1.Cursor{Kind: agentv1.ResourceKind_RESOURCE_KIND_BUNDLE, Key: g.cfg.Service}); err != nil {
			return err
		}
		var resource *agentv1.SignedResource
		for event := range client.Events() {
			switch {
			case event.GetSnapshot() != nil:
				snapshot := event.GetSnapshot()
				resource = snapshot.GetInlineResource()
				if resource == nil {
					return errors.New("mock bundle must be inline")
				}
				v, err := g.prepare(resource)
				if err != nil {
					log.Ctx(ctx).Error().Err(err).Msg("Rejected gogw runtime view")
					if err = client.SendMessage(ctx, &agentv1.ResourceRejected{Revision: snapshot.GetRevision(), Error: &agentv1.Error{Code: agentv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Reason: "runtime view rejected"}}, agent.Metadata{OperationID: uuid.New().String()}); err != nil {
						return err
					}
					continue
				}
				if err = client.SendMessage(ctx, &agentv1.Prepared{Release: &agentv1.ReleaseIdentity{ReleaseId: g.cfg.Service, Generation: v.bundle.Generation, BundleHash: v.hash}, InstanceId: g.cfg.Instance, BootId: g.cfg.Boot, BuildId: g.cfg.Build, AcceptedProtocolVersion: 1, PreparedUnixMs: time.Now().UnixMilli(), ExpiresUnixMs: v.claims.ExpiresUnixMs}, agent.Metadata{OperationID: uuid.New().String()}); err != nil {
					return err
				}
			case event.GetActivate() != nil:
				identity := event.GetActivate().GetRelease()
				if err := g.activate(identity); err != nil {
					log.Ctx(ctx).Error().Err(err).Msg("Rejected gogw activation")
					continue
				}
				log.Ctx(ctx).Info().Uint64("generation", identity.GetGeneration()).Str("bundleHash", identity.GetBundleHash()).Msg("Activated gogw runtime view")
				v := g.capture()
				applied := &agentv1.Applied{Release: identity, InstanceId: g.cfg.Instance, BootId: g.cfg.Boot, PolicyRevision: v.claims.Revision, DiscoveryRevision: v.bundle.DiscoveryRevision}
				v.release()
				if err := client.SendMessage(ctx, applied, agent.Metadata{OperationID: uuid.New().String()}); err != nil {
					return err
				}
			case event.GetDrainRequested() != nil:
				g.Drain()
			case event.GetRevoke() != nil:
				// Fail closed for this mock's single active bundle. A later production
				// adapter must persist revocation epochs and independently govern old flows.
				g.Drain()
			}
		}
		return client.Err()
	})
	if err != nil && ctx.Err() == nil {
		log.Ctx(ctx).Error().Err(err).Msg("Grayling Agent stopped")
	}
}

func (g *Gateway) checkHealth(ctx context.Context) {
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	target := g.localURL.Clone()
	target.Path = g.cfg.HealthPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		g.health.Store(false)
		return
	}
	response, err := client.Do(req)
	healthy := err == nil && response.StatusCode >= 200 && response.StatusCode < 300
	if response != nil {
		_ = response.Body.Close()
	}
	g.health.Store(healthy)
}

func (g *Gateway) probe(ctx context.Context) {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			g.health.Store(false)
			return
		case <-timer.C:
			g.checkHealth(ctx)
		}
	}
}
