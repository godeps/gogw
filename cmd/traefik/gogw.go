package main

import (
	"context"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/gogw"
	"github.com/traefik/traefik/v3/pkg/safe"
	"github.com/traefik/traefik/v3/pkg/server/service"
)

// GOGW_CONFIG keeps fork-specific options outside Traefik's generated schemas.
func configureGogw(factory *service.ManagerFactory, pool *safe.Pool) (func(), error) {
	path := os.Getenv("GOGW_CONFIG")
	if path == "" {
		return nil, nil
	}
	cfg, err := gogw.Load(path)
	if err != nil {
		return nil, err
	}
	gateway, err := gogw.New(cfg)
	if err != nil {
		return nil, err
	}
	factory.AddServiceBuilder(gateway)
	pool.GoCtx(func(ctx context.Context) { log.Ctx(ctx).Info().Msg("Starting Grayling Agent"); gateway.Run(ctx) })
	return gateway.Drain, nil
}
