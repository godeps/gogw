package gogw

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	proxy "github.com/traefik/traefik/v3/pkg/proxy/httputil"
)

type transport struct {
	rt     *http.Transport
	config *tls.Config
}

func (t transport) Get(string) (*dynamic.ServersTransport, error) {
	return &dynamic.ServersTransport{}, nil
}

func (t transport) GetRoundTripper(string) (http.RoundTripper, error) {
	if t.rt == nil {
		return nil, errors.New("missing transport")
	}
	return noReplay{RoundTripper: t.rt}, nil
}
func (t transport) GetTLSConfig(string) (*tls.Config, error) { return t.config, nil }

// Each view owns its pools, so an address reused by another boot cannot inherit
// authenticated connections. Retired views close idle pools after their last stream.
func newProxy(target *url.URL, config *tls.Config) (http.Handler, *http.Transport, error) {
	rt := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: config, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 64, MaxIdleConnsPerHost: 16, MaxConnsPerHost: 128, ForceAttemptHTTP2: true}
	h, err := proxy.NewProxyBuilder(transport{rt: rt, config: config}, nil).Build("gogw", target, true, false, -time.Millisecond)
	if err != nil {
		rt.CloseIdleConnections()
		return nil, nil, err
	}
	return h, rt, nil
}

// noReplay prevents net/http from treating empty writes carrying an idempotency
// key as automatically replayable. Business idempotency remains the app's job.
type noReplay struct{ http.RoundTripper }

func (t noReplay) RoundTrip(r *http.Request) (*http.Response, error) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		r = r.Clone(r.Context())
		r.GetBody = nil
		if r.Body == nil || r.Body == http.NoBody {
			r.Body = io.NopCloser(strings.NewReader(""))
		}
	}
	return t.RoundTripper.RoundTrip(r)
}
