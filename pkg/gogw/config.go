// Package gogw integrates locally evaluated Grayling bundles with Traefik services.
package gogw

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/saker-ai/grayling/pkg/agent"
	"github.com/saker-ai/grayling/pkg/model"
)

// Config is deliberately separate from Traefik's install configuration schema.
type Config struct {
	HealthPath         string      `json:"healthPath,omitempty"`
	Service            string      `json:"service"`
	Scope              agent.Scope `json:"scope"`
	Instance           string      `json:"instance"`
	Boot               string      `json:"boot"`
	Build              string      `json:"build"`
	LocalURL           string      `json:"localURL"`
	GraylingURL        string      `json:"graylingURL"`
	TokenFile          string      `json:"tokenFile"`
	StateFile          string      `json:"stateFile"`
	CertFile           string      `json:"certFile"`
	KeyFile            string      `json:"keyFile"`
	CAFile             string      `json:"caFile"`
	PolicyKeyID        string      `json:"policyKeyID"`
	PolicyPublicKey    string      `json:"policyPublicKey"`
	IdentitySecretFile string      `json:"identitySecretFile"`
	IdentityIssuer     string      `json:"identityIssuer"`
	TrustedProxies     []string    `json:"trustedProxies,omitempty"`
}

// Bundle is the mock's versioned whole-view payload, not a Grayling production
// discovery or release schema. Prepared is mock evidence, not a registry label.
type Bundle struct {
	Schema               int            `json:"schema"`
	Generation           uint64         `json:"generation"`
	DiscoveryRevision    uint64         `json:"discoveryRevision"`
	DiscoveryExpiresUnix int64          `json:"discoveryExpiresUnix"`
	Flag                 string         `json:"flag"`
	Policy               model.Snapshot `json:"policy"`
	Endpoints            []Endpoint     `json:"endpoints"`
}

type Endpoint struct {
	Instance          string `json:"instance"`
	Boot              string `json:"boot"`
	Build             string `json:"build"`
	URL               string `json:"url"`
	ServerName        string `json:"serverName"`
	CertificateSHA256 string `json:"certificateSHA256"`
	Ready             bool   `json:"ready"`
	Draining          bool   `json:"draining"`
	Prepared          bool   `json:"prepared"`
	ExpiresUnix       int64  `json:"expiresUnix"`
}

func Load(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(b, &cfg, json.RejectUnknownMembers(true))
	return cfg, err
}

func endpointURL(raw string, local bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid endpoint URL")
	}
	if local {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("local application must use loopback HTTP")
		}
	} else if u.Scheme != "https" {
		return nil, errors.New("remote gateway must use HTTPS")
	}
	return u, nil
}

func roots(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid CA file")
	}
	return pool, nil
}

func New(cfg Config) (*Gateway, error) {
	if cfg.Service == "" || cfg.Scope.WorkspaceID == "" || cfg.Scope.EnvironmentID == "" || cfg.Scope.ServiceKey == "" || cfg.Instance == "" || cfg.Boot == "" || cfg.Build == "" || cfg.StateFile == "" || cfg.IdentityIssuer == "" {
		return nil, errors.New("incomplete gogw configuration")
	}
	if cfg.HealthPath == "" {
		cfg.HealthPath = "/health"
	}
	if cfg.HealthPath[0] != '/' {
		return nil, errors.New("healthPath must start with /")
	}
	local, err := endpointURL(cfg.LocalURL, true)
	if err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("gateway certificate must use Ed25519")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	pool, err := roots(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(cfg.PolicyPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid policy public key")
	}
	now := time.Now()
	verifier, err := agent.NewVerifier(map[string]agent.TrustKey{cfg.PolicyKeyID: {PublicKey: ed25519.PublicKey(pub), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}})
	if err != nil {
		return nil, err
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("gateway certificate expired")
	}
	secret, err := os.ReadFile(cfg.IdentitySecretFile)
	if err != nil {
		return nil, err
	}
	if len(secret) < 32 {
		return nil, errors.New("identity secret must contain at least 32 bytes")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{pair}}
	g := &Gateway{cfg: cfg, verifier: verifier, key: key, leaf: leaf, tls: tlsConfig, secret: secret, localURL: local}
	for _, cidr := range cfg.TrustedProxies {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		g.proxies = append(g.proxies, network)
	}
	g.control = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig.Clone()}, Timeout: 0}
	if err = g.restore(); err != nil {
		return nil, err
	}
	return g, nil
}
