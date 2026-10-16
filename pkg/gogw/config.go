package gogw

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
)

const (
	// defaultHealthPath is probed when the configuration omits one.
	defaultHealthPath = "/health"

	// defaultPreparedTTLSeconds bounds how long the control plane may advertise
	// this instance as a prepared candidate.
	defaultPreparedTTLSeconds = 300

	// defaultDrainGraceSeconds bounds how long an existing stream may outlive the
	// start of draining before it is closed.
	defaultDrainGraceSeconds = 120

	// defaultCertificateOverlapSeconds keeps the previous gateway certificate
	// digest verifiable while peers adopt the rotated one.
	defaultCertificateOverlapSeconds = 300

	// defaultSessionCompatibilitySeconds keeps a session on the release it was
	// admitted to after a new release is activated.
	defaultSessionCompatibilitySeconds = 300

	defaultMaxTrackedSessions = 65536
	defaultMaxRetainedViews   = 4
)

// TrustKey is one accepted resource signing key. Windows are independent per key
// so an overlap rotation can trust two keys at once.
type TrustKey struct {
	KeyID           string `json:"keyId"`
	PublicKey       string `json:"publicKey"`
	NotBeforeUnixMs int64  `json:"notBeforeUnixMs,omitempty"`
	NotAfterUnixMs  int64  `json:"notAfterUnixMs,omitempty"`
}

// Config is the fork-specific configuration read from the GOGW_CONFIG file.
type Config struct {
	HealthPath         string      `json:"healthPath"`
	Service            string      `json:"service"`
	Scope              agent.Scope `json:"scope"`
	Instance           string      `json:"instance"`
	Boot               string      `json:"boot"`
	Build              string      `json:"build"`
	LocalURL           string      `json:"localURL"`
	GraylingURL        string      `json:"graylingURL"`
	TokenFile          string      `json:"tokenFile"`
	StateFile          string      `json:"stateFile"`
	AdvertiseAddress   string      `json:"advertiseAddress"`
	AdvertisePort      int         `json:"advertisePort"`
	Zone               string      `json:"zone,omitempty"`
	ImageDigest        string      `json:"imageDigest,omitempty"`
	CertFile           string      `json:"certFile"`
	KeyFile            string      `json:"keyFile"`
	CAFile             string      `json:"caFile"`
	PolicyKeyID        string      `json:"policyKeyID"`
	PolicyPublicKey    string      `json:"policyPublicKey"`
	PolicyKeys         []TrustKey  `json:"policyKeys,omitempty"`
	IdentitySecretFile string      `json:"identitySecretFile"`
	IdentityIssuer     string      `json:"identityIssuer"`
	TrustedProxies     []string    `json:"trustedProxies,omitempty"`

	PreparedTTLSeconds          int64 `json:"preparedTTLSeconds,omitempty"`
	DrainGraceSeconds           int64 `json:"drainGraceSeconds,omitempty"`
	CertificateOverlapSeconds   int64 `json:"certificateOverlapSeconds,omitempty"`
	SessionCompatibilitySeconds int64 `json:"sessionCompatibilitySeconds,omitempty"`
	MaxTrackedSessions          int   `json:"maxTrackedSessions,omitempty"`
	MaxRetainedViews            int   `json:"maxRetainedViews,omitempty"`
}

// Load reads and validates the gateway configuration file.
func Load(path string) (Config, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg, json.RejectUnknownMembers(true)); err != nil {
		return cfg, fmt.Errorf("gogw: invalid configuration: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.HealthPath == "" {
		c.HealthPath = defaultHealthPath
	}
	if c.PreparedTTLSeconds <= 0 {
		c.PreparedTTLSeconds = defaultPreparedTTLSeconds
	}
	if c.DrainGraceSeconds <= 0 {
		c.DrainGraceSeconds = defaultDrainGraceSeconds
	}
	if c.CertificateOverlapSeconds <= 0 {
		c.CertificateOverlapSeconds = defaultCertificateOverlapSeconds
	}
	if c.SessionCompatibilitySeconds <= 0 {
		c.SessionCompatibilitySeconds = defaultSessionCompatibilitySeconds
	}
	if c.MaxTrackedSessions <= 0 {
		c.MaxTrackedSessions = defaultMaxTrackedSessions
	}
	if c.MaxRetainedViews <= 0 {
		c.MaxRetainedViews = defaultMaxRetainedViews
	}
}

func (c *Config) validate() error {
	required := map[string]string{
		"service": c.Service, "instance": c.Instance, "boot": c.Boot, "build": c.Build,
		"localURL": c.LocalURL, "graylingURL": c.GraylingURL, "tokenFile": c.TokenFile,
		"stateFile": c.StateFile, "certFile": c.CertFile, "keyFile": c.KeyFile, "caFile": c.CAFile,
		"identitySecretFile": c.IdentitySecretFile, "identityIssuer": c.IdentityIssuer,
		"advertiseAddress": c.AdvertiseAddress,
	}
	for name, value := range required {
		if value == "" {
			return fmt.Errorf("gogw: missing %s", name)
		}
	}
	if _, err := c.advertise(); err != nil {
		return err
	}
	if c.Zone != "" && !validIdentifier(c.Zone, maxIdentifier) {
		return errors.New("gogw: invalid zone")
	}
	if c.ImageDigest != "" && !validDigest(c.ImageDigest) {
		return errors.New("gogw: imageDigest must be a lowercase hexadecimal sha256 digest")
	}
	for name, value := range map[string]string{
		"workspaceID": c.Scope.WorkspaceID, "environmentID": c.Scope.EnvironmentID, "serviceKey": c.Scope.ServiceKey,
	} {
		if value == "" {
			return fmt.Errorf("gogw: missing scope %s", name)
		}
	}
	if _, err := localEndpoint(c.LocalURL); err != nil {
		return err
	}
	origin, err := url.Parse(c.GraylingURL)
	if err != nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.Scheme != "wss" {
		return errors.New("gogw: graylingURL must be a wss origin without credentials, query or fragment")
	}
	// The SDK appends the connect path itself and refuses any other one.
	if origin.Path != "" && origin.Path != "/" && origin.Path != agentv1.ConnectPath {
		return errors.New("gogw: graylingURL must not contain a path other than the connect path")
	}
	for name, value := range map[string]string{
		"service": c.Service, "instance": c.Instance, "boot": c.Boot, "build": c.Build,
	} {
		if !validIdentifier(value, maxRegistrationIdentifier) {
			return fmt.Errorf("gogw: invalid %s", name)
		}
	}
	if c.AdvertisePort < 1 || c.AdvertisePort > 65535 {
		return errors.New("gogw: advertisePort must be between 1 and 65535")
	}
	if _, err := c.trustKeys(); err != nil {
		return err
	}
	for _, proxy := range c.TrustedProxies {
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			if net.ParseIP(proxy) == nil {
				return fmt.Errorf("gogw: invalid trusted proxy %q", proxy)
			}
		}
	}
	return nil
}

// trustKeys resolves the accepted signing keys. The legacy single-key form keeps
// its window bounded by the gateway certificate, which is only safe while the
// certificate and the signing key rotate together.
func (c *Config) trustKeys() (map[string]TrustKey, error) {
	if len(c.PolicyKeys) > 0 {
		keys := make(map[string]TrustKey, len(c.PolicyKeys))
		for _, key := range c.PolicyKeys {
			if key.KeyID == "" {
				return nil, errors.New("gogw: policy key without keyId")
			}
			if _, ok := keys[key.KeyID]; ok {
				return nil, fmt.Errorf("gogw: duplicate policy key %q", key.KeyID)
			}
			public, err := decodePublicKey(key.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("gogw: policy key %q: %w", key.KeyID, err)
			}
			_ = public
			keys[key.KeyID] = key
		}
		return keys, nil
	}
	if c.PolicyKeyID == "" || c.PolicyPublicKey == "" {
		return nil, errors.New("gogw: missing policy signing key")
	}
	if _, err := decodePublicKey(c.PolicyPublicKey); err != nil {
		return nil, fmt.Errorf("gogw: policy public key: %w", err)
	}
	return map[string]TrustKey{c.PolicyKeyID: {KeyID: c.PolicyKeyID, PublicKey: c.PolicyPublicKey}}, nil
}

// maxRegistrationIdentifier bounds every identifier sent in a Hello, Register or
// release report: the frozen protocol rejects a longer one at validation.
const maxRegistrationIdentifier = 128

// advertise renders the address peers and the control plane must dial for this
// gateway. The scheme is fixed by the mTLS peer transport.
func (c *Config) advertise() (string, error) {
	if c.AdvertisePort < 1 || c.AdvertisePort > 65535 {
		return "", errors.New("gogw: advertisePort must be between 1 and 65535")
	}
	address := c.AdvertiseAddress
	if strings.ContainsAny(address, "/\\?#@ \t\r\n") {
		return "", errors.New("gogw: advertiseAddress must be a host without scheme, path or credentials")
	}
	if ip := net.ParseIP(address); ip != nil {
		return "https://" + net.JoinHostPort(ip.String(), strconv.Itoa(c.AdvertisePort)), nil
	}
	if strings.Contains(address, ":") {
		return "", errors.New("gogw: advertiseAddress must be an IPv4 address, an IPv6 address without brackets, or a hostname")
	}
	for label := range strings.SplitSeq(address, ".") {
		if label == "" || len(label) > 63 {
			return "", errors.New("gogw: invalid advertiseAddress")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return "", errors.New("gogw: invalid advertiseAddress")
			}
		}
	}
	return "https://" + net.JoinHostPort(address, strconv.Itoa(c.AdvertisePort)), nil
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("expected a hex encoded Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// localEndpoint validates the loopback application address.
func localEndpoint(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Host == "" || target.Scheme != "http" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return nil, errors.New("gogw: localURL must be an http URL without credentials, query or fragment")
	}
	if target.Path != "" && target.Path != "/" {
		return nil, errors.New("gogw: localURL must not contain a path")
	}
	host, _, err := net.SplitHostPort(target.Host)
	if err != nil {
		return nil, errors.New("gogw: localURL must contain a port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("gogw: localURL must use an explicit loopback address")
	}
	return target, nil
}

// roots loads the certificate authority pool used for the control plane and for
// peer gateway verification.
func roots(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("gogw: no certificate authority found")
	}
	return pool, nil
}

// loadCertificate reads one Ed25519 certificate and key pair.
func loadCertificate(certFile, keyFile string) (tlsCertificate, error) {
	var pair tlsCertificate
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return pair, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return pair, errors.New("gogw: certFile must contain a PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return pair, fmt.Errorf("gogw: parsing gateway certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return pair, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return pair, errors.New("gogw: keyFile must contain a PEM private key")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return pair, err
	}
	pair.leaf = leaf
	pair.key = key
	pair.certificate = tlsCertificateOf(block.Bytes, key)
	return pair, nil
}

func parsePrivateKey(der []byte) (ed25519.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("gogw: parsing gateway key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("gogw: gateway key must be Ed25519")
	}
	return key, nil
}

// validCertificate requires a currently valid Ed25519 leaf certificate.
func validCertificate(leaf *x509.Certificate, now time.Time) error {
	if leaf.PublicKeyAlgorithm != x509.Ed25519 {
		return errors.New("gogw: gateway certificate must use Ed25519")
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return errors.New("gogw: gateway certificate is not currently valid")
	}
	return nil
}
