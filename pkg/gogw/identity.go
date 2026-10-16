package gogw

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
)

// tlsCertificate is one loaded gateway certificate, key pair.
type tlsCertificate struct {
	certificate tls.Certificate
	leaf        *x509.Certificate
	key         ed25519.PrivateKey
}

func tlsCertificateOf(der []byte, key ed25519.PrivateKey) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: nil}
}

func digestOf(der []byte) [32]byte { return sha256.Sum256(der) }

func hexDigest(digest [32]byte) string { return hex.EncodeToString(digest[:]) }

// identity owns the gateway certificate used to sign forwarding tickets and the
// digest peers pin. Rotation keeps the previous digest verifiable until its
// overlap deadline so a rolling certificate change does not break forwarding.
type identity struct {
	certFile string
	keyFile  string
	overlap  time.Duration

	mu        sync.RWMutex
	current   tlsCertificate
	digest    [32]byte
	previous  [32]byte
	prevUntil time.Time
	watchKey  string
}

func newIdentity(certFile, keyFile string, overlap time.Duration, now time.Time) (*identity, error) {
	pair, err := loadCertificate(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if err := validCertificate(pair.leaf, now); err != nil {
		return nil, err
	}
	if len(pair.leaf.Raw) == 0 {
		return nil, errors.New("gogw: gateway certificate has no raw encoding")
	}
	id := &identity{certFile: certFile, keyFile: keyFile, overlap: overlap}
	id.current = pair
	id.digest = digestOf(pair.leaf.Raw)
	id.watchKey = fingerprintOf(pair)
	return id, nil
}

// fingerprintOf identifies a certificate, key pair by content, not by mtime.
func fingerprintOf(pair tlsCertificate) string {
	sum := sha256.Sum256(append(append([]byte{}, pair.leaf.Raw...), pair.key.Seed()...))
	return hex.EncodeToString(sum[:])
}

func (i *identity) currentCertificate() tlsCertificate {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.current
}

// advertisement reports the digests the control plane should publish for this
// instance: the current one and, during overlap, the previous one.
func (i *identity) advertisement(now time.Time) (current string, previous string, previousUntilMs int64) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	current = hexDigest(i.digest)
	if !i.prevUntil.IsZero() && now.Before(i.prevUntil) && i.previous != i.digest {
		return current, hexDigest(i.previous), i.prevUntil.UnixMilli()
	}
	return current, "", 0
}

func (i *identity) signer() ed25519.PrivateKey {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.current.key
}

// serverName is the name peers must use in the TLS handshake for this gateway.
func (i *identity) serverName() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if len(i.current.leaf.DNSNames) > 0 {
		return i.current.leaf.DNSNames[0]
	}
	if len(i.current.leaf.IPAddresses) > 0 {
		return i.current.leaf.IPAddresses[0].String()
	}
	return ""
}

// reload adopts a rotated certificate, pair. A failed reload keeps the previous
// identity: a partially written file must not take the gateway out of service.
func (i *identity) reload(now time.Time, rotate bool) error {
	pair, err := loadCertificate(i.certFile, i.keyFile)
	if err != nil {
		return err
	}
	if err := validCertificate(pair.leaf, now); err != nil {
		return err
	}
	fingerprint := fingerprintOf(pair)
	i.mu.Lock()
	defer i.mu.Unlock()
	if fingerprint == i.watchKey {
		return nil
	}
	next := digestOf(pair.leaf.Raw)
	if !rotate {
		// Adoption without rotation keeps the current digest authoritative: the
		// certificate is re-read, but no overlap window is announced.
		i.current, i.watchKey = pair, fingerprint
		return nil
	}
	if next != i.digest {
		i.previous = i.digest
		i.prevUntil = now.Add(i.overlap)
	}
	i.current, i.digest, i.watchKey = pair, next, fingerprint
	return nil
}

// watch polls the certificate files so a rotation is adopted without a restart.
func (i *identity) watch(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := i.reload(now, true); err != nil {
				log.Ctx(ctx).Warn().Err(err).Msg("Gateway certificate reload failed, keeping the current identity")
			}
		}
	}
}

// trustKeys builds the verifier key set. Explicit windows win; otherwise the
// window is bounded by the gateway certificate validity, which only rotates in
// lockstep with the signing key.
func trustKeysOf(cfg Config, leafNotBefore, leafNotAfter time.Time) (map[string]agent.TrustKey, error) {
	configured, err := cfg.trustKeys()
	if err != nil {
		return nil, err
	}
	keys := make(map[string]agent.TrustKey, len(configured))
	for keyID, key := range configured {
		public, err := decodePublicKey(key.PublicKey)
		if err != nil {
			return nil, err
		}
		window := agent.TrustKey{PublicKey: public}
		if key.NotBeforeUnixMs != 0 || key.NotAfterUnixMs != 0 {
			window.NotBefore = time.UnixMilli(key.NotBeforeUnixMs)
			window.NotAfter = time.UnixMilli(key.NotAfterUnixMs)
		} else {
			window.NotBefore = leafNotBefore
			window.NotAfter = leafNotAfter
		}
		keys[keyID] = window
	}
	return keys, nil
}

// verifier wraps the SDK resource verifier with the monotone watermark rules.
type verifier struct {
	inner *agent.Verifier
}

func newVerifier(cfg Config, leafNotBefore, leafNotAfter time.Time) (*verifier, error) {
	keys, err := trustKeysOf(cfg, leafNotBefore, leafNotAfter)
	if err != nil {
		return nil, err
	}
	inner, err := agent.NewVerifier(keys)
	if err != nil {
		return nil, err
	}
	return &verifier{inner: inner}, nil
}

// verify checks one signed resource against the expected scope, kind and key and
// against the persisted watermark, which is what stops a replay of an older,
// still validly signed resource.
func (v *verifier) verify(resource *agentv1.SignedResource, scope agent.Scope, kind agentv1.ResourceKind, key string, mark agent.Watermark, now time.Time) (agent.Claims, error) {
	if resource == nil {
		return agent.Claims{}, errors.New("gogw: missing signed resource")
	}
	claims, err := v.inner.Verify(resource, scope, kind, key, mark, now)
	if err != nil {
		return agent.Claims{}, err
	}
	return claims, nil
}
