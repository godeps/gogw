package gogw

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// errPeerCertificate rejects a peer that is not the advertised identity.
var errPeerCertificate = errors.New("gogw: peer certificate is not the advertised identity")

// parseMemberURL validates one candidate address and returns its canonical form.
func parseMemberURL(raw string) (string, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Host == "" || target.Scheme != "https" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return "", errors.New("gogw: candidate URL must be an https origin without credentials, query or fragment")
	}
	if target.Path != "" && target.Path != "/" {
		return "", errors.New("gogw: candidate URL must not contain a path")
	}
	return "https://" + target.Host, nil
}

const (
	// maxConnsPerMember bounds how many connections one candidate may receive.
	maxConnsPerMember = 128

	// idleConnTimeout releases unused member connections.
	idleConnTimeout = 90 * time.Second

	// responseHeaderTimeout bounds a peer that accepts a connection and stalls.
	responseHeaderTimeout = 30 * time.Second
)

// dialTimeout bounds connection establishment to one peer.
const dialTimeout = 10 * time.Second

// memberTransport builds the pinned mTLS transport used to reach one candidate.
// The peer certificate is pinned to the digests the approved discovery artifact
// advertises, so a compromised CA alone cannot redirect a forwarding ticket.
func memberTransport(caPool *x509.CertPool, id *identity, peer member) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxConnsPerMember,
		MaxIdleConnsPerHost:   maxConnsPerMember,
		MaxConnsPerHost:       maxConnsPerMember,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   dialTimeout,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    caPool,
			ServerName: peer.serverName,
			// The gateway certificate rotates, so the callback always presents the
			// current one instead of the one captured when the view was compiled.
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				pair := id.currentCertificate()
				return &pair.certificate, nil
			},
			VerifyPeerCertificate: pinnedVerifier(peer.digests),
		},
	}
}

// localTransport reaches the co-deployed application over loopback.
func localTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          maxConnsPerMember,
		MaxIdleConnsPerHost:   maxConnsPerMember,
		MaxConnsPerHost:       maxConnsPerMember,
		IdleConnTimeout:       idleConnTimeout,
		ExpectContinueTimeout: time.Second,
	}
}

// pinnedVerifier accepts only the exact advertised certificate digests.
func pinnedVerifier(digests []string) func([][]byte, [][]*x509.Certificate) error {
	allowed := append([]string(nil), digests...)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errPeerCertificate
		}
		if slices.Contains(allowed, hexDigest(digestOf(rawCerts[0]))) {
			return nil
		}
		return errPeerCertificate
	}
}

// memberURL validates and normalizes one advertised candidate address.
func memberURL(raw string) (*url.URL, error) {
	target, err := parseMemberURL(raw)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

// noReplay prevents the standard library from silently re-sending a write whose
// result is unknown, which would otherwise happen for a reused connection that
// fails before the response arrives.
type noReplay struct {
	next http.RoundTripper
}

func (n noReplay) RoundTrip(req *http.Request) (*http.Response, error) {
	if !idempotentMethod(req.Method) {
		req = req.Clone(req.Context())
		req.GetBody = nil
		if req.Body == nil {
			req.Body = http.NoBody
		}
	}
	return n.next.RoundTrip(req)
}

// idempotentMethod reports whether the standard library may re-send a request
// with this method after a connection level failure.
func idempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// replayable reports whether a failed attempt may be retried: the result must be
// knowably unknown (no response byte was received) and the request must be
// replayable at all.
func replayable(req *http.Request) bool {
	if !idempotentMethod(req.Method) {
		return false
	}
	// An empty body is replayable whatever wrapper carries it: HTTP/2 hands the
	// server a requestBody even for a GET that declared no content, so comparing
	// against http.NoBody alone would refuse to retry the commonest request there
	// is.
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0 {
		return true
	}
	// A body that carries bytes may only be replayed when it can be rewound.
	return req.GetBody != nil
}
