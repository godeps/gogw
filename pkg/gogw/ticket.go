package gogw

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"
)

const (
	// ticketHeader carries the signed forwarding ticket between gateways.
	ticketHeader = "X-Gogw-Ticket"

	// ticketTTL bounds how long a forwarded request may be replayed.
	ticketTTL = 15 * time.Second

	// ticketLeeway absorbs clock skew between gateway processes.
	ticketLeeway = 2 * time.Second

	// maxTicketBytes bounds an inbound ticket before it is parsed.
	maxTicketBytes = 4096

	// ticketType is the JOSE type of a final forwarding ticket.
	ticketType = "gogw-final+jwt"
)

var errTicket = errors.New("gogw: invalid forwarding ticket")

// ticketClaims binds one forwarded request to exactly one target, one release
// and one hop. Every field is checked by the receiver: a ticket is the only
// thing that lets a request cross the gateway identity boundary.
type ticketClaims struct {
	Issuer      string `json:"iss"`
	IssuerBoot  string `json:"iboot"`
	Subject     string `json:"sub"`
	SubjectBoot string `json:"sboot"`
	Build       string `json:"bld"`
	Bundle      string `json:"bnd"`
	Generation  uint64 `json:"gen"`
	Method      string `json:"m"`
	Authority   string `json:"aud"`
	URI         string `json:"uri"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	Final       bool   `json:"fin"`
	Hop         int    `json:"hop"`
	Principal   string `json:"prn"`
	Tenant      string `json:"tnt"`
	DecisionID  string `json:"dec,omitempty"`
}

type ticketHeaderJSON struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

// ticketVerifier carries the signed bytes of one ticket so the receiver can
// check the signature with the public key of the certificate the control plane
// advertised for the issuer. That avoids any second key distribution channel.
type ticketVerifier struct {
	signing   []byte
	signature []byte
}

func (v ticketVerifier) verify(public ed25519.PublicKey) bool {
	return len(public) == ed25519.PublicKeySize && ed25519.Verify(public, v.signing, v.signature)
}

// signTicket produces one final, single hop ticket for an exact request.
func signTicket(key ed25519.PrivateKey, claims ticketClaims) (string, error) {
	header, err := json.Marshal(ticketHeaderJSON{Algorithm: "EdDSA", Type: ticketType})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	signature := ed25519.Sign(key, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// decodeTicket validates the structure and header of one ticket. The signature is
// returned unchecked because the verification key is the issuer certificate,
// which the caller resolves from the approved discovery artifact.
func decodeTicket(token string) (ticketClaims, ticketVerifier, error) {
	var claims ticketClaims
	var verifier ticketVerifier
	if len(token) == 0 || len(token) > maxTicketBytes {
		return claims, verifier, errTicket
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, verifier, errTicket
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return claims, verifier, errTicket
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, verifier, errTicket
	}
	var meta ticketHeaderJSON
	if err := json.Unmarshal(header, &meta); err != nil || meta.Algorithm != "EdDSA" || meta.Type != ticketType {
		return claims, verifier, errTicket
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, verifier, errTicket
	}
	if err := json.Unmarshal(body, &claims, json.RejectUnknownMembers(true)); err != nil {
		return claims, verifier, errTicket
	}
	if !claims.Final || claims.Hop != 1 {
		return claims, verifier, errTicket
	}
	verifier.signing = []byte(parts[0] + "." + parts[1])
	verifier.signature = signature
	return claims, verifier, nil
}

// peerDigest returns the SHA-256 digest of the presented client certificate.
func peerDigest(state *tls.ConnectionState) (string, bool) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return "", false
	}
	return hexDigest(sha256.Sum256(state.PeerCertificates[0].Raw)), true
}

// peerKey returns the Ed25519 public key of the presented client certificate.
func peerKey(state *tls.ConnectionState) (ed25519.PublicKey, bool) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, false
	}
	public, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	return public, ok
}
