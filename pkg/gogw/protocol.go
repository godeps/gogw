package gogw

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/saker-ai/grayling/pkg/agent"
	"github.com/saker-ai/grayling/pkg/bucketing"
	"github.com/saker-ai/grayling/pkg/model"
)

// The pinned Grayling SDK freezes the session, command and signed-resource
// envelope, but leaves the payload of the DISCOVERY, BUNDLE and REVOCATION
// resource kinds to the control plane. This file is the fork's versioned
// extension for those payloads: every document carries an explicit schema
// number, unknown members are rejected, and the gateway refuses a document it
// cannot fully verify. A control plane must serve these exact shapes for the
// negotiation to succeed; that contract is documented in
// docs/content/contributing/gogw.md and is not a claim about any existing
// production deployment.
const (
	// payloadSchema is the only payload schema this gateway verifies.
	payloadSchema = 1

	maxDocumentBytes  = 2 << 20
	maxMembers        = 1024
	maxRevokedBundles = 4096
	maxIdentifier     = 256

	// defaultPolicyMaxAgeSeconds and defaultDiscoveryMaxAgeSeconds are the
	// validity windows a release document may omit. They are deliberately short:
	// an omitted window must never extend how long an unreviewed artifact stays
	// in service, and maxArtifactAgeSeconds bounds what a document may claim.
	defaultPolicyMaxAgeSeconds    = 300
	defaultDiscoveryMaxAgeSeconds = 300
	maxArtifactAgeSeconds         = 24 * 60 * 60
)

var errDocument = errors.New("invalid gogw resource payload")

// BundleKey is the resource key convention for a release bundle. The bundle is
// self-addressed by its payload digest, which is the release identity the
// control plane signs into every related resource. The digest of the serialized
// SignedResource is a separate value: it is what a ResourceRef carries for
// download verification, and the two must never be conflated.
func BundleKey(hash [32]byte) string { return "bundle/" + hex.EncodeToString(hash[:]) }

// DiscoveryKey returns the resource key of the membership artifact bound to one
// accepted bundle. Membership is per-bundle by contract: a member listed here
// has accepted exactly the bundle whose hash is part of the key.
func DiscoveryKey(hash [32]byte) string { return "discovery/" + hex.EncodeToString(hash[:]) }

// RevocationKey is the resource key of the service-scoped revocation document.
const RevocationKey = "revocation"

// BuildDescriptor describes one logical build of a release. Instance addresses
// and counts deliberately do not appear here: neither is a bucketing input.
type BuildDescriptor struct {
	ImageDigest string `json:"imageDigest,omitempty"`
}

// Ramp is the monotone eligibility prefix of one release ramp. The published
// SDK states that a variant split is not stable across ratio changes, while an
// eligibility prefix interval is: a unit inside the prefix stays inside it when
// the threshold grows. The gateway therefore evaluates the approved policy for
// the allocation itself and uses this prefix only as an additional gate, so a
// ratio change can never pull an already-canary unit back to the default build.
type Ramp struct {
	Key         string `json:"key"`
	Epoch       int64  `json:"epoch"`
	Salt        string `json:"salt"`
	Unit        string `json:"unit"`
	Threshold   int    `json:"threshold"`
	CanaryBuild string `json:"canaryBuild"`
}

// BundleDocument is the verified payload of one immutable release bundle. It
// contains policy and build mapping only; membership always arrives through the
// DISCOVERY subscription so that scaling never rewrites an approved policy.
type BundleDocument struct {
	Schema                 int                        `json:"schema"`
	ReleaseID              string                     `json:"releaseId"`
	Generation             uint64                     `json:"generation"`
	Flag                   string                     `json:"flag"`
	DefaultBuild           string                     `json:"defaultBuild"`
	Builds                 map[string]BuildDescriptor `json:"builds"`
	Ramp                   *Ramp                      `json:"ramp,omitempty"`
	Policy                 model.Snapshot             `json:"policy"`
	MinimumProtocolVersion uint32                     `json:"minimumProtocolVersion"`
	DiscoveryMaxAgeSeconds int64                      `json:"discoveryMaxAgeSeconds"`
	PolicyMaxAgeSeconds    int64                      `json:"policyMaxAgeSeconds"`
}

// PreparedEvidence is the control plane's record that one instance accepted one
// bundle. It is a candidate filter, never an authorization: the target gateway
// still validates the presented ticket against its own build, boot and bundle.
type PreparedEvidence struct {
	BundleHash       string `json:"bundleHash"`
	Generation       uint64 `json:"generation"`
	PreparedRevision uint64 `json:"preparedRevision"`
	ExpiresUnixMs    int64  `json:"expiresUnixMs"`
}

// CertificateIdentity binds a member to the gateway certificate it currently
// serves. PreviousSHA256 with a validity bound is the rotation overlap window.
type CertificateIdentity struct {
	SHA256                   string `json:"sha256"`
	PreviousSHA256           string `json:"previousSha256,omitempty"`
	PreviousValidUntilUnixMs int64  `json:"previousValidUntilUnixMs,omitempty"`
}

// Member is one candidate endpoint of the discovery artifact.
type Member struct {
	InstanceID         string              `json:"instanceId"`
	BootID             string              `json:"bootId"`
	BuildID            string              `json:"buildId"`
	ImageDigest        string              `json:"imageDigest,omitempty"`
	URL                string              `json:"url"`
	TLSServerName      string              `json:"tlsServerName"`
	Zone               string              `json:"zone,omitempty"`
	ProtocolVersion    uint32              `json:"protocolVersion"`
	Ready              bool                `json:"ready"`
	Draining           bool                `json:"draining"`
	LeaseEpoch         uint64              `json:"leaseEpoch"`
	LeaseExpiresUnixMs int64               `json:"leaseExpiresUnixMs"`
	Prepared           *PreparedEvidence   `json:"prepared,omitempty"`
	Certificate        CertificateIdentity `json:"certificate"`
}

// DiscoveryDocument is the immutable membership artifact for one bundle.
type DiscoveryDocument struct {
	Schema        int      `json:"schema"`
	BundleHash    string   `json:"bundleHash"`
	Revision      uint64   `json:"discoveryRevision"`
	ExpiresUnixMs int64    `json:"expiresUnixMs"`
	Members       []Member `json:"members"`
}

// RevocationDocument is the service-scoped, cumulative revocation state. The
// epoch is persisted before it takes effect so a restart cannot resurrect a
// revoked bundle or accept a lower epoch later.
type RevocationDocument struct {
	Schema              int      `json:"schema"`
	Epoch               uint64   `json:"epoch"`
	BundleHashes        []string `json:"bundleHashes"`
	CancelActiveStreams bool     `json:"cancelActiveStreams"`
	ExpiresUnixMs       int64    `json:"expiresUnixMs"`
}

func decodeDocument(payload []byte, document any) error {
	if len(payload) == 0 || len(payload) > maxDocumentBytes {
		return errDocument
	}
	if err := json.Unmarshal(payload, document, json.RejectUnknownMembers(true)); err != nil {
		return errDocument
	}
	return nil
}

func validIdentifier(value string, maxLength int) bool {
	if value == "" || len(value) > maxLength || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == sha256.Size && value == strings.ToLower(value)
}

// decodeBundle verifies the extended bundle contract. The bundle hash is the
// digest of the payload itself, so a release identity can be checked against it
// without trusting any field inside the document.
func decodeBundle(payload []byte, scope agent.Scope) (BundleDocument, error) {
	var doc BundleDocument
	if err := decodeDocument(payload, &doc); err != nil {
		return doc, err
	}
	if doc.Schema != payloadSchema || !validIdentifier(doc.ReleaseID, maxIdentifier) || doc.Generation == 0 ||
		!validIdentifier(doc.Flag, maxIdentifier) || doc.Policy.Workspace != scope.WorkspaceID || doc.Policy.Environment != scope.EnvironmentID {
		return doc, errDocument
	}
	if doc.DiscoveryMaxAgeSeconds == 0 {
		doc.DiscoveryMaxAgeSeconds = defaultDiscoveryMaxAgeSeconds
	}
	if doc.PolicyMaxAgeSeconds == 0 {
		doc.PolicyMaxAgeSeconds = defaultPolicyMaxAgeSeconds
	}
	if doc.DiscoveryMaxAgeSeconds < 0 || doc.DiscoveryMaxAgeSeconds > maxArtifactAgeSeconds ||
		doc.PolicyMaxAgeSeconds < 0 || doc.PolicyMaxAgeSeconds > maxArtifactAgeSeconds {
		return doc, errDocument
	}
	if len(doc.Builds) == 0 || len(doc.Builds) > 64 {
		return doc, errDocument
	}
	for name, build := range doc.Builds {
		if !validIdentifier(name, maxIdentifier) || (build.ImageDigest != "" && !validDigest(build.ImageDigest)) {
			return doc, errDocument
		}
	}
	if _, ok := doc.Builds[doc.DefaultBuild]; !ok {
		return doc, errDocument
	}
	if ramp := doc.Ramp; ramp != nil {
		if !validIdentifier(ramp.Key, maxIdentifier) || ramp.Threshold < 0 || ramp.Threshold > bucketing.Buckets ||
			len(ramp.Salt) > model.MaxSaltLen || ramp.Unit == "" || ramp.CanaryBuild == doc.DefaultBuild {
			return doc, errDocument
		}
		if _, ok := doc.Builds[ramp.CanaryBuild]; !ok {
			return doc, errDocument
		}
	}
	return doc, nil
}

// decodeDiscovery verifies the extended membership contract for one bundle and
// rejects any member that could not be dispatched to safely.
func decodeDiscovery(payload []byte, bundleHash string, now time.Time) (DiscoveryDocument, error) {
	var doc DiscoveryDocument
	if err := decodeDocument(payload, &doc); err != nil {
		return doc, err
	}
	if doc.Schema != payloadSchema || doc.BundleHash != bundleHash || doc.Revision == 0 || doc.ExpiresUnixMs <= now.UnixMilli() || len(doc.Members) > maxMembers {
		return doc, errDocument
	}
	seen := make(map[string]bool, len(doc.Members))
	for _, member := range doc.Members {
		if !validIdentifier(member.InstanceID, maxIdentifier) || !validIdentifier(member.BootID, maxIdentifier) || !validIdentifier(member.BuildID, maxIdentifier) ||
			!validIdentifier(member.TLSServerName, maxIdentifier) || !validDigest(member.Certificate.SHA256) || seen[member.InstanceID] {
			return doc, errDocument
		}
		seen[member.InstanceID] = true
		if member.Zone != "" && !validIdentifier(member.Zone, maxIdentifier) {
			return doc, errDocument
		}
		if member.Certificate.PreviousSHA256 != "" && (!validDigest(member.Certificate.PreviousSHA256) || member.Certificate.PreviousValidUntilUnixMs <= 0) {
			return doc, errDocument
		}
		if member.Prepared != nil {
			if member.Prepared.BundleHash != bundleHash || member.Prepared.Generation == 0 || member.Prepared.PreparedRevision == 0 {
				return doc, errDocument
			}
		}
	}
	return doc, nil
}

func decodeRevocation(payload []byte, now time.Time) (RevocationDocument, error) {
	var doc RevocationDocument
	if err := decodeDocument(payload, &doc); err != nil {
		return doc, err
	}
	if doc.Schema != payloadSchema || doc.Epoch == 0 || len(doc.BundleHashes) > maxRevokedBundles || doc.ExpiresUnixMs <= now.UnixMilli() {
		return doc, errDocument
	}
	for _, hash := range doc.BundleHashes {
		if !validDigest(hash) {
			return doc, errDocument
		}
	}
	return doc, nil
}
