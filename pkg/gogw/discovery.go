package gogw

import (
	"strings"
	"time"

	"github.com/saker-ai/grayling/pkg/bucketing"
	"github.com/saker-ai/grayling/pkg/model"
)

// Member rejection reasons. They are drawn from a fixed set so diagnostics and
// metrics cannot grow with the number of rejected candidates.
const (
	reasonAdmitted         = "admitted"
	reasonNotReady         = "not_ready"
	reasonDraining         = "draining"
	reasonBuildMismatch    = "build_mismatch"
	reasonProtocolMismatch = "protocol_mismatch"
	reasonLeaseExpired     = "lease_expired"
	reasonPreparedMissing  = "prepared_missing"
	reasonPreparedExpired  = "prepared_expired"
	reasonPreparedMismatch = "prepared_mismatch"
	reasonCertificateStale = "certificate_stale"
	reasonRevoked          = "bundle_revoked"
)

// member is one admitted discovery candidate with the identity data a ticket
// needs. Admission never authorizes by itself: the target gateway re-checks the
// presented ticket against its own release and boot.
type member struct {
	id         string
	boot       string
	build      string
	zone       string
	url        string
	serverName string
	digests    []string
	leaseUntil time.Time
	prepared   time.Time
}

// memberRejections counts why candidates were dropped, for diagnostics.
type memberRejections map[string]int

// admittedMembers filters one discovery artifact down to the candidates this
// gateway may dispatch to for the given release.
func admittedMembers(doc DiscoveryDocument, bundleHash string, generation uint64, builds map[string]BuildDescriptor, minimumProtocol uint32, revoked bool, now time.Time) ([]member, memberRejections) {
	rejections := memberRejections{}
	admitted := make([]member, 0, len(doc.Members))
	for _, candidate := range doc.Members {
		reason := rejectReason(candidate, bundleHash, generation, builds, minimumProtocol, revoked, now)
		if reason != reasonAdmitted {
			rejections[reason]++
			continue
		}
		digests := []string{candidate.Certificate.SHA256}
		if candidate.Certificate.PreviousSHA256 != "" && now.UnixMilli() < candidate.Certificate.PreviousValidUntilUnixMs {
			digests = append(digests, candidate.Certificate.PreviousSHA256)
		}
		admitted = append(admitted, member{
			id: candidate.InstanceID, boot: candidate.BootID, build: candidate.BuildID, zone: candidate.Zone,
			url: candidate.URL, serverName: candidate.TLSServerName, digests: digests,
			leaseUntil: time.UnixMilli(candidate.LeaseExpiresUnixMs), prepared: time.UnixMilli(candidate.Prepared.ExpiresUnixMs),
		})
	}
	return admitted, rejections
}

func rejectReason(candidate Member, bundleHash string, generation uint64, builds map[string]BuildDescriptor, minimumProtocol uint32, revoked bool, now time.Time) string {
	switch {
	case revoked:
		return reasonRevoked
	case !candidate.Ready:
		return reasonNotReady
	case candidate.Draining:
		return reasonDraining
	case candidate.ProtocolVersion < minimumProtocol:
		return reasonProtocolMismatch
	case candidate.LeaseEpoch == 0 || candidate.LeaseExpiresUnixMs <= now.UnixMilli():
		return reasonLeaseExpired
	case candidate.Prepared == nil:
		return reasonPreparedMissing
	case candidate.Prepared.BundleHash != bundleHash || candidate.Prepared.Generation != generation:
		return reasonPreparedMismatch
	case candidate.Prepared.ExpiresUnixMs <= now.UnixMilli():
		return reasonPreparedExpired
	}
	if _, ok := builds[candidate.BuildID]; !ok {
		return reasonBuildMismatch
	}
	if !validMemberAddress(candidate) {
		return reasonCertificateStale
	}
	return reasonAdmitted
}

// validMemberAddress requires a dispatchable HTTPS origin with a certificate
// identity. A candidate this gateway cannot dial is not a candidate.
func validMemberAddress(candidate Member) bool {
	if !validDigest(candidate.Certificate.SHA256) || candidate.TLSServerName == "" {
		return false
	}
	target, err := parseMemberURL(candidate.URL)
	if err != nil {
		return false
	}
	return target == candidate.URL
}

// rampState is the monotone eligibility prefix of one release ramp, with the
// threshold floored by the durable per-key maximum.
type rampState struct {
	key       string
	epoch     int64
	salt      string
	unit      string
	threshold int
	canary    string

	// canonical mirrors the SDK's own unit canonicalization so the prefix
	// coordinate cannot drift from the published bucketing algorithm.
	canonical func(any) (string, bool)
}

// rampOf builds the ramp state of one release. The effective threshold is
// floored by the durable per-key maximum, so a lower threshold can never pull an
// already exposed unit back out of the canary prefix.
func rampOf(doc BundleDocument, floor func(*Ramp) (int, error), canonical func(any) (string, bool)) (*rampState, error) {
	if doc.Ramp == nil {
		return nil, nil
	}
	threshold, err := floor(doc.Ramp)
	if err != nil {
		return nil, err
	}
	if threshold < doc.Ramp.Threshold {
		threshold = doc.Ramp.Threshold
	}
	return &rampState{
		key: doc.Ramp.Key, epoch: doc.Ramp.Epoch, salt: doc.Ramp.Salt, unit: doc.Ramp.Unit,
		threshold: threshold, canary: doc.Ramp.CanaryBuild, canonical: canonical,
	}, nil
}

// rampFloorKey identifies the durable ramp threshold slot: the salt and unit are
// part of the coordinate, so a re-salted ramp must not inherit the old floor.
func rampFloorKey(workspace, environment string, ramp *Ramp) string {
	return strings.Join([]string{workspace, environment, ramp.Key, ramp.Salt, ramp.Unit}, "\x00")
}

// unitValue extracts the ramp randomization unit from the evaluation context.
func (r *rampState) unitValue(ctx model.EvaluationContext) (string, bool) {
	if value, ok := r.canonicalAttribute(ctx, r.unit); ok {
		return value, true
	}
	// The authenticated subject is the only unit the gateway itself derives, so
	// it remains the fallback when the configured unit is absent.
	if value, ok := r.canonicalAttribute(ctx, "targetingKey"); ok {
		return value, true
	}
	if ctx.TargetingKey != "" {
		return ctx.TargetingKey, true
	}
	return "", false
}

func (r *rampState) canonicalAttribute(ctx model.EvaluationContext, name string) (string, bool) {
	raw, ok := ctx.Attributes[name]
	if !ok {
		return "", false
	}
	return r.canonical(raw)
}

// rampBucket is the eligibility coordinate of one unit. It uses the published
// bucketing algorithm with the eligibility purpose, whose result is a prefix
// interval: raising the threshold never removes a unit from the interval.
func rampBucket(snapshot model.Snapshot, ramp *rampState, unit string) (int, error) {
	return bucketing.Bucket(bucketing.Inputs{
		Workspace: snapshot.Workspace, Environment: snapshot.Environment,
		Key: ramp.key, Epoch: ramp.epoch, Salt: ramp.salt, UnitValue: unit,
		Purpose: bucketing.PurposeEligibility,
	})
}
