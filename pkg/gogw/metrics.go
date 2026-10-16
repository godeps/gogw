package gogw

import (
	"sort"
	"strings"
	"sync"
)

// Traffic event phases. They are deliberately distinct: an allocation is a
// decision, an execution is an attempt that may fail, and an exposure is a unit
// actually reaching a build, which is the only one an experiment may count.
const (
	phaseAllocation = "allocation"
	phaseExecution  = "execution"
	phaseExposure   = "exposure"
)

// maxMetricKeys bounds the counter map. Every label already comes from a fixed
// vocabulary; the limit is a second line of defense against a hostile or buggy
// control plane inflating the key space.
const maxMetricKeys = 4096

const overflowLabel = "overflow"

// instanceBuild is the build dimension of an event that belongs to the instance
// as a whole rather than to one logical build — a maintenance sweep, a release
// activation, a refused internal request. It is deliberately not overflowLabel:
// that one means the label vocabulary was exhausted, and an operator reading the
// counters must be able to tell the two apart.
const instanceBuild = "instance"

// metricSample is one bounded counter.
type metricSample struct {
	Phase string `json:"phase"`
	Build string `json:"build"`
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// metrics is a bounded-cardinality counter set. It never records a principal,
// an address or a token: only phase, build and a fixed-vocabulary label.
type metrics struct {
	mu       sync.Mutex
	counters map[string]*metricSample
}

func newMetrics() *metrics {
	return &metrics{counters: map[string]*metricSample{}}
}

// add counts one event.
func (m *metrics) add(phase, build, label string) {
	if m == nil {
		return
	}
	if build == "" {
		build = instanceBuild
	} else if !validIdentifier(build, 64) {
		build = overflowLabel
	}
	if !validIdentifier(label, 64) {
		label = overflowLabel
	}
	key := strings.Join([]string{phase, build, label}, "\x00")
	m.mu.Lock()
	defer m.mu.Unlock()
	sample, ok := m.counters[key]
	if !ok {
		if len(m.counters) >= maxMetricKeys {
			key = strings.Join([]string{phase, overflowLabel, overflowLabel}, "\x00")
			sample, ok = m.counters[key]
			if !ok {
				m.counters[key] = &metricSample{Phase: phase, Build: overflowLabel, Label: overflowLabel, Count: 1}
				return
			}
			sample.Count++
			return
		}
		sample = &metricSample{Phase: phase, Build: build, Label: label}
		m.counters[key] = sample
	}
	sample.Count++
}

// snapshot returns the counters in a stable order.
func (m *metrics) snapshot() []metricSample {
	m.mu.Lock()
	defer m.mu.Unlock()
	samples := make([]metricSample, 0, len(m.counters))
	for _, sample := range m.counters {
		samples = append(samples, *sample)
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Phase != samples[j].Phase {
			return samples[i].Phase < samples[j].Phase
		}
		if samples[i].Build != samples[j].Build {
			return samples[i].Build < samples[j].Build
		}
		return samples[i].Label < samples[j].Label
	})
	return samples
}

// Diagnostics is the operator-visible gateway state. It is served only on the
// authenticated internal path and never contains a token, a principal, a request
// header or an application address.
type Diagnostics struct {
	Instance              string `json:"instance"`
	Boot                  string `json:"boot"`
	Build                 string `json:"build"`
	AgentSession          string `json:"agentSession"`
	Registered            bool   `json:"registered"`
	LeaseEpoch            uint64 `json:"leaseEpoch"`
	LeaseExpiresUnixMs    int64  `json:"leaseExpiresUnixMs"`
	Ready                 bool   `json:"ready"`
	ReadyReason           string `json:"readyReason,omitempty"`
	Eligible              bool   `json:"eligible"`
	EligibleReason        string `json:"eligibleReason,omitempty"`
	Healthy               bool   `json:"healthy"`
	Draining              bool   `json:"draining"`
	Fenced                bool   `json:"fenced"`
	Generation            uint64 `json:"generation"`
	ReleaseID             string `json:"releaseID"`
	BundleHash            string `json:"bundleHash"`
	DiscoveryRevision     uint64 `json:"discoveryRevision"`
	Prepared              bool   `json:"prepared"`
	PreparedHash          string `json:"preparedHash,omitempty"`
	PreparedGeneration    uint64 `json:"preparedGeneration,omitempty"`
	PreparedExpiresUnixMs int64  `json:"preparedExpiresUnixMs,omitempty"`
	Operations            int    `json:"operations"`
	// The instants after which the active release may no longer be used. They are
	// what bounds offline validity, so an operator reads when traffic stops instead
	// of discovering it: the instance refuses with the name of the window that ran
	// out, and the window is these two.
	PolicyExpiresUnixMs    int64          `json:"policyExpiresUnixMs,omitempty"`
	DiscoveryExpiresUnixMs int64          `json:"discoveryExpiresUnixMs,omitempty"`
	Members                int            `json:"members"`
	Rejected               map[string]int `json:"rejected"`
	Isolated               map[string]int `json:"isolated"`
	RampThreshold          int            `json:"rampThreshold"`
	Sessions               int            `json:"sessions"`
	RetiredViews           int            `json:"retiredViews"`
	InFlight               int            `json:"inFlight"`
	Streams                int            `json:"streams"`
	RevocationEpoch        uint64         `json:"revocationEpoch"`
	RevokedReleases        int            `json:"revokedReleases"`
	// The certificate digests a control plane must advertise for this instance.
	// The frozen protocol carries no such field, so the digest travels out of band
	// and this is where an operator checks the published artifact against it.
	CertificateSHA256                   string         `json:"certificateSha256"`
	CertificatePreviousSHA256           string         `json:"certificatePreviousSha256,omitempty"`
	CertificatePreviousValidUntilUnixMs int64          `json:"certificatePreviousValidUntilUnixMs,omitempty"`
	Counters                            []metricSample `json:"counters"`
}
