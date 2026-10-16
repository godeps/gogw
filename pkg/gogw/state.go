package gogw

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sync"

	agentv1 "github.com/saker-ai/grayling/api/agent/v1"
	"github.com/saker-ai/grayling/pkg/agent"
	"google.golang.org/protobuf/proto"
)

// errRegression reports a publication that would move persisted state backwards.
// It is distinct from a document error so the control plane is told the artifact
// was a rollback rather than malformed.
var errRegression = errors.New("gogw: refused a publication that regresses persisted state")

const (
	stateSchema = 1

	// maxStateBytes bounds the state file read so a corrupt or hostile file
	// cannot exhaust memory before validation.
	maxStateBytes = 8 << 20

	// maxOperationRecords bounds the persisted idempotency journal.
	maxOperationRecords = 128
)

// markRecord is the persisted watermark of one accepted resource.
type markRecord struct {
	Kind              string `json:"kind"`
	Key               string `json:"key"`
	ControlPlaneEpoch uint64 `json:"controlPlaneEpoch"`
	Revision          uint64 `json:"revision"`
	PayloadHash       string `json:"payloadHash"`
	BundleHash        string `json:"bundleHash"`
}

// operationRecord remembers one handled release command so a replay after a
// reconnect or restart cannot apply the same transition twice.
type operationRecord struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Generation uint64 `json:"generation"`
	Status     string `json:"status"`
	AtUnixMs   int64  `json:"atUnixMs"`
}

type revocationRecord struct {
	Epoch  uint64   `json:"epoch"`
	Hashes []string `json:"hashes"`
}

// activeRecord is the durable evidence that one release was activated by this
// instance. A restart re-installs only a release recorded here: an accepted but
// never activated release must not begin serving because the process restarted.
type activeRecord struct {
	Hash       string `json:"hash"`
	Key        string `json:"key"`
	ReleaseID  string `json:"releaseId"`
	Generation uint64 `json:"generation"`
}

type journalState struct {
	Schema     int                   `json:"schema"`
	Watermarks map[string]markRecord `json:"watermarks,omitempty"`
	Generation uint64                `json:"generation"`
	Bundle     string                `json:"bundle,omitempty"`
	Discovery  string                `json:"discovery,omitempty"`
	Active     *activeRecord         `json:"active,omitempty"`
	Revocation revocationRecord      `json:"revocation"`
	Ramps      map[string]int        `json:"ramps,omitempty"`
	Operations []operationRecord     `json:"operations,omitempty"`
}

// journal is the durable, atomically replaced gateway state. Every mutation is
// persisted before it is acted on, so a crash cannot lose a revocation epoch, a
// monotone generation or an accepted watermark.
type journal struct {
	path string

	mu    sync.Mutex
	state journalState
}

func openJournal(path string) (*journal, error) {
	j := &journal{path: path, state: journalState{Schema: stateSchema, Watermarks: map[string]markRecord{}, Ramps: map[string]int{}}}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return j, nil
	case err != nil:
		return nil, err
	case len(raw) > maxStateBytes:
		return nil, errors.New("gogw: state file is too large")
	}
	var state journalState
	if err := json.Unmarshal(raw, &state, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("gogw: corrupt state file %s: %w", path, err)
	}
	if state.Schema != stateSchema {
		return nil, fmt.Errorf("gogw: unsupported state schema %d", state.Schema)
	}
	if state.Watermarks == nil {
		state.Watermarks = map[string]markRecord{}
	}
	if state.Ramps == nil {
		state.Ramps = map[string]int{}
	}
	for key, mark := range state.Watermarks {
		if _, err := decodeMark(mark); err != nil {
			return nil, fmt.Errorf("gogw: corrupt state file %s: %w", path, err)
		}
		_ = key
	}
	j.state = state
	return j, nil
}

func markID(kind agentv1.ResourceKind, key string) string {
	return fmt.Sprintf("%d/%s", int32(kind), key)
}

func decodeMark(mark markRecord) (agent.Watermark, error) {
	payload, err := hex.DecodeString(mark.PayloadHash)
	if err != nil || len(payload) != 32 {
		return agent.Watermark{}, errors.New("invalid payload hash")
	}
	bundle, err := hex.DecodeString(mark.BundleHash)
	if err != nil || len(bundle) != 32 {
		return agent.Watermark{}, errors.New("invalid bundle hash")
	}
	watermark := agent.Watermark{ControlPlaneEpoch: mark.ControlPlaneEpoch, Revision: mark.Revision}
	copy(watermark.PayloadHash[:], payload)
	copy(watermark.BundleHash[:], bundle)
	return watermark, nil
}

func encodeMark(kind agentv1.ResourceKind, key string, watermark agent.Watermark) markRecord {
	return markRecord{
		Kind: kind.String(), Key: key,
		ControlPlaneEpoch: watermark.ControlPlaneEpoch, Revision: watermark.Revision,
		PayloadHash: hex.EncodeToString(watermark.PayloadHash[:]), BundleHash: hex.EncodeToString(watermark.BundleHash[:]),
	}
}

// snapshot returns a deep copy of the persisted state.
func (j *journal) snapshot() journalState {
	j.mu.Lock()
	defer j.mu.Unlock()
	return cloneState(j.state)
}

func cloneState(state journalState) journalState {
	clone := state
	clone.Watermarks = make(map[string]markRecord, len(state.Watermarks))
	maps.Copy(clone.Watermarks, state.Watermarks)
	clone.Ramps = make(map[string]int, len(state.Ramps))
	maps.Copy(clone.Ramps, state.Ramps)
	clone.Revocation = revocationRecord{Epoch: state.Revocation.Epoch, Hashes: append([]string(nil), state.Revocation.Hashes...)}
	clone.Operations = append([]operationRecord(nil), state.Operations...)
	if state.Active != nil {
		active := *state.Active
		clone.Active = &active
	}
	return clone
}

// watermark returns the persisted watermark of one resource key.
func (j *journal) watermark(kind agentv1.ResourceKind, key string) agent.Watermark {
	j.mu.Lock()
	defer j.mu.Unlock()
	mark, ok := j.state.Watermarks[markID(kind, key)]
	if !ok {
		return agent.Watermark{}
	}
	watermark, err := decodeMark(mark)
	if err != nil {
		return agent.Watermark{}
	}
	return watermark
}

// commit applies a mutation and persists the result before returning.
func (j *journal) commit(mutate func(*journalState) error) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	next := cloneState(j.state)
	if err := mutate(&next); err != nil {
		return err
	}
	if err := writeState(j.path, next); err != nil {
		return err
	}
	j.state = next
	return nil
}

// accept records one accepted resource and its watermark atomically with the
// resource that will be restored on a cold start. The release generation is
// persisted separately from the resource revision so a restart cannot accept a
// release older than the one already applied. Membership is persisted next to
// the release it was verified against: a restart that restored only the bundle
// would have to wait for a control plane that may consider the cursor current.
func (j *journal) accept(kind agentv1.ResourceKind, key string, generation uint64, claims agent.Claims, resource *agentv1.SignedResource) error {
	encoded, err := proto.Marshal(resource)
	if err != nil {
		return err
	}
	stored := base64.StdEncoding.EncodeToString(encoded)
	return j.commit(func(state *journalState) error {
		switch kind {
		case agentv1.ResourceKind_RESOURCE_KIND_BUNDLE:
			if generation < state.Generation {
				return fmt.Errorf("%w: release generation", errRegression)
			}
			state.Generation = generation
			state.Bundle = stored
		case agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY:
			state.Discovery = stored
		}
		state.Watermarks[markID(kind, key)] = encodeMark(kind, key, claims.Watermark())
		return nil
	})
}

// setActive persists the activation of one release. It is written before the
// release starts serving, so a crash cannot leave a view in service that the
// state file does not record.
func (j *journal) setActive(record *activeRecord) error {
	return j.commit(func(state *journalState) error {
		if record == nil {
			state.Active = nil
			return nil
		}
		if state.Active != nil && state.Active.Generation > record.Generation {
			return fmt.Errorf("%w: active release", errRegression)
		}
		stored := *record
		state.Active = &stored
		return nil
	})
}

// active returns the release this instance had activated, if any.
func (j *journal) active() *activeRecord {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state.Active == nil {
		return nil
	}
	stored := *j.state.Active
	return &stored
}

// noteOperation persists a handled release command for idempotent replay.
func (j *journal) noteOperation(record operationRecord) error {
	return j.commit(func(state *journalState) error {
		for index, existing := range state.Operations {
			if existing.ID == record.ID {
				state.Operations[index] = record
				return nil
			}
		}
		state.Operations = append(state.Operations, record)
		if len(state.Operations) > maxOperationRecords {
			state.Operations = append([]operationRecord(nil), state.Operations[len(state.Operations)-maxOperationRecords:]...)
		}
		return nil
	})
}

func (j *journal) operation(id string) (operationRecord, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, record := range j.state.Operations {
		if record.ID == id {
			return record, true
		}
	}
	return operationRecord{}, false
}

// operations reports how much of the idempotency journal is in use.
func (j *journal) operations() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.state.Operations)
}

// mergeRevocation persists a cumulative revocation state. The epoch is written
// before it takes effect, so a restart cannot resurrect a revoked bundle and a
// later lower epoch is refused.
func (j *journal) mergeRevocation(epoch uint64, hashes []string) (revocationRecord, error) {
	var merged revocationRecord
	err := j.commit(func(state *journalState) error {
		if epoch < state.Revocation.Epoch {
			return fmt.Errorf("%w: revocation epoch", errRegression)
		}
		known := make(map[string]bool, len(state.Revocation.Hashes)+len(hashes))
		records := make([]string, 0, len(state.Revocation.Hashes)+len(hashes))
		for _, hash := range append(append([]string(nil), state.Revocation.Hashes...), hashes...) {
			if known[hash] {
				continue
			}
			known[hash] = true
			records = append(records, hash)
		}
		if epoch == state.Revocation.Epoch && len(records) > maxRevokedBundles {
			return errors.New("gogw: too many revoked bundles")
		}
		state.Revocation = revocationRecord{Epoch: epoch, Hashes: records}
		merged = state.Revocation
		return nil
	})
	return merged, err
}

// rampFloor raises the persisted monotone ramp threshold of one allocation key.
func (j *journal) rampFloor(key string, threshold int) (int, error) {
	floor := threshold
	err := j.commit(func(state *journalState) error {
		if current, ok := state.Ramps[key]; ok && current > threshold {
			floor = current
			return nil
		}
		state.Ramps[key] = threshold
		floor = threshold
		return nil
	})
	return floor, err
}

// restore returns the resource of one persisted kind, accepted before the last
// restart.
func (j *journal) restore(kind agentv1.ResourceKind) (*agentv1.SignedResource, error) {
	j.mu.Lock()
	var encoded string
	switch kind {
	case agentv1.ResourceKind_RESOURCE_KIND_BUNDLE:
		encoded = j.state.Bundle
	case agentv1.ResourceKind_RESOURCE_KIND_DISCOVERY:
		encoded = j.state.Discovery
	}
	j.mu.Unlock()
	if encoded == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	resource := new(agentv1.SignedResource)
	if err := proto.Unmarshal(raw, resource); err != nil {
		return nil, err
	}
	return resource, nil
}

// writeState replaces the state file atomically and flushes the directory entry.
func writeState(path string, state journalState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".gogw-state-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
