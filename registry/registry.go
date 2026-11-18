// Package registry is the Kirowen sequencer for the proof of concept.
//
// It accepts envelopes, stores them outside the tree, appends their event
// leaves to a Tessera log on local disk, and inserts an internal
// checkpoint leaf after every 1,000 ordinary leaves (docs/envelope-v0.md
// §5.1).
//
// Phase 0 scope: the stateless acceptance rules and the signature are
// checked. The stateful rules (object ownership, oseq/prev, kseq, refs,
// quotas, idempotency) and the source key registry come in phase 2
// (docs/technical-analysis.md §17); until then keys come from a static
// KeyResolver.
package registry

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"

	"github.com/pasta0126/kirowen/envelope"
	"github.com/pasta0126/kirowen/leaf"
)

// DefaultCheckpointEvery is the number of ordinary leaves between internal
// checkpoint leaves (concept decision 11).
const DefaultCheckpointEvery = 1000

// ErrUnknownKey is returned when no public key is known for an envelope's kid.
var ErrUnknownKey = errors.New("registry: unknown key id")

// KeyResolver returns the public key for a key id, or ErrUnknownKey.
type KeyResolver func(kid [envelope.HashSize]byte) (ed25519.PublicKey, error)

// StaticKeys returns a KeyResolver over a fixed set of keys.
func StaticKeys(keys ...ed25519.PublicKey) KeyResolver {
	m := make(map[[envelope.HashSize]byte]ed25519.PublicKey, len(keys))
	for _, k := range keys {
		m[envelope.KeyID(k)] = k
	}
	return func(kid [envelope.HashSize]byte) (ed25519.PublicKey, error) {
		if k, ok := m[kid]; ok {
			return k, nil
		}
		return nil, ErrUnknownKey
	}
}

// Config configures a Registry.
type Config struct {
	// Dir is the data directory. Dir/log holds the public log (tiles,
	// entry bundles, checkpoint); Dir/envelopes holds envelopes, which are
	// not public.
	Dir string
	// Signer signs tree heads. Its name is the log origin.
	Signer note.Signer
	// Verifier verifies the Signer's tree heads.
	Verifier note.Verifier
	// Keys resolves source keys for Submit. Optional: the API server
	// validates envelopes itself and calls AppendEvent.
	Keys KeyResolver
	// CheckpointEvery defaults to DefaultCheckpointEvery.
	CheckpointEvery uint64
	// BatchMaxAge defaults to 1 s; CheckpointInterval defaults to 1 s.
	BatchMaxAge        time.Duration
	CheckpointInterval time.Duration
}

// Registry is a running sequencer. It is safe for concurrent use.
type Registry struct {
	cfg      Config
	logDir   string
	envDir   string
	fetch    client.FileFetcher
	add      tessera.AddFn
	reader   tessera.LogReader
	awaiter  *tessera.PublicationAwaiter
	shutdown func(context.Context) error
	cancel   context.CancelFunc

	// mu serializes appends, so that leaf order and the ordinary-leaf
	// count stay consistent with checkpoint insertion.
	mu       sync.Mutex
	ordinary uint64 // ordinary leaves since the last checkpoint leaf
	prevSize uint64 // size certified by the last checkpoint leaf (0 if none)
	prevRoot []byte
}

// Confirmation is what the registry returns for an accepted envelope
// (docs/envelope-v0.md §10). With the envelope itself, it is a
// self-sufficient proof of the event.
type Confirmation struct {
	EnvelopeHash   []byte   `cbor:"1,keyasint"`
	LeafIndex      uint64   `cbor:"2,keyasint"`
	TreeHead       []byte   `cbor:"3,keyasint"`
	InclusionProof [][]byte `cbor:"4,keyasint"`
}

// Open opens or creates a registry in cfg.Dir.
func Open(ctx context.Context, cfg Config) (*Registry, error) {
	if cfg.Signer == nil || cfg.Verifier == nil {
		return nil, errors.New("registry: Signer and Verifier are required")
	}
	if cfg.Signer.Name() != cfg.Verifier.Name() {
		return nil, errors.New("registry: signer and verifier names differ")
	}
	if cfg.CheckpointEvery == 0 {
		cfg.CheckpointEvery = DefaultCheckpointEvery
	}
	if cfg.BatchMaxAge == 0 {
		cfg.BatchMaxAge = time.Second
	}
	if cfg.CheckpointInterval == 0 {
		cfg.CheckpointInterval = time.Second
	}
	r := &Registry{
		cfg:    cfg,
		logDir: filepath.Join(cfg.Dir, "log"),
		envDir: filepath.Join(cfg.Dir, "envelopes"),
	}
	r.fetch = client.FileFetcher{Root: r.logDir}
	for _, d := range []string{r.logDir, r.envDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}

	ctx, r.cancel = context.WithCancel(ctx)
	driver, err := posix.New(ctx, posix.Config{Path: r.logDir})
	if err != nil {
		r.cancel()
		return nil, err
	}
	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(cfg.Signer).
		WithBatching(1024, cfg.BatchMaxAge).
		WithCheckpointInterval(cfg.CheckpointInterval).
		// No-self-validation rule: never re-sign an unchanged tree.
		WithCheckpointRepublishInterval(0)
	appender, shutdown, reader, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		r.cancel()
		return nil, err
	}
	r.add, r.reader, r.shutdown = appender.Add, reader, shutdown
	r.awaiter = tessera.NewPublicationAwaiter(ctx, reader.ReadCheckpoint, 100*time.Millisecond)

	if err := r.recover(ctx); err != nil {
		r.Close(context.Background())
		return nil, err
	}
	return r, nil
}

// Close shuts the registry down, waiting for pending entries.
func (r *Registry) Close(ctx context.Context) error {
	err := r.shutdown(ctx)
	r.cancel()
	return err
}

// Origin returns the log origin.
func (r *Registry) Origin() string { return r.cfg.Signer.Name() }

// LogDir returns the directory holding the public log.
func (r *Registry) LogDir() string { return r.logDir }

// recover rebuilds the in-memory checkpoint state by scanning back from
// the end of the log to the last checkpoint leaf. At most CheckpointEvery
// leaves are read. If the log ends with a full run of ordinary leaves
// (e.g. after a crash), the missing checkpoint leaf is appended now.
func (r *Registry) recover(ctx context.Context) error {
	size, err := r.reader.IntegratedSize(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := size; i > 0; i-- {
		l, err := r.readLeaf(ctx, i-1, size)
		if err != nil {
			return fmt.Errorf("registry: recover: leaf %d: %w", i-1, err)
		}
		if l.Type == leaf.TypeCheckpoint {
			r.prevSize, r.prevRoot = l.Checkpoint.Size, l.Checkpoint.Root
			break
		}
		r.ordinary++
		if r.ordinary > r.cfg.CheckpointEvery {
			return fmt.Errorf("registry: recover: more than %d ordinary leaves without a checkpoint", r.cfg.CheckpointEvery)
		}
	}
	if r.ordinary == r.cfg.CheckpointEvery {
		return r.appendCheckpointLocked(ctx, size)
	}
	return nil
}

// readLeaf reads leaf i from a tree of the given size.
func (r *Registry) readLeaf(ctx context.Context, i, size uint64) (*leaf.Leaf, error) {
	b, err := client.GetEntryBundle(ctx, r.fetch.ReadEntryBundle, i/256, size)
	if err != nil {
		return nil, err
	}
	return leaf.Parse(b.Entries[i%256])
}

// Submit validates and appends an envelope and blocks until it is
// covered by a published tree head. It checks only the stateless rules
// and the signature (with Config.Keys); the API server adds the stateful
// rules on top of AppendEvent and Prove.
func (r *Registry) Submit(ctx context.Context, raw []byte) (*Confirmation, error) {
	env, err := envelope.Parse(raw)
	if err != nil {
		return nil, err
	}
	if r.cfg.Keys == nil {
		return nil, ErrUnknownKey
	}
	pub, err := r.cfg.Keys(env.KeyID)
	if err != nil {
		return nil, err
	}
	if err := env.Verify(pub); err != nil {
		return nil, err
	}
	future, err := r.AppendEvent(ctx, env)
	if err != nil {
		return nil, err
	}
	idx, err := future()
	if err != nil {
		return nil, err
	}
	return r.Prove(ctx, env.Hash[:], idx.Index)
}

// AppendEvent stores an already validated envelope and appends its event
// leaf. It returns as soon as the leaf is queued; the future resolves to
// its index. If this leaf completes a run of CheckpointEvery ordinary
// leaves, AppendEvent also appends the checkpoint leaf, which blocks for
// about one batch.
func (r *Registry) AppendEvent(ctx context.Context, env *envelope.Envelope) (tessera.IndexFuture, error) {
	// Store the envelope before its leaf exists, so that a leaf never
	// points to an envelope we failed to keep.
	if err := r.storeEnvelope(env); err != nil {
		return nil, err
	}
	lb, err := leaf.Event(env.Hash[:])
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	future := r.add(ctx, tessera.NewEntry(lb))
	r.ordinary++
	if r.ordinary == r.cfg.CheckpointEvery {
		// The checkpoint leaf goes right after this event, so wait for
		// this event's index (futures are memoized).
		idx, err := future()
		if err != nil {
			return nil, err
		}
		if err := r.appendCheckpointLocked(ctx, idx.Index+1); err != nil {
			return nil, err
		}
	}
	return future, nil
}

// Prove waits until leaf index is covered by a published tree head and
// returns the confirmation for it.
func (r *Registry) Prove(ctx context.Context, envelopeHash []byte, index uint64) (*Confirmation, error) {
	known := func() (tessera.Index, error) { return tessera.Index{Index: index}, nil }
	_, cp, err := r.awaiter.Await(ctx, known)
	if err != nil {
		return nil, err
	}
	c, _, _, err := log.ParseCheckpoint(cp, r.Origin(), r.cfg.Verifier)
	if err != nil {
		return nil, fmt.Errorf("registry: own checkpoint: %w", err)
	}
	pb, err := client.NewProofBuilder(ctx, c.Size, r.fetch.ReadTile)
	if err != nil {
		return nil, err
	}
	proof, err := pb.InclusionProof(ctx, index)
	if err != nil {
		return nil, err
	}
	return &Confirmation{
		EnvelopeHash:   envelopeHash,
		LeafIndex:      index,
		TreeHead:       cp,
		InclusionProof: proof,
	}, nil
}

// EventHashes returns the envelope hashes of the event leaves at
// positions [from, size), keyed by hash, where size is the integrated
// tree size. It is used to reconcile registry state after a crash.
func (r *Registry) EventHashes(ctx context.Context, from uint64) (map[[envelope.HashSize]byte]uint64, error) {
	size, err := r.reader.IntegratedSize(ctx)
	if err != nil {
		return nil, err
	}
	out := map[[envelope.HashSize]byte]uint64{}
	for i := from; i < size; {
		b, err := client.GetEntryBundle(ctx, r.fetch.ReadEntryBundle, i/256, size)
		if err != nil {
			return nil, err
		}
		for j := i % 256; j < uint64(len(b.Entries)) && i < size; j, i = j+1, i+1 {
			l, err := leaf.Parse(b.Entries[j])
			if err != nil {
				return nil, fmt.Errorf("registry: leaf %d: %w", i, err)
			}
			if l.Type == leaf.TypeEvent {
				var h [envelope.HashSize]byte
				copy(h[:], l.EnvelopeHash)
				out[h] = i
			}
		}
	}
	return out, nil
}

// appendCheckpointLocked appends the internal checkpoint leaf at position
// n. r.mu must be held, so no other leaf can be added meanwhile. It waits
// until the tree of size n (every leaf so far) has a published tree head,
// then appends a leaf certifying it.
func (r *Registry) appendCheckpointLocked(ctx context.Context, n uint64) error {
	cpRaw, c, err := r.waitForCheckpoint(ctx, n)
	if err != nil {
		return fmt.Errorf("registry: checkpoint leaf at %d: %w", n, err)
	}
	body := leaf.Checkpoint{Size: n, Root: c.Hash, PrevSize: r.prevSize, PrevRoot: r.prevRoot, Note: cpRaw}
	lb, err := leaf.NewCheckpoint(body)
	if err != nil {
		return err
	}
	idx, err := r.add(ctx, tessera.NewEntry(lb))()
	if err != nil {
		return err
	}
	if idx.Index != n {
		return fmt.Errorf("registry: checkpoint leaf landed at %d, want %d", idx.Index, n)
	}
	r.ordinary, r.prevSize, r.prevRoot = 0, n, c.Hash
	return nil
}

// waitForCheckpoint polls until the published tree head has exactly size n.
func (r *Registry) waitForCheckpoint(ctx context.Context, n uint64) ([]byte, *log.Checkpoint, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		raw, err := r.reader.ReadCheckpoint(ctx)
		if err == nil {
			c, _, _, err := log.ParseCheckpoint(raw, r.Origin(), r.cfg.Verifier)
			if err != nil {
				return nil, nil, err
			}
			switch {
			case c.Size == n:
				return raw, c, nil
			case c.Size > n:
				return nil, nil, fmt.Errorf("published size %d passed %d", c.Size, n)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (r *Registry) envelopePath(hash []byte) string {
	h := hex.EncodeToString(hash)
	return filepath.Join(r.envDir, h[:2], h[2:4], h+".cose")
}

func (r *Registry) storeEnvelope(env *envelope.Envelope) error {
	p := r.envelopePath(env.Hash[:])
	if _, err := os.Stat(p); err == nil {
		return nil // content-addressed: already stored
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(env.Raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}

// Envelope returns a stored envelope by its hash.
func (r *Registry) Envelope(hash []byte) ([]byte, error) {
	if len(hash) != envelope.HashSize {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(r.envelopePath(hash))
}
