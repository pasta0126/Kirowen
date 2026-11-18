package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"

	"github.com/pasta0126/kirowen/envelope"
	"github.com/pasta0126/kirowen/leaf"
	"github.com/pasta0126/kirowen/verify"
)

const testOrigin = "example.com/log/v0"

type fixture struct {
	signer   note.Signer
	verifier note.Verifier
	source   ed25519.PrivateKey
	object   []byte
	oseq     uint64
	prev     []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := note.NewSigner(skey)
	v, _ := note.NewVerifier(vkey)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &fixture{signer: s, verifier: v, source: priv, object: bytes.Repeat([]byte{7}, 16)}
}

func (f *fixture) open(t *testing.T, dir string, every uint64) *Registry {
	t.Helper()
	r, err := Open(context.Background(), Config{
		Dir: dir, Signer: f.signer, Verifier: f.verifier,
		Keys:            StaticKeys(f.source.Public().(ed25519.PublicKey)),
		CheckpointEvery: every,
		BatchMaxAge:     10 * time.Millisecond, CheckpointInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// next signs the object's next event for some content.
func (f *fixture) next(t *testing.T, content string) []byte {
	t.Helper()
	d := sha256.Sum256([]byte(content))
	p := envelope.Payload{
		Version: envelope.Version, Source: bytes.Repeat([]byte{1}, 16), Object: f.object,
		ObjectSeq: f.oseq, Prev: f.prev, KeySeq: f.oseq,
		Digest: envelope.Digest{Alg: envelope.AlgSHA256, Value: d[:]},
	}
	raw, err := envelope.Sign(p, f.source)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	f.oseq, f.prev = f.oseq+1, h[:]
	return raw
}

func submit(t *testing.T, r *Registry, raw []byte) *Confirmation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := r.Submit(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func leafTypes(t *testing.T, dir string, size uint64) string {
	t.Helper()
	ff := client.FileFetcher{Root: dir}
	var s []byte
	for i := uint64(0); i < size; i++ {
		b, err := client.GetEntryBundle(context.Background(), ff.ReadEntryBundle, i/256, size)
		if err != nil {
			t.Fatal(err)
		}
		l, err := leaf.Parse(b.Entries[i%256])
		if err != nil {
			t.Fatal(err)
		}
		if l.Ordinary() {
			s = append(s, 'e')
		} else {
			s = append(s, 'C')
		}
	}
	return string(s)
}

func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	f := newFixture(t)
	pub := f.source.Public().(ed25519.PublicKey)
	r := f.open(t, dir, 3)

	var envs [][]byte
	var confs []*Confirmation
	for i := range 7 {
		raw := f.next(t, fmt.Sprintf("reading %d", i))
		envs = append(envs, raw)
		confs = append(confs, submit(t, r, raw))
	}

	// Leaves: e e e C e e e C e  (checkpoint leaves at 3 and 7).
	wantIdx := []uint64{0, 1, 2, 4, 5, 6, 8}
	for i, c := range confs {
		if c.LeafIndex != wantIdx[i] {
			t.Errorf("event %d at leaf %d, want %d", i, c.LeafIndex, wantIdx[i])
		}
		// Every confirmation verifies offline (scenarios 1, 2, 7).
		if _, _, err := verify.Event(envs[i], pub, c.LeafIndex, c.TreeHead, c.InclusionProof, testOrigin, f.verifier); err != nil {
			t.Errorf("event %d: %v", i, err)
		}
		if got, _ := r.Envelope(c.EnvelopeHash); !bytes.Equal(got, envs[i]) {
			t.Errorf("event %d: stored envelope differs", i)
		}
	}

	// A tampered envelope does not verify against its confirmation.
	tampered := f.next(t, "something else")
	if _, _, err := verify.Event(tampered, pub, confs[0].LeafIndex, confs[0].TreeHead, confs[0].InclusionProof, testOrigin, f.verifier); !errors.Is(err, verify.ErrInclusion) {
		t.Errorf("tampered envelope: got %v, want ErrInclusion", err)
	}
	f.oseq, f.prev = 7, confs[6].EnvelopeHash

	logDir := r.LogDir()
	l := client.FileFetcher{Root: logDir}
	rep, err := verify.Audit(ctx, l, testOrigin, f.verifier, 3)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Size != 9 || rep.Ordinary != 7 || rep.Checkpoints != 2 {
		t.Errorf("audit = %+v", rep)
	}

	// Old tree heads are consistent with the current one (scenario 4).
	th0, _ := verify.TreeHead(confs[0].TreeHead, testOrigin, f.verifier)
	cur, _ := l.ReadCheckpoint(ctx)
	thN, _ := verify.TreeHead(cur, testOrigin, f.verifier)
	if err := verify.Consistency(ctx, l, th0, thN); err != nil {
		t.Errorf("consistency: %v", err)
	}

	// Restart: state is recovered from the log.
	if err := r.Close(ctx); err != nil {
		t.Fatal(err)
	}
	r = f.open(t, dir, 3)
	for i := 7; i < 9; i++ {
		submit(t, r, f.next(t, fmt.Sprintf("reading %d", i)))
	}
	if err := r.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := leafTypes(t, logDir, 11), "eeeCeeeCeee"; got != want {
		t.Errorf("leaves after restart = %s, want %s", got, want)
	}
}

// TestCrashBeforeCheckpointLeaf simulates a crash between the last
// ordinary leaf of a run and its checkpoint leaf: reopening appends the
// missing checkpoint leaf.
func TestCrashBeforeCheckpointLeaf(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	f := newFixture(t)
	r := f.open(t, dir, 1000) // large: no checkpoint leaf is written
	for i := range 3 {
		submit(t, r, f.next(t, fmt.Sprint(i)))
	}
	r.Close(ctx)

	r = f.open(t, dir, 3) // now 3 ordinary leaves are a full run
	defer r.Close(ctx)
	submit(t, r, f.next(t, "after"))
	if got, want := leafTypes(t, r.LogDir(), 5), "eeeCe"; got != want {
		t.Errorf("leaves = %s, want %s", got, want)
	}
}

// TestRebuildDetected is scenario 6: the operator rebuilds the log with
// the same key but a different history. A verifier that kept an earlier
// tree head detects it.
func TestRebuildDetected(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	honest := f.open(t, t.TempDir(), 1000)
	var kept *Confirmation
	for i := range 3 {
		kept = submit(t, honest, f.next(t, fmt.Sprint(i)))
	}
	honest.Close(ctx)
	keptTH, err := verify.TreeHead(kept.TreeHead, testOrigin, f.verifier)
	if err != nil {
		t.Fatal(err)
	}

	// Rebuild: same signer, different events, more of them.
	f.oseq, f.prev = 0, nil
	forged := f.open(t, t.TempDir(), 1000)
	defer forged.Close(ctx)
	for i := range 5 {
		submit(t, forged, f.next(t, fmt.Sprintf("forged %d", i)))
	}
	l := client.FileFetcher{Root: forged.LogDir()}
	raw, _ := l.ReadCheckpoint(ctx)
	newTH, err := verify.TreeHead(raw, testOrigin, f.verifier)
	if err != nil {
		t.Fatal(err) // the forged tree head is validly signed...
	}
	// ...but it is not consistent with the one the verifier kept.
	if err := verify.Consistency(ctx, l, keptTH, newTH); !errors.Is(err, verify.ErrInconsistent) {
		t.Fatalf("got %v, want ErrInconsistent", err)
	}
}

func TestRejectsUnknownKey(t *testing.T) {
	f := newFixture(t)
	r := f.open(t, t.TempDir(), 3)
	defer r.Close(context.Background())
	other := newFixture(t)
	if _, err := r.Submit(context.Background(), other.next(t, "x")); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("got %v, want ErrUnknownKey", err)
	}
}

// TestConcurrentSubmits checks that concurrent submissions crossing
// several checkpoint boundaries still leave a log that passes the audit.
func TestConcurrentSubmits(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	r := f.open(t, t.TempDir(), 5)
	defer r.Close(ctx)

	const n = 23
	envs := make([][]byte, n)
	for i := range envs {
		envs[i] = f.next(t, fmt.Sprint(i)) // phase 0 does not enforce oseq order
	}
	errs := make(chan error, n)
	for _, e := range envs {
		go func() {
			_, err := r.Submit(ctx, e)
			errs <- err
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	rep, err := verify.Audit(ctx, client.FileFetcher{Root: r.LogDir()}, testOrigin, f.verifier, 5)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Ordinary != n || rep.Checkpoints != n/5 {
		t.Errorf("audit = %+v", rep)
	}
}

// TestAuditDetectsBadCheckpointLeaf appends a checkpoint leaf with a wrong
// root, bypassing the sequencer, and checks that the audit rejects it.
func TestAuditDetectsBadCheckpointLeaf(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	r := f.open(t, t.TempDir(), 1000)
	defer r.Close(ctx)
	submit(t, r, f.next(t, "a"))
	c := submit(t, r, f.next(t, "b"))

	lb, err := leaf.NewCheckpoint(leaf.Checkpoint{Size: 2, Root: make([]byte, 32), Note: c.TreeHead})
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	_, _, err = r.awaiter.Await(ctx, r.add(ctx, tessera.NewEntry(lb)))
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	_, err = verify.Audit(ctx, client.FileFetcher{Root: r.LogDir()}, testOrigin, f.verifier, 2)
	if !errors.Is(err, verify.ErrBadCheckpoint) {
		t.Fatalf("got %v, want ErrBadCheckpoint", err)
	}
}

// TestDefaultCheckpointEvery runs the real parameter: 1,001 events give a
// checkpoint leaf at position 1,000.
func TestDefaultCheckpointEvery(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	ctx := context.Background()
	f := newFixture(t)
	r := f.open(t, t.TempDir(), DefaultCheckpointEvery)
	defer r.Close(ctx)

	const n = DefaultCheckpointEvery + 1
	errs := make(chan error, n)
	for i := range n {
		e := f.next(t, fmt.Sprint(i))
		go func() {
			_, err := r.Submit(ctx, e)
			errs <- err
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	rep, err := verify.Audit(ctx, client.FileFetcher{Root: r.LogDir()}, testOrigin, f.verifier, DefaultCheckpointEvery)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Size != n+1 || rep.Checkpoints != 1 {
		t.Errorf("audit = %+v", rep)
	}
	if got := leafTypes(t, r.LogDir(), n+1)[1000]; got != 'C' {
		t.Errorf("leaf 1000 is %c, want C", got)
	}
}
