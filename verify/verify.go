// Package verify holds the checks a Kirowen verifier runs without trusting
// the registry: tree head signatures, inclusion of an event, consistency
// between two tree heads, and a full audit of the log's internal
// checkpoints.
//
// What these checks guarantee, and under which assumptions, is described
// in docs/technical-analysis.md §2–§3. In short: a verifier that holds an
// earlier tree head detects any rewrite of the history it covers. Without
// an independently held tree head (a witness, an anchor, or one saved by
// the verifier), a registry that rebuilds its whole log from scratch is not
// detected by these checks alone.
package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"

	"github.com/pasta0126/kirowen/envelope"
	"github.com/pasta0126/kirowen/leaf"
)

// Log is read access to a published log, e.g. client.FileFetcher or
// *client.HTTPFetcher.
type Log interface {
	ReadCheckpoint(ctx context.Context) ([]byte, error)
	ReadTile(ctx context.Context, level, index uint64, p uint8) ([]byte, error)
	ReadEntryBundle(ctx context.Context, index uint64, p uint8) ([]byte, error)
}

// Errors that indicate the registry misbehaved (as opposed to I/O errors).
var (
	ErrInclusion     = errors.New("verify: event is not included in the tree head")
	ErrInconsistent  = errors.New("verify: tree heads are inconsistent (history was rewritten)")
	ErrBadCheckpoint = errors.New("verify: invalid internal checkpoint leaf")
)

// TreeHead verifies a signed tree head and returns it.
func TreeHead(raw []byte, origin string, v note.Verifier) (*log.Checkpoint, error) {
	c, _, _, err := log.ParseCheckpoint(raw, origin, v)
	if err != nil {
		return nil, fmt.Errorf("verify: tree head: %w", err)
	}
	return c, nil
}

// Event verifies a proof bundle offline: the envelope's signature under
// pub, the tree head's signature, and the inclusion of the envelope's
// leaf at leafIndex in that tree head.
func Event(env []byte, pub ed25519.PublicKey, leafIndex uint64, treeHead []byte, inclusion [][]byte, origin string, v note.Verifier) (*envelope.Envelope, *log.Checkpoint, error) {
	e, err := envelope.Parse(env)
	if err != nil {
		return nil, nil, err
	}
	if err := e.Verify(pub); err != nil {
		return nil, nil, err
	}
	th, err := TreeHead(treeHead, origin, v)
	if err != nil {
		return nil, nil, err
	}
	lb, err := leaf.Event(e.Hash[:])
	if err != nil {
		return nil, nil, err
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, leafIndex, th.Size, leaf.Hash(lb), inclusion, th.Hash); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInclusion, err)
	}
	return e, th, nil
}

// Consistency checks that the tree head newer extends older, fetching
// the consistency proof from l. Both must already be verified.
func Consistency(ctx context.Context, l Log, older, newer *log.Checkpoint) error {
	if older.Size > newer.Size {
		older, newer = newer, older
	}
	if older.Size == newer.Size {
		if !bytes.Equal(older.Hash, newer.Hash) {
			return fmt.Errorf("%w: two roots for size %d", ErrInconsistent, older.Size)
		}
		return nil
	}
	if older.Size == 0 {
		return nil
	}
	pb, err := client.NewProofBuilder(ctx, newer.Size, l.ReadTile)
	if err != nil {
		return err
	}
	p, err := pb.ConsistencyProof(ctx, older.Size, newer.Size)
	if err != nil {
		return err
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, older.Size, newer.Size, p, older.Hash, newer.Hash); err != nil {
		return fmt.Errorf("%w: %w", ErrInconsistent, err)
	}
	return nil
}

// AuditReport summarizes a full audit.
type AuditReport struct {
	Size        uint64 // tree size audited
	Ordinary    uint64 // ordinary (event) leaves
	Checkpoints uint64 // internal checkpoint leaves
}

// Audit downloads every leaf of the log up to its current tree head and
// checks that:
//   - every leaf is well formed;
//   - the recomputed root matches the published tree head;
//   - every checkpoint leaf sits right after exactly `every` ordinary
//     leaves, certifies the tree before it (size and root), carries a
//     valid signed tree head for that size, and links to the previous one;
//   - at most `every` ordinary leaves follow the last checkpoint leaf.
//
// This is what a monitor runs. It needs no access to envelopes.
func Audit(ctx context.Context, l Log, origin string, v note.Verifier, every uint64) (*AuditReport, error) {
	raw, err := l.ReadCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	th, err := TreeHead(raw, origin, v)
	if err != nil {
		return nil, err
	}

	rf := &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	tree := rf.NewEmptyRange(0)
	rep := &AuditReport{Size: th.Size}
	var sinceCP, prevSize uint64
	var prevRoot []byte

	bad := func(i uint64, format string, args ...any) error {
		return fmt.Errorf("%w: leaf %d: %s", ErrBadCheckpoint, i, fmt.Sprintf(format, args...))
	}
	for i := uint64(0); i < th.Size; {
		bundle, err := client.GetEntryBundle(ctx, l.ReadEntryBundle, i/256, th.Size)
		if err != nil {
			return nil, err
		}
		for _, raw := range bundle.Entries {
			if i >= th.Size {
				break
			}
			lf, err := leaf.Parse(raw)
			if err != nil {
				return nil, fmt.Errorf("verify: leaf %d: %w", i, err)
			}
			if lf.Type == leaf.TypeCheckpoint {
				cp := lf.Checkpoint
				root, err := rootOf(tree)
				if err != nil {
					return nil, err
				}
				switch {
				case sinceCP != every:
					return nil, bad(i, "%d ordinary leaves since the previous checkpoint, want %d", sinceCP, every)
				case cp.Size != i:
					return nil, bad(i, "certifies size %d", cp.Size)
				case !bytes.Equal(cp.Root, root):
					return nil, bad(i, "root does not match the tree")
				case cp.PrevSize != prevSize || !bytes.Equal(cp.PrevRoot, prevRoot):
					return nil, bad(i, "does not link to the previous checkpoint")
				}
				noteCP, err := TreeHead(cp.Note, origin, v)
				if err != nil {
					return nil, bad(i, "note: %v", err)
				}
				if noteCP.Size != cp.Size || !bytes.Equal(noteCP.Hash, cp.Root) {
					return nil, bad(i, "note does not match size and root")
				}
				sinceCP, prevSize, prevRoot = 0, cp.Size, cp.Root
				rep.Checkpoints++
			} else {
				sinceCP++
				rep.Ordinary++
				if sinceCP > every {
					return nil, bad(i, "more than %d ordinary leaves without a checkpoint", every)
				}
			}
			if err := tree.Append(leaf.Hash(raw), nil); err != nil {
				return nil, err
			}
			i++
		}
	}
	root, err := rootOf(tree)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(root, th.Hash) {
		return nil, fmt.Errorf("%w: recomputed root does not match the tree head", ErrInconsistent)
	}
	return rep, nil
}

func rootOf(r *compact.Range) ([]byte, error) {
	if r.End() == 0 {
		return rfc6962.DefaultHasher.EmptyRoot(), nil
	}
	return r.GetRootHash(nil)
}
