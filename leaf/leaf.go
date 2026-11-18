// Package leaf implements Kirowen log leaves (docs/envelope-v0.md §4 and
// §5.1): a deterministic CBOR array [1, type, body].
package leaf

import (
	"crypto"
	_ "crypto/sha256" // registers SHA-256 for the RFC 6962 hasher
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/pasta0126/kirowen/internal/dcbor"
)

// FormatVersion is the leaf format version.
const FormatVersion = 1

// Type is a leaf type.
type Type uint64

const (
	// TypeEvent is an ordinary event leaf; its body is an envelope_hash.
	TypeEvent Type = 1
	// TypeCheckpoint is an internal checkpoint leaf; it is not ordinary.
	TypeCheckpoint Type = 2
)

const hashSize = 32

var (
	ErrMalformed = errors.New("leaf: malformed")
	ErrInvalid   = errors.New("leaf: invalid")
)

// Checkpoint is the body of an internal checkpoint leaf (§5.1).
type Checkpoint struct {
	Size     uint64 `cbor:"1,keyasint"`
	Root     []byte `cbor:"2,keyasint"`
	PrevSize uint64 `cbor:"3,keyasint"`
	PrevRoot []byte `cbor:"4,keyasint,omitempty"`
	Note     []byte `cbor:"5,keyasint"`
}

// Validate checks the checkpoint's field formats.
func (c *Checkpoint) Validate() error {
	switch {
	case len(c.Root) != hashSize:
		return fmt.Errorf("%w: root has %d bytes", ErrInvalid, len(c.Root))
	case c.Size <= c.PrevSize:
		return fmt.Errorf("%w: size %d not greater than prev_size %d", ErrInvalid, c.Size, c.PrevSize)
	case c.PrevSize == 0 && c.PrevRoot != nil:
		return fmt.Errorf("%w: prev_root must be absent for the first checkpoint", ErrInvalid)
	case c.PrevSize > 0 && len(c.PrevRoot) != hashSize:
		return fmt.Errorf("%w: prev_root must have %d bytes", ErrInvalid, hashSize)
	case len(c.Note) == 0:
		return fmt.Errorf("%w: note is empty", ErrInvalid)
	}
	return nil
}

// Leaf is a decoded leaf. Exactly one of EnvelopeHash and Checkpoint is
// set, according to Type.
type Leaf struct {
	Type         Type
	EnvelopeHash []byte
	Checkpoint   *Checkpoint
}

// Ordinary reports whether the leaf counts toward the 1,000 ordinary
// events between internal checkpoints.
func (l *Leaf) Ordinary() bool { return l.Type == TypeEvent }

type wire struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	Type    Type
	Body    cbor.RawMessage
}

// Event returns the encoded event leaf for an envelope hash.
func Event(envelopeHash []byte) ([]byte, error) {
	if len(envelopeHash) != hashSize {
		return nil, fmt.Errorf("%w: envelope hash has %d bytes", ErrInvalid, len(envelopeHash))
	}
	body, err := dcbor.Marshal(envelopeHash)
	if err != nil {
		return nil, err
	}
	return dcbor.Marshal(wire{Version: FormatVersion, Type: TypeEvent, Body: body})
}

// NewCheckpoint returns the encoded checkpoint leaf for c.
func NewCheckpoint(c Checkpoint) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	body, err := dcbor.Marshal(c)
	if err != nil {
		return nil, err
	}
	return dcbor.Marshal(wire{Version: FormatVersion, Type: TypeCheckpoint, Body: body})
}

// Parse decodes and validates a leaf.
func Parse(b []byte) (*Leaf, error) {
	var w wire
	if err := dcbor.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if w.Version != FormatVersion {
		return nil, fmt.Errorf("%w: format version %d", ErrInvalid, w.Version)
	}
	l := &Leaf{Type: w.Type}
	switch w.Type {
	case TypeEvent:
		if err := dcbor.Unmarshal(w.Body, &l.EnvelopeHash); err != nil {
			return nil, fmt.Errorf("%w: event body: %w", ErrMalformed, err)
		}
		if len(l.EnvelopeHash) != hashSize {
			return nil, fmt.Errorf("%w: envelope hash has %d bytes", ErrInvalid, len(l.EnvelopeHash))
		}
	case TypeCheckpoint:
		l.Checkpoint = new(Checkpoint)
		if err := dcbor.Unmarshal(w.Body, l.Checkpoint); err != nil {
			return nil, fmt.Errorf("%w: checkpoint body: %w", ErrMalformed, err)
		}
		if err := l.Checkpoint.Validate(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: unknown type %d", ErrInvalid, w.Type)
	}
	return l, nil
}

var hasher = rfc6962.New(crypto.SHA256)

// Hash returns the RFC 6962 leaf hash, SHA-256(0x00 ‖ leaf).
func Hash(leaf []byte) []byte { return hasher.HashLeaf(leaf) }
