// Package envelope implements the Kirowen event envelope defined in
// docs/envelope-v0.md §3: a COSE_Sign1 structure (RFC 9052), signed by the
// source with Ed25519, whose payload is a deterministic CBOR map.
//
// This package checks only the stateless acceptance rules (rules 1 and 6,
// plus field formats and the signature). The stateful rules (key validity,
// object ownership, oseq/prev, kseq, refs and quotas) need registry state
// and are enforced by the registry.
package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/pasta0126/kirowen/internal/dcbor"
)

const (
	// Version is the only envelope version defined so far.
	Version = 1

	// ContentType is the COSE content type of an envelope.
	ContentType = "application/vnd.kirowen.envelope+cbor"

	// MaxSize is the maximum size of an encoded envelope, in bytes.
	MaxSize = 1024

	// MaxRefs is the maximum number of entries in refs.
	MaxRefs = 8

	// AlgSHA256 is the COSE algorithm id for SHA-256 (RFC 9054).
	AlgSHA256 = -16

	// AlgEdDSA is the COSE algorithm id for EdDSA (RFC 9053).
	AlgEdDSA = -8

	// IDSize is the size of source and object ids.
	IDSize = 16

	// HashSize is the size of SHA-256 digests, key ids and envelope hashes.
	HashSize = sha256.Size

	// cborTagSign1 is the CBOR tag of a COSE_Sign1 message.
	cborTagSign1 = 18
)

// Errors returned by Parse and Verify. Callers can match them with
// errors.Is; the returned errors wrap them with details.
var (
	ErrTooLarge     = errors.New("envelope: larger than 1 KiB")
	ErrMalformed    = errors.New("envelope: malformed")
	ErrInvalidField = errors.New("envelope: invalid field")
	ErrWrongKey     = errors.New("envelope: kid does not match the given public key")
	ErrBadSignature = errors.New("envelope: signature verification failed")
)

// Digest is a content digest: [alg, value].
type Digest struct {
	_     struct{} `cbor:",toarray"`
	Alg   int64
	Value []byte
}

// Payload is the envelope payload (docs/envelope-v0.md §3.2).
type Payload struct {
	Version   uint64   `cbor:"1,keyasint"`
	Source    []byte   `cbor:"2,keyasint"`
	Object    []byte   `cbor:"3,keyasint"`
	ObjectSeq uint64   `cbor:"4,keyasint"`
	Prev      []byte   `cbor:"5,keyasint,omitempty"`
	KeySeq    uint64   `cbor:"6,keyasint"`
	Time      *int64   `cbor:"7,keyasint,omitempty"`
	Digest    Digest   `cbor:"8,keyasint"`
	Refs      [][]byte `cbor:"9,keyasint,omitempty"`
}

// Validate checks the field formats that do not depend on registry state.
func (p *Payload) Validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidField, fmt.Sprintf(format, args...))
	}
	if p.Version != Version {
		return bad("v = %d, want %d", p.Version, Version)
	}
	if len(p.Source) != IDSize {
		return bad("src has %d bytes, want %d", len(p.Source), IDSize)
	}
	if len(p.Object) != IDSize {
		return bad("obj has %d bytes, want %d", len(p.Object), IDSize)
	}
	switch {
	case p.ObjectSeq == 0 && p.Prev != nil:
		return bad("prev must be absent when oseq = 0")
	case p.ObjectSeq > 0 && len(p.Prev) != HashSize:
		return bad("prev must have %d bytes when oseq > 0", HashSize)
	}
	if p.Digest.Alg != AlgSHA256 {
		return bad("unsupported digest alg %d", p.Digest.Alg)
	}
	if len(p.Digest.Value) != HashSize {
		return bad("digest value has %d bytes, want %d", len(p.Digest.Value), HashSize)
	}
	if p.Refs != nil && len(p.Refs) == 0 {
		return bad("refs must be absent rather than empty")
	}
	if len(p.Refs) > MaxRefs {
		return bad("%d refs, at most %d allowed", len(p.Refs), MaxRefs)
	}
	for i, r := range p.Refs {
		if len(r) != HashSize {
			return bad("refs[%d] has %d bytes, want %d", i, len(r), HashSize)
		}
	}
	return nil
}

// protectedHeader is the COSE protected header (docs/envelope-v0.md §3.1).
type protectedHeader struct {
	Alg         int64  `cbor:"1,keyasint"`
	ContentType string `cbor:"3,keyasint"`
	KeyID       []byte `cbor:"4,keyasint"`
}

// sign1 is the content of a tagged COSE_Sign1 message.
type sign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int64]cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// Envelope is a parsed envelope. Parse checks its structure; Verify checks
// its signature.
type Envelope struct {
	// Raw is the exact encoded COSE_Sign1 message.
	Raw []byte
	// Hash is envelope_hash = SHA-256(Raw).
	Hash [HashSize]byte
	// KeyID is the kid of the signing key, SHA-256(public key).
	KeyID [HashSize]byte
	// Payload is the decoded payload.
	Payload Payload
}

// KeyID returns the key id of an Ed25519 public key: SHA-256(public key).
func KeyID(pub ed25519.PublicKey) [HashSize]byte {
	return sha256.Sum256(pub)
}

// Sign validates p, encodes it and signs it with priv. It returns the
// encoded envelope. Ed25519 is deterministic, so the same inputs always
// produce the same bytes.
func Sign(p Payload, priv ed25519.PrivateKey) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	payload, err := dcbor.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("envelope: encode payload: %w", err)
	}
	kid := KeyID(priv.Public().(ed25519.PublicKey))

	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected = cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm:   cose.AlgorithmEdDSA,
		cose.HeaderLabelContentType: ContentType,
		cose.HeaderLabelKeyID:       kid[:],
	}
	msg.Payload = payload
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("envelope: sign: %w", err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("envelope: encode message: %w", err)
	}
	// Self-check: what we emit must be what we accept.
	if _, err := Parse(raw); err != nil {
		return nil, fmt.Errorf("envelope: produced an envelope that does not parse: %w", err)
	}
	return raw, nil
}

// Parse decodes an envelope and checks everything that can be checked
// without registry state and without the public key: size, deterministic
// encoding of every layer, header values and payload field formats.
// It does not verify the signature; call Verify for that.
func Parse(raw []byte) (*Envelope, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(raw))
	}
	malformed := func(what string, err error) error {
		return fmt.Errorf("%w: %s: %w", ErrMalformed, what, err)
	}

	var tag cbor.RawTag
	if err := dcbor.Unmarshal(raw, &tag); err != nil {
		return nil, malformed("message", err)
	}
	if tag.Number != cborTagSign1 {
		return nil, malformed("message", fmt.Errorf("CBOR tag %d, want %d (COSE_Sign1)", tag.Number, cborTagSign1))
	}
	var msg sign1
	if err := dcbor.Unmarshal(tag.Content, &msg); err != nil {
		return nil, malformed("COSE_Sign1", err)
	}
	if len(msg.Unprotected) != 0 {
		return nil, malformed("COSE_Sign1", errors.New("unprotected header must be empty"))
	}
	if msg.Payload == nil {
		return nil, malformed("COSE_Sign1", errors.New("detached payload not allowed"))
	}
	if len(msg.Signature) != ed25519.SignatureSize {
		return nil, malformed("COSE_Sign1", fmt.Errorf("signature has %d bytes", len(msg.Signature)))
	}

	var hdr protectedHeader
	if err := dcbor.Unmarshal(msg.Protected, &hdr); err != nil {
		return nil, malformed("protected header", err)
	}
	if hdr.Alg != AlgEdDSA {
		return nil, fmt.Errorf("%w: alg %d, want %d (EdDSA)", ErrInvalidField, hdr.Alg, AlgEdDSA)
	}
	if hdr.ContentType != ContentType {
		return nil, fmt.Errorf("%w: content type %q", ErrInvalidField, hdr.ContentType)
	}
	if len(hdr.KeyID) != HashSize {
		return nil, fmt.Errorf("%w: kid has %d bytes, want %d", ErrInvalidField, len(hdr.KeyID), HashSize)
	}

	e := &Envelope{Raw: bytes.Clone(raw), Hash: sha256.Sum256(raw)}
	copy(e.KeyID[:], hdr.KeyID)
	if err := dcbor.Unmarshal(msg.Payload, &e.Payload); err != nil {
		return nil, malformed("payload", err)
	}
	if err := e.Payload.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// Verify checks that pub is the key named by kid and that the signature
// is valid for pub. Whether pub is an active key of the payload's source
// is a registry check (acceptance rule 2).
func (e *Envelope) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key has %d bytes", ErrWrongKey, len(pub))
	}
	if KeyID(pub) != e.KeyID {
		return ErrWrongKey
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, pub)
	if err != nil {
		return fmt.Errorf("envelope: %w", err)
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(e.Raw); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	return nil
}
