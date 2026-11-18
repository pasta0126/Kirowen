package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/pasta0126/kirowen/internal/dcbor"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

// fixed returns n bytes all equal to b, for readable test vectors.
func fixed(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(fixed(seed, ed25519.SeedSize))
}

func basePayload() Payload {
	return Payload{
		Version: Version,
		Source:  fixed(0x11, IDSize),
		Object:  fixed(0x22, IDSize),
		Digest:  Digest{Alg: AlgSHA256, Value: fixed(0x33, HashSize)},
	}
}

type vector struct {
	Name         string `json:"name"`
	Seed         string `json:"seed"`
	PublicKey    string `json:"public_key"`
	KeyID        string `json:"key_id"`
	Payload      string `json:"payload"`
	Envelope     string `json:"envelope"`
	EnvelopeHash string `json:"envelope_hash"`
}

func vectorCases() []struct {
	name    string
	seed    byte
	payload Payload
} {
	first := basePayload()

	second := basePayload()
	second.ObjectSeq = 1
	second.KeySeq = 1
	second.Prev = fixed(0x44, HashSize)
	t := int64(1_795_000_000_000)
	second.Time = &t
	second.Refs = [][]byte{fixed(0x55, HashSize), fixed(0x66, HashSize)}

	return []struct {
		name    string
		seed    byte
		payload Payload
	}{
		{"first-event-minimal", 0x01, first},
		{"later-event-all-fields", 0x01, second},
	}
}

func TestVectors(t *testing.T) {
	path := filepath.Join("testdata", "vectors.json")
	var got []vector
	for _, c := range vectorCases() {
		priv := testKey(c.seed)
		pub := priv.Public().(ed25519.PublicKey)
		raw, err := Sign(c.payload, priv)
		if err != nil {
			t.Fatalf("%s: Sign: %v", c.name, err)
		}
		payload, _ := dcbor.Marshal(c.payload)
		kid := KeyID(pub)
		h := sha256.Sum256(raw)
		got = append(got, vector{
			Name:         c.name,
			Seed:         hex.EncodeToString(fixed(c.seed, ed25519.SeedSize)),
			PublicKey:    hex.EncodeToString(pub),
			KeyID:        hex.EncodeToString(kid[:]),
			Payload:      hex.EncodeToString(payload),
			Envelope:     hex.EncodeToString(raw),
			EnvelopeHash: hex.EncodeToString(h[:]),
		})

		e, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: Parse: %v", c.name, err)
		}
		if err := e.Verify(pub); err != nil {
			t.Fatalf("%s: Verify: %v", c.name, err)
		}
		if e.Hash != h {
			t.Errorf("%s: Hash mismatch", c.name)
		}
	}

	if *update {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	var want []vector
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(got) {
		t.Fatalf("got %d vectors, file has %d", len(got), len(want))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("vector %q changed:\n got %+v\nwant %+v", want[i].Name, got[i], want[i])
		}
	}
}

func TestSignIsDeterministic(t *testing.T) {
	a, err := Sign(basePayload(), testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Sign(basePayload(), testKey(1))
	if !bytes.Equal(a, b) {
		t.Fatal("same inputs produced different envelopes")
	}
}

func TestVerifyRejects(t *testing.T) {
	priv := testKey(1)
	raw, err := Sign(basePayload(), priv)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	other := testKey(2).Public().(ed25519.PublicKey)
	if err := e.Verify(other); !errors.Is(err, ErrWrongKey) {
		t.Errorf("other key: got %v, want ErrWrongKey", err)
	}

	// Flip one signature bit: still parses, fails verification.
	bad := bytes.Clone(raw)
	bad[len(bad)-1] ^= 1
	e2, err := Parse(bad)
	if err != nil {
		t.Fatalf("Parse(flipped signature): %v", err)
	}
	if err := e2.Verify(priv.Public().(ed25519.PublicKey)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("flipped signature: got %v, want ErrBadSignature", err)
	}
}

// --- Hand-built messages, to exercise encodings Sign never produces. ---

func sigStructure(protected, payload []byte) []byte {
	b, err := dcbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		panic(err)
	}
	return b
}

// build assembles a tagged COSE_Sign1 with a valid signature over the
// given (possibly non-canonical) protected header and payload bytes.
func build(t *testing.T, protected, unprotected, payload []byte, tagged bool) []byte {
	t.Helper()
	sig := ed25519.Sign(testKey(1), sigStructure(protected, payload))
	arr := []any{protected, cbor.RawMessage(unprotected), payload, sig}
	var v any = arr
	if tagged {
		v = cbor.Tag{Number: cborTagSign1, Content: arr}
	}
	b, err := dcbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goodProtected() []byte {
	kid := KeyID(testKey(1).Public().(ed25519.PublicKey))
	b, _ := dcbor.Marshal(protectedHeader{Alg: AlgEdDSA, ContentType: ContentType, KeyID: kid[:]})
	return b
}

func goodPayload() []byte {
	b, _ := dcbor.Marshal(basePayload())
	return b
}

func payloadMap(mut func(m map[int]any)) []byte {
	p := basePayload()
	m := map[int]any{
		1: p.Version, 2: p.Source, 3: p.Object, 4: uint64(0), 6: uint64(0),
		8: []any{int64(AlgSHA256), p.Digest.Value},
	}
	if mut != nil {
		mut(m)
	}
	b, err := dcbor.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseRejects(t *testing.T) {
	empty := []byte{0xa0}
	good := build(t, goodProtected(), empty, goodPayload(), true)
	if _, err := Parse(good); err != nil {
		t.Fatalf("hand-built good envelope rejected: %v", err)
	}
	// Sanity: hand-built and Sign agree byte for byte.
	if signed, _ := Sign(basePayload(), testKey(1)); !bytes.Equal(signed, good) {
		t.Fatal("hand-built envelope differs from Sign output")
	}

	// Payload with key 1 encoded as a non-shortest integer (0x18 0x01).
	nonShortest := bytes.Replace(goodPayload(), []byte{0x01, 0x01}, []byte{0x01, 0x18, 0x01}, 1)

	// Payload with keys 1 and 2 swapped (unsorted map).
	unsorted := func() []byte {
		p := goodPayload()
		// a6 01 01 02 50 <16> ... -> a6 02 50 <16> 01 01 ...
		head, src := p[1:3], p[3:3+2+IDSize]
		out := append([]byte{p[0]}, src...)
		out = append(out, head...)
		return append(out, p[3+2+IDSize:]...)
	}()

	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"untagged", build(t, goodProtected(), empty, goodPayload(), false), ErrMalformed},
		{"trailing byte", append(bytes.Clone(good), 0x00), ErrMalformed},
		{"too large", append(bytes.Clone(good), make([]byte, MaxSize)...), ErrTooLarge},
		{"non-empty unprotected", build(t, goodProtected(), []byte{0xa1, 0x04, 0x41, 0x00}, goodPayload(), true), ErrMalformed},
		{"payload non-shortest int", build(t, goodProtected(), empty, nonShortest, true), ErrMalformed},
		{"payload unsorted keys", build(t, goodProtected(), empty, unsorted, true), ErrMalformed},
		{"payload unknown key", build(t, goodProtected(), empty, payloadMap(func(m map[int]any) { m[10] = 1 }), true), ErrMalformed},
		{"payload missing kseq", build(t, goodProtected(), empty, payloadMap(func(m map[int]any) { delete(m, 6) }), true), ErrMalformed},
		{"payload empty refs", build(t, goodProtected(), empty, payloadMap(func(m map[int]any) { m[9] = []any{} }), true), ErrMalformed},
		{"version 2", build(t, goodProtected(), empty, payloadMap(func(m map[int]any) { m[1] = 2 }), true), ErrInvalidField},
		{"short src", build(t, goodProtected(), empty, payloadMap(func(m map[int]any) { m[2] = fixed(1, 15) }), true), ErrInvalidField},
		{"digest wrong length", build(t, goodProtected(), empty, payloadMap(func(m map[int]any) { m[8] = []any{int64(AlgSHA256), fixed(1, 31)} }), true), ErrInvalidField},
		{"digest unknown alg", build(t, goodProtected(), empty, payloadMap(func(m map[int]any) { m[8] = []any{int64(-43), fixed(1, 48)} }), true), ErrInvalidField},
		{"prev with oseq 0", build(t, goodProtected(), empty, payloadMap(func(m map[int]any) { m[5] = fixed(1, 32) }), true), ErrInvalidField},
		{"oseq 1 without prev", build(t, goodProtected(), empty, payloadMap(func(m map[int]any) { m[4] = 1 }), true), ErrInvalidField},
		{"nine refs", build(t, goodProtected(), empty, payloadMap(func(m map[int]any) {
			refs := make([]any, 9)
			for i := range refs {
				refs[i] = fixed(byte(i), 32)
			}
			m[9] = refs
		}), true), ErrInvalidField},
		{"wrong content type", build(t, func() []byte {
			kid := KeyID(testKey(1).Public().(ed25519.PublicKey))
			b, _ := dcbor.Marshal(protectedHeader{Alg: AlgEdDSA, ContentType: "application/json", KeyID: kid[:]})
			return b
		}(), empty, goodPayload(), true), ErrInvalidField},
		{"wrong alg", build(t, func() []byte {
			kid := KeyID(testKey(1).Public().(ed25519.PublicKey))
			b, _ := dcbor.Marshal(protectedHeader{Alg: -7, ContentType: ContentType, KeyID: kid[:]})
			return b
		}(), empty, goodPayload(), true), ErrInvalidField},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.raw)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}
