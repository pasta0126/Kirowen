package leaf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestEventRoundTrip(t *testing.T) {
	h := bytes.Repeat([]byte{0xab}, 32)
	b, err := Event(h)
	if err != nil {
		t.Fatal(err)
	}
	// [1, 1, h'ab…ab'] = 83 01 01 58 20 ab…
	want := "83010158 20" + hex.EncodeToString(h)
	if got := hex.EncodeToString(b); got != stripSpaces(want) {
		t.Fatalf("encoding = %s, want %s", got, stripSpaces(want))
	}
	l, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if l.Type != TypeEvent || !l.Ordinary() || !bytes.Equal(l.EnvelopeHash, h) {
		t.Fatalf("unexpected leaf %+v", l)
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	c := Checkpoint{Size: 1000, Root: bytes.Repeat([]byte{1}, 32), Note: []byte("note")}
	b, err := NewCheckpoint(c)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if l.Ordinary() || l.Checkpoint == nil || l.Checkpoint.Size != 1000 {
		t.Fatalf("unexpected leaf %+v", l)
	}

	next := Checkpoint{Size: 2001, Root: bytes.Repeat([]byte{2}, 32), PrevSize: 1000, PrevRoot: c.Root, Note: []byte("n")}
	if _, err := NewCheckpoint(next); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointInvalid(t *testing.T) {
	root := bytes.Repeat([]byte{1}, 32)
	for name, c := range map[string]Checkpoint{
		"short root":              {Size: 1, Root: root[:31], Note: []byte("n")},
		"size not increasing":     {Size: 5, Root: root, PrevSize: 5, PrevRoot: root, Note: []byte("n")},
		"first with prev_root":    {Size: 5, Root: root, PrevRoot: root, Note: []byte("n")},
		"later without prev_root": {Size: 9, Root: root, PrevSize: 5, Note: []byte("n")},
		"empty note":              {Size: 5, Root: root},
	} {
		if _, err := NewCheckpoint(c); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	h := hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	for name, in := range map[string]string{
		"version 2":        "830201 5820" + h,
		"unknown type":     "830103 5820" + h,
		"short hash":       "830101 581f" + h[2:],
		"non-shortest int": "83180101 5820" + h,
		"trailing byte":    "830101 5820" + h + "00",
		"two elements":     "8201 01",
	} {
		b, _ := hex.DecodeString(stripSpaces(in))
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHash(t *testing.T) {
	// RFC 6962: leaf hash of the empty leaf is SHA-256(0x00).
	got := hex.EncodeToString(Hash(nil))
	if want := "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"; got != want {
		t.Fatalf("Hash(empty) = %s, want %s", got, want)
	}
}

func stripSpaces(s string) string {
	return string(bytes.ReplaceAll([]byte(s), []byte(" "), nil))
}
