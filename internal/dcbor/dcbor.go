// Package dcbor provides the deterministic CBOR encoding used by every
// Kirowen structure (RFC 8949 §4.2.1, core deterministic encoding).
//
// Decoding is strict: input is accepted only if re-encoding the decoded
// value reproduces the input byte for byte. That single check rejects
// unsorted map keys, non-shortest integers, indefinite lengths, unknown or
// missing fields, and any other encoding that a different implementation
// could produce for the same value.
package dcbor

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ErrNotDeterministic is returned when input decodes but is not the
// canonical encoding of the decoded value.
var ErrNotDeterministic = errors.New("dcbor: input is not in canonical deterministic encoding")

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	decMode, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsAllowed,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// Marshal encodes v in core deterministic encoding.
func Marshal(v any) ([]byte, error) {
	return encMode.Marshal(v)
}

// Unmarshal decodes data into v and then checks that data is exactly the
// deterministic encoding of v. Trailing bytes are rejected.
func Unmarshal(data []byte, v any) error {
	if err := decMode.Unmarshal(data, v); err != nil {
		return fmt.Errorf("dcbor: %w", err)
	}
	again, err := encMode.Marshal(v)
	if err != nil {
		return fmt.Errorf("dcbor: re-encode: %w", err)
	}
	if !bytes.Equal(again, data) {
		return ErrNotDeterministic
	}
	return nil
}
