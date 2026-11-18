package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/pasta0126/kirowen/internal/dcbor"
)

// KeyActionAdd is the only key action so far. Rotation and revocation
// ("revoke") will follow.
const KeyActionAdd = "add"

// SystemSource is the reserved source id of the system source (16 zero
// bytes). Its events register source keys.
var SystemSource = make([]byte, IDSize)

// KeyStatement is a key registration statement (docs/envelope-v0.md §6).
// The registry logs a system-source event whose digest is the SHA-256 of
// the statement's deterministic CBOR encoding, and publishes the
// statement, so anyone can check which key a source had at which point.
type KeyStatement struct {
	Source    []byte `cbor:"1,keyasint"`
	PublicKey []byte `cbor:"2,keyasint"`
	Alg       int64  `cbor:"3,keyasint"`
	Action    string `cbor:"4,keyasint"`
}

// Encode validates and encodes the statement.
func (k KeyStatement) Encode() ([]byte, error) {
	if len(k.Source) != IDSize || len(k.PublicKey) != ed25519.PublicKeySize || k.Alg != AlgEdDSA || k.Action != KeyActionAdd {
		return nil, fmt.Errorf("%w: key statement", ErrInvalidField)
	}
	return dcbor.Marshal(k)
}

// ParseKeyStatement decodes a statement strictly.
func ParseKeyStatement(b []byte) (*KeyStatement, error) {
	var k KeyStatement
	if err := dcbor.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("%w: key statement: %w", ErrMalformed, err)
	}
	if _, err := k.Encode(); err != nil {
		return nil, err
	}
	return &k, nil
}

// StatementDigest returns the digest logged for an encoded statement.
func StatementDigest(encoded []byte) Digest {
	h := sha256.Sum256(encoded)
	return Digest{Alg: AlgSHA256, Value: h[:]}
}

// RegistrationMessage is what a new source signs to prove it holds the
// private key it registers. The origin binds the proof to one log.
func RegistrationMessage(origin string, pub ed25519.PublicKey) []byte {
	return fmt.Appendf(nil, "kirowen register v0\n%s\n%x\n", origin, []byte(pub))
}
