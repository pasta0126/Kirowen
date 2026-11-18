// Command kirowen is the phase 0 command-line tool: key generation,
// recording files in a local registry, verifying receipts and auditing a
// log. There is no network API yet; "add" opens the registry directory
// directly.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"

	"github.com/pasta0126/kirowen/envelope"
	"github.com/pasta0126/kirowen/registry"
	"github.com/pasta0126/kirowen/verify"
)

const usage = `usage:
  kirowen keygen-log -origin ORIGIN -out NAME     write NAME.key (secret) and NAME.pub
  kirowen keygen     -out NAME                    write a source key: NAME.key (secret) and NAME.pub
  kirowen init   -data DIR -log-key F            create an empty log (publishes the size-0 tree head)
  kirowen add    -data DIR -log-key F -key F [-object HEX] FILE...
                                                  record files; writes FILE.receipt.json
  kirowen verify -log DIR|URL -log-pub F -pub F RECEIPT [FILE]
                                                  verify a receipt (and the file, if given)
  kirowen audit  -log DIR|URL -log-pub F          check the whole log and its checkpoints
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"keygen-log": keygenLog, "keygen": keygen, "init": initCmd, "add": add, "verify": verifyCmd, "audit": audit,
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "kirowen:", err)
		os.Exit(1)
	}
}

// --- keys ---

// sourceKey is the on-disk source key. In phase 0 the source id is chosen
// locally; from phase 2 the registry assigns it at registration.
type sourceKey struct {
	SourceID string `json:"source_id"`
	Seed     string `json:"ed25519_seed,omitempty"`
	Public   string `json:"ed25519_public"`
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func keygenLog(args []string) error {
	fs := flag.NewFlagSet("keygen-log", flag.ExitOnError)
	origin := fs.String("origin", "", "log origin, e.g. example.com/log/v0")
	out := fs.String("out", "log", "output file prefix")
	fs.Parse(args)
	if *origin == "" {
		return errors.New("-origin is required")
	}
	skey, vkey, err := note.GenerateKey(rand.Reader, *origin)
	if err != nil {
		return err
	}
	if err := writeNew(*out+".key", []byte(skey+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeNew(*out+".pub", []byte(vkey+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Println(vkey)
	return nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "source", "output file prefix")
	fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	id := make([]byte, envelope.IDSize)
	rand.Read(id)
	k := sourceKey{SourceID: hex.EncodeToString(id), Seed: hex.EncodeToString(priv.Seed()), Public: hex.EncodeToString(pub)}
	sec, _ := json.MarshalIndent(k, "", "  ")
	k.Seed = ""
	pb, _ := json.MarshalIndent(k, "", "  ")
	if err := writeNew(*out+".key", append(sec, '\n'), 0o600); err != nil {
		return err
	}
	if err := writeNew(*out+".pub", append(pb, '\n'), 0o644); err != nil {
		return err
	}
	kid := envelope.KeyID(pub)
	fmt.Printf("source_id %s\nkey_id    %x\n", k.SourceID, kid)
	return nil
}

func readSourceKey(path string) (sourceKey, error) {
	var k sourceKey
	b, err := os.ReadFile(path)
	if err != nil {
		return k, err
	}
	return k, json.Unmarshal(b, &k)
}

func (k sourceKey) public() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(k.Public)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("bad ed25519_public")
	}
	return b, nil
}

func (k sourceKey) private() (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(k.Seed)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("bad ed25519_seed (is this a .pub file?)")
	}
	return ed25519.NewKeyFromSeed(b), nil
}

func readLogKeys(skeyPath, vkeyPath string) (note.Signer, note.Verifier, error) {
	var s note.Signer
	if skeyPath != "" {
		b, err := os.ReadFile(skeyPath)
		if err != nil {
			return nil, nil, err
		}
		if s, err = note.NewSigner(strings.TrimSpace(string(b))); err != nil {
			return nil, nil, err
		}
	}
	b, err := os.ReadFile(vkeyPath)
	if err != nil {
		return nil, nil, err
	}
	v, err := note.NewVerifier(strings.TrimSpace(string(b)))
	return s, v, err
}

// --- client state: per-key and per-object sequence numbers ---

type objectHead struct {
	Next uint64 `json:"next_oseq"`
	Prev string `json:"prev,omitempty"`
}

type clientState struct {
	NextKeySeq uint64                 `json:"next_kseq"`
	Objects    map[string]*objectHead `json:"objects"`
}

func loadState(path string) (*clientState, error) {
	st := &clientState{Objects: map[string]*objectHead{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	return st, json.Unmarshal(b, st)
}

func saveState(path string, st *clientState) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// --- receipts ---

// receipt is what a source keeps for each recorded file: the envelope, the
// salt and the registry's confirmation. Together with the file, it proves
// the event to anyone, even after the registry deletes the envelope.
type receipt struct {
	Envelope       []byte   `json:"envelope"`
	Salt           []byte   `json:"salt"`
	LeafIndex      uint64   `json:"leaf_index"`
	TreeHead       string   `json:"tree_head"`
	InclusionProof [][]byte `json:"inclusion_proof"`
}

func digest(salt, content []byte) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write(content)
	return h.Sum(nil)
}

func initCmd(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dataDir := fs.String("data", "", "registry data directory")
	logKey := fs.String("log-key", "", "log signing key (from keygen-log)")
	fs.Parse(args)
	if *dataDir == "" || *logKey == "" {
		return errors.New("init needs -data and -log-key")
	}
	signer, verifier, err := readLogKeys(*logKey, strings.TrimSuffix(*logKey, ".key")+".pub")
	if err != nil {
		return err
	}
	ctx := context.Background()
	reg, err := registry.Open(ctx, registry.Config{
		Dir: *dataDir, Signer: signer, Verifier: verifier, Keys: registry.StaticKeys(),
	})
	if err != nil {
		return err
	}
	if err := reg.Close(ctx); err != nil {
		return err
	}
	cp, err := os.ReadFile(reg.LogDir() + "/checkpoint")
	if err != nil {
		return err
	}
	fmt.Print(string(cp))
	return nil
}

func add(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	dataDir := fs.String("data", "", "registry data directory")
	logKey := fs.String("log-key", "", "log signing key (from keygen-log)")
	logPub := fs.String("log-pub", "", "log verifier key (default: -log-key with .pub)")
	keyPath := fs.String("key", "", "source key (from keygen)")
	objHex := fs.String("object", "", "object id (hex, 16 bytes); a new object if empty")
	fs.Parse(args)
	if *dataDir == "" || *logKey == "" || *keyPath == "" || fs.NArg() == 0 {
		return errors.New("add needs -data, -log-key, -key and at least one FILE")
	}
	if *logPub == "" {
		*logPub = strings.TrimSuffix(*logKey, ".key") + ".pub"
	}
	signer, verifier, err := readLogKeys(*logKey, *logPub)
	if err != nil {
		return err
	}
	sk, err := readSourceKey(*keyPath)
	if err != nil {
		return err
	}
	priv, err := sk.private()
	if err != nil {
		return err
	}
	src, err := hex.DecodeString(sk.SourceID)
	if err != nil {
		return err
	}
	obj := make([]byte, envelope.IDSize)
	if *objHex == "" {
		rand.Read(obj)
	} else if obj, err = hex.DecodeString(*objHex); err != nil {
		return err
	}

	statePath := strings.TrimSuffix(*keyPath, ".key") + ".state.json"
	st, err := loadState(statePath)
	if err != nil {
		return err
	}
	head := st.Objects[hex.EncodeToString(obj)]
	if head == nil {
		head = &objectHead{}
		st.Objects[hex.EncodeToString(obj)] = head
	}

	ctx := context.Background()
	reg, err := registry.Open(ctx, registry.Config{
		Dir: *dataDir, Signer: signer, Verifier: verifier,
		Keys: registry.StaticKeys(priv.Public().(ed25519.PublicKey)),
	})
	if err != nil {
		return err
	}
	defer reg.Close(ctx)

	for _, path := range fs.Args() {
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		salt := make([]byte, 32)
		rand.Read(salt)
		now := time.Now().UnixMilli()
		p := envelope.Payload{
			Version: envelope.Version, Source: src, Object: obj,
			ObjectSeq: head.Next, KeySeq: st.NextKeySeq, Time: &now,
			Digest: envelope.Digest{Alg: envelope.AlgSHA256, Value: digest(salt, content)},
		}
		if head.Prev != "" {
			if p.Prev, err = hex.DecodeString(head.Prev); err != nil {
				return err
			}
		}
		raw, err := envelope.Sign(p, priv)
		if err != nil {
			return err
		}
		c, err := reg.Submit(ctx, raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		r := receipt{Envelope: raw, Salt: salt, LeafIndex: c.LeafIndex, TreeHead: string(c.TreeHead), InclusionProof: c.InclusionProof}
		b, _ := json.MarshalIndent(r, "", "  ")
		if err := os.WriteFile(path+".receipt.json", append(b, '\n'), 0o600); err != nil {
			return err
		}
		head.Next, head.Prev = head.Next+1, hex.EncodeToString(c.EnvelopeHash)
		st.NextKeySeq++
		if err := saveState(statePath, st); err != nil {
			return err
		}
		fmt.Printf("%s  object %x  oseq %d  leaf %d\n", path, obj, p.ObjectSeq, c.LeafIndex)
	}
	return nil
}

// --- verification ---

func openLog(s string) (verify.Log, error) {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		u, err := url.Parse(strings.TrimSuffix(s, "/") + "/")
		if err != nil {
			return nil, err
		}
		return client.NewHTTPFetcher(u, nil)
	}
	return client.FileFetcher{Root: s}, nil
}

func verifyCmd(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	logLoc := fs.String("log", "", "log directory or URL (for consistency with the current tree head)")
	logPub := fs.String("log-pub", "", "log verifier key")
	pubPath := fs.String("pub", "", "source public key (from keygen)")
	fs.Parse(args)
	if *logPub == "" || *pubPath == "" || fs.NArg() < 1 {
		return errors.New("verify needs -log-pub, -pub and RECEIPT")
	}
	_, verifier, err := readLogKeys("", *logPub)
	if err != nil {
		return err
	}
	sk, err := readSourceKey(*pubPath)
	if err != nil {
		return err
	}
	pub, err := sk.public()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var r receipt
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}

	env, th, err := verify.Event(r.Envelope, pub, r.LeafIndex, []byte(r.TreeHead), r.InclusionProof, verifier.Name(), verifier)
	if err != nil {
		return err
	}
	fmt.Printf("OK  envelope signed by key %x\n", env.KeyID)
	fmt.Printf("OK  included at leaf %d of tree size %d\n", r.LeafIndex, th.Size)

	if fs.NArg() > 1 {
		content, err := os.ReadFile(fs.Arg(1))
		if err != nil {
			return err
		}
		if !bytes.Equal(digest(r.Salt, content), env.Payload.Digest.Value) {
			return fmt.Errorf("FAIL  %s does not match the recorded digest", fs.Arg(1))
		}
		fmt.Printf("OK  %s matches the recorded digest\n", fs.Arg(1))
	}

	if *logLoc != "" {
		l, err := openLog(*logLoc)
		if err != nil {
			return err
		}
		raw, err := l.ReadCheckpoint(context.Background())
		if err != nil {
			return err
		}
		cur, err := verify.TreeHead(raw, verifier.Name(), verifier)
		if err != nil {
			return err
		}
		if err := verify.Consistency(context.Background(), l, th, cur); err != nil {
			return err
		}
		fmt.Printf("OK  current tree head (size %d) is consistent with the receipt's\n", cur.Size)
	}
	return nil
}

func audit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	logLoc := fs.String("log", "", "log directory or URL")
	logPub := fs.String("log-pub", "", "log verifier key")
	every := fs.Uint64("every", registry.DefaultCheckpointEvery, "ordinary leaves between checkpoint leaves")
	fs.Parse(args)
	if *logLoc == "" || *logPub == "" {
		return errors.New("audit needs -log and -log-pub")
	}
	_, verifier, err := readLogKeys("", *logPub)
	if err != nil {
		return err
	}
	l, err := openLog(*logLoc)
	if err != nil {
		return err
	}
	rep, err := verify.Audit(context.Background(), l, verifier.Name(), verifier, *every)
	if err != nil {
		return err
	}
	fmt.Printf("OK  tree size %d: %d events, %d internal checkpoints, all consistent\n", rep.Size, rep.Ordinary, rep.Checkpoints)
	return nil
}
