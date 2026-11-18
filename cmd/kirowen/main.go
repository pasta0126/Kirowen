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
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"

	"github.com/pasta0126/kirowen/api"
	"github.com/pasta0126/kirowen/envelope"
	"github.com/pasta0126/kirowen/registry"
	"github.com/pasta0126/kirowen/verify"
)

const usage = `usage:
  kirowen keygen-log -origin ORIGIN -out NAME     registry key: NAME.key (secret) and NAME.pub
  kirowen keygen     -out NAME                    source key: NAME.key (secret) and NAME.pub
  kirowen register   -api URL -key NAME.key       self-service sign-up; writes NAME.cred.json
  kirowen object     -key NAME.key                create an object; prints its id
  kirowen add        -key NAME.key [-object HEX] FILE...
                                                  record files; writes FILE.receipt.json
  kirowen verify     -log DIR|URL -log-pub F -pub F RECEIPT [FILE]
                                                  verify a receipt (and the file, if given)
  kirowen audit      -log DIR|URL -log-pub F      check the whole log and its checkpoints

The API URL and token are read from NAME.cred.json next to the key.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"keygen-log": keygenLog, "keygen": keygen, "register": register, "object": objectCmd, "add": add, "verify": verifyCmd, "audit": audit,
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

// sourceKey is the on-disk source key. The source id is assigned by the
// registry at registration and kept in the credentials file.
type sourceKey struct {
	Seed   string `json:"ed25519_seed,omitempty"`
	Public string `json:"ed25519_public"`
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
	k := sourceKey{Seed: hex.EncodeToString(priv.Seed()), Public: hex.EncodeToString(pub)}
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
	fmt.Printf("key_id %x\n", kid)
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

// --- API client ---

type creds struct {
	API      string `json:"api"`
	SourceID string `json:"source_id"`
	Token    string `json:"token"`
}

func credPath(keyPath string) string { return strings.TrimSuffix(keyPath, ".key") + ".cred.json" }

func readCreds(keyPath string) (*creds, error) {
	b, err := os.ReadFile(credPath(keyPath))
	if err != nil {
		return nil, fmt.Errorf("%w (run kirowen register first)", err)
	}
	var c creds
	return &c, json.Unmarshal(b, &c)
}

type apiClient struct {
	base, token string
	hc          *http.Client
}

type apiErr struct {
	Status int
	Msg    string
	Body   map[string]any
}

func (e *apiErr) Error() string { return fmt.Sprintf("API %d: %s", e.Status, e.Msg) }

func (c *apiClient) do(method, path, ctype string, body []byte, out any) error {
	req, err := http.NewRequest(method, strings.TrimSuffix(c.base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		e := &apiErr{Status: resp.StatusCode}
		json.Unmarshal(b, &e.Body)
		e.Msg, _ = e.Body["error"].(string)
		if e.Msg == "" {
			e.Msg = strings.TrimSpace(string(b))
		}
		return e
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func newClient(keyPath string) (*apiClient, *creds, ed25519.PrivateKey, error) {
	sk, err := readSourceKey(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	priv, err := sk.private()
	if err != nil {
		return nil, nil, nil, err
	}
	cr, err := readCreds(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	return &apiClient{base: cr.API, token: cr.Token, hc: &http.Client{Timeout: 60 * time.Second}}, cr, priv, nil
}

func register(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	apiURL := fs.String("api", "https://kirowen-api.northernarchive.com", "API base URL")
	keyPath := fs.String("key", "", "source key (from keygen)")
	fs.Parse(args)
	if *keyPath == "" {
		return errors.New("register needs -key")
	}
	if _, err := os.Stat(credPath(*keyPath)); err == nil {
		return fmt.Errorf("%s already exists: this key is registered", credPath(*keyPath))
	}
	sk, err := readSourceKey(*keyPath)
	if err != nil {
		return err
	}
	priv, err := sk.private()
	if err != nil {
		return err
	}
	c := &apiClient{base: *apiURL, hc: &http.Client{Timeout: 60 * time.Second}}
	var info struct {
		Origin string `json:"origin"`
	}
	if err := c.do("GET", "/v0/", "", nil, &info); err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	body, _ := json.Marshal(api.RegisterRequest{PublicKey: pub, Proof: ed25519.Sign(priv, envelope.RegistrationMessage(info.Origin, pub))})
	var resp api.RegisterResponse
	if err := c.do("POST", "/v0/sources", "application/json", body, &resp); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(creds{API: *apiURL, SourceID: resp.SourceID, Token: resp.Token}, "", "  ")
	if err := writeNew(credPath(*keyPath), append(b, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "could not save credentials; token: %s\n", resp.Token)
		return err
	}
	fmt.Printf("registered on %s\nsource_id %s\nkey_id    %s\nkey registered at leaf %d\ncredentials in %s (keep it secret)\n",
		info.Origin, resp.SourceID, resp.KeyID, resp.Registration.LeafIndex, credPath(*keyPath))
	return nil
}

func objectCmd(args []string) error {
	fs := flag.NewFlagSet("object", flag.ExitOnError)
	keyPath := fs.String("key", "", "source key")
	fs.Parse(args)
	c, _, _, err := newClient(*keyPath)
	if err != nil {
		return err
	}
	var resp struct {
		ObjectID string `json:"object_id"`
	}
	if err := c.do("POST", "/v0/objects", "", nil, &resp); err != nil {
		return err
	}
	fmt.Println(resp.ObjectID)
	return nil
}

func add(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	keyPath := fs.String("key", "", "source key (registered)")
	objHex := fs.String("object", "", "object id (hex); a new object if empty")
	fs.Parse(args)
	if *keyPath == "" || fs.NArg() == 0 {
		return errors.New("add needs -key and at least one FILE")
	}
	c, cr, priv, err := newClient(*keyPath)
	if err != nil {
		return err
	}
	src, err := hex.DecodeString(cr.SourceID)
	if err != nil {
		return err
	}
	if *objHex == "" {
		var resp struct {
			ObjectID string `json:"object_id"`
		}
		if err := c.do("POST", "/v0/objects", "", nil, &resp); err != nil {
			return err
		}
		*objHex = resp.ObjectID
		fmt.Printf("new object %s\n", *objHex)
	}
	obj, err := hex.DecodeString(*objHex)
	if err != nil {
		return err
	}
	kid := envelope.KeyID(priv.Public().(ed25519.PublicKey))

	for _, path := range fs.Args() {
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		salt := make([]byte, 32)
		rand.Read(salt)
		var raw []byte
		var conf api.Confirmation
		for attempt := 0; ; attempt++ {
			// Read the heads, sign, submit. A conflict means another
			// writer moved a head: re-read and re-sign once more.
			var o struct {
				NextOSeq uint64  `json:"next_oseq"`
				LastHash *string `json:"last_hash"`
			}
			if err := c.do("GET", "/v0/objects/"+*objHex, "", nil, &o); err != nil {
				return err
			}
			var me struct {
				Keys []api.KeyInfo `json:"keys"`
			}
			if err := c.do("GET", "/v0/sources/me", "", nil, &me); err != nil {
				return err
			}
			var kseq *uint64
			for _, k := range me.Keys {
				if k.KeyID == hex.EncodeToString(kid[:]) {
					kseq = k.NextKSeq
				}
			}
			if kseq == nil {
				return errors.New("this key is not registered for the source in the credentials file")
			}
			now := time.Now().UnixMilli()
			p := envelope.Payload{
				Version: envelope.Version, Source: src, Object: obj, ObjectSeq: o.NextOSeq, KeySeq: *kseq, Time: &now,
				Digest: envelope.Digest{Alg: envelope.AlgSHA256, Value: digest(salt, content)},
			}
			if o.LastHash != nil {
				if p.Prev, err = hex.DecodeString(*o.LastHash); err != nil {
					return err
				}
			}
			if raw, err = envelope.Sign(p, priv); err != nil {
				return err
			}
			err = c.do("POST", "/v0/events", "application/cose", raw, &conf)
			var ae *apiErr
			if errors.As(err, &ae) && ae.Status == http.StatusConflict && attempt < 3 {
				continue
			}
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			break
		}
		r := receipt{Envelope: raw, Salt: salt, LeafIndex: conf.LeafIndex, TreeHead: conf.TreeHead, InclusionProof: conf.InclusionProof}
		b, _ := json.MarshalIndent(r, "", "  ")
		if err := os.WriteFile(path+".receipt.json", append(b, '\n'), 0o600); err != nil {
			return err
		}
		fmt.Printf("%s  object %s  leaf %d  receipt %s.receipt.json\n", path, *objHex, conf.LeafIndex, path)
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
