package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/time/rate"

	"github.com/pasta0126/kirowen/envelope"
	"github.com/pasta0126/kirowen/leaf"
	"github.com/pasta0126/kirowen/registry"
	"github.com/pasta0126/kirowen/state"
	"github.com/pasta0126/kirowen/verify"
)

const origin = "example.com/log/v0"

type env struct {
	t        *testing.T
	srv      *httptest.Server
	api      *Server
	reg      *registry.Registry
	st       *state.Store
	verifier note.Verifier
	dir      string
	signer   note.Signer
	sysKey   ed25519.PrivateKey
}

func newEnv(t *testing.T) *env {
	t.Helper()
	skey, vkey, _ := note.GenerateKey(rand.Reader, origin)
	s, _ := note.NewSigner(skey)
	v, _ := note.NewVerifier(vkey)
	_, sys, _ := ed25519.GenerateKey(rand.Reader)
	e := &env{t: t, dir: t.TempDir(), signer: s, verifier: v, sysKey: sys}
	e.start()
	return e
}

func (e *env) start() {
	t := e.t
	ctx := context.Background()
	reg, err := registry.Open(ctx, registry.Config{
		Dir: e.dir, Signer: e.signer, Verifier: e.verifier, CheckpointEvery: 4,
		BatchMaxAge: 10 * time.Millisecond, CheckpointInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.Open(filepath.Join(e.dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits
	lim.RegistrationsPerIP = 100
	a, err := New(ctx, Config{Registry: reg, State: st, SystemKey: e.sysKey, Limits: lim})
	if err != nil {
		t.Fatal(err)
	}
	e.reg, e.st, e.api = reg, st, a
	e.srv = httptest.NewServer(a.Handler())
}

func (e *env) stop() {
	e.srv.Close()
	e.reg.Close(context.Background())
	e.st.Close()
}

func (e *env) do(method, path, token string, body []byte, out any) int {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: %v: %s", method, path, err, b)
		}
	}
	return resp.StatusCode
}

type source struct {
	priv  ed25519.PrivateKey
	id    []byte
	token string
	kseq  uint64
}

func (e *env) register() *source {
	e.t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body, _ := json.Marshal(RegisterRequest{PublicKey: pub, Proof: ed25519.Sign(priv, envelope.RegistrationMessage(origin, pub))})
	var resp RegisterResponse
	if code := e.do("POST", "/v0/sources", "", body, &resp); code != http.StatusCreated {
		e.t.Fatalf("register: %d", code)
	}
	id, _ := hex.DecodeString(resp.SourceID)
	return &source{priv: priv, id: id, token: resp.Token}
}

func (e *env) object(s *source) []byte {
	e.t.Helper()
	var resp struct {
		ObjectID string `json:"object_id"`
	}
	if code := e.do("POST", "/v0/objects", s.token, nil, &resp); code != http.StatusCreated {
		e.t.Fatalf("create object: %d", code)
	}
	id, _ := hex.DecodeString(resp.ObjectID)
	return id
}

func (s *source) sign(t *testing.T, obj []byte, oseq uint64, prev []byte, content string) []byte {
	t.Helper()
	d := sha256.Sum256([]byte(content))
	raw, err := envelope.Sign(envelope.Payload{
		Version: 1, Source: s.id, Object: obj, ObjectSeq: oseq, Prev: prev, KeySeq: s.kseq,
		Digest: envelope.Digest{Alg: envelope.AlgSHA256, Value: d[:]},
	}, s.priv)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFlow(t *testing.T) {
	e := newEnv(t)
	defer e.stop()
	ctx := context.Background()

	alice := e.register()
	obj := e.object(alice)

	// First event.
	raw := alice.sign(t, obj, 0, nil, "hello")
	var c Confirmation
	if code := e.do("POST", "/v0/events", alice.token, raw, &c); code != http.StatusOK {
		t.Fatalf("submit: %d", code)
	}
	alice.kseq++
	if _, _, err := verify.Event(raw, alice.priv.Public().(ed25519.PublicKey), c.LeafIndex, []byte(c.TreeHead), c.InclusionProof, origin, e.verifier); err != nil {
		t.Fatalf("confirmation does not verify: %v", err)
	}

	// Retry of the same bytes: same confirmation index (idempotency).
	var c2 Confirmation
	if code := e.do("POST", "/v0/events", alice.token, raw, &c2); code != http.StatusOK || c2.LeafIndex != c.LeafIndex {
		t.Fatalf("retry: %d, leaf %d vs %d", code, c2.LeafIndex, c.LeafIndex)
	}

	// Stale head: oseq 0 again with different content → conflict.
	if code := e.do("POST", "/v0/events", alice.token, alice.sign(t, obj, 0, nil, "other"), nil); code != http.StatusConflict {
		t.Errorf("stale oseq: %d, want 409", code)
	}
	// Wrong prev.
	if code := e.do("POST", "/v0/events", alice.token, alice.sign(t, obj, 1, make([]byte, 32), "x"), nil); code != http.StatusConflict {
		t.Errorf("wrong prev: %d, want 409", code)
	}
	// Correct second event.
	h1, _ := hex.DecodeString(c.EnvelopeHash)
	if code := e.do("POST", "/v0/events", alice.token, alice.sign(t, obj, 1, h1, "second"), nil); code != http.StatusOK {
		t.Fatalf("second: %d", code)
	}
	alice.kseq++

	// Bob cannot write into Alice's object, nor use Alice's source id.
	bob := e.register()
	if code := e.do("POST", "/v0/events", bob.token, raw, nil); code != http.StatusForbidden {
		t.Errorf("bob sends alice's envelope: %d, want 403", code)
	}
	bobOnAlice := bob.sign(t, obj, 2, make([]byte, 32), "intrusion")
	if code := e.do("POST", "/v0/events", bob.token, bobOnAlice, nil); code != http.StatusForbidden {
		t.Errorf("bob writes alice's object: %d, want 403", code)
	}
	// No token → 401.
	if code := e.do("POST", "/v0/events", "", raw, nil); code != http.StatusUnauthorized {
		t.Errorf("anonymous submit: %d, want 401", code)
	}

	// Reads: anyone can get the proof; only the owner gets the envelope
	// and the history.
	if code := e.do("GET", "/v0/events/"+c.EnvelopeHash, "", nil, nil); code != http.StatusOK {
		t.Errorf("anonymous proof: %d", code)
	}
	if code := e.do("GET", "/v0/envelopes/"+c.EnvelopeHash, "", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("anonymous envelope: %d, want 401", code)
	}
	if code := e.do("GET", "/v0/envelopes/"+c.EnvelopeHash, bob.token, nil, nil); code != http.StatusNotFound {
		t.Errorf("bob reads alice's envelope: %d, want 404", code)
	}
	if code := e.do("GET", "/v0/envelopes/"+c.EnvelopeHash, alice.token, nil, nil); code != http.StatusOK {
		t.Errorf("alice reads her envelope: %d", code)
	}
	var hist struct {
		NextOSeq uint64 `json:"next_oseq"`
		Events   []ObjectEvent
	}
	if code := e.do("GET", "/v0/objects/"+hex.EncodeToString(obj), alice.token, nil, &hist); code != http.StatusOK || hist.NextOSeq != 2 || len(hist.Events) != 2 {
		t.Errorf("history: %d %+v", code, hist)
	}
	if code := e.do("GET", "/v0/objects/"+hex.EncodeToString(obj), bob.token, nil, nil); code != http.StatusNotFound {
		t.Errorf("bob reads alice's history: %d, want 404", code)
	}

	// Key statements are public and match what was logged.
	kid := envelope.KeyID(alice.priv.Public().(ed25519.PublicKey))
	var ki KeyInfo
	if code := e.do("GET", "/v0/keys/"+hex.EncodeToString(kid[:]), "", nil, &ki); code != http.StatusOK || ki.NextKSeq != nil {
		t.Fatalf("key info: %d %+v", code, ki)
	}
	stmt, err := envelope.ParseKeyStatement(ki.Statement)
	if err != nil || !bytes.Equal(stmt.Source, alice.id) {
		t.Fatalf("statement: %v", err)
	}

	// The whole log audits: 1 system key + 2 registrations + 2 events,
	// with a checkpoint leaf after the first 4 ordinary leaves.
	rep, err := verify.Audit(ctx, client.FileFetcher{Root: e.reg.LogDir()}, origin, e.verifier, 4)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Ordinary != 5 || rep.Checkpoints != 1 {
		t.Errorf("audit = %+v", rep)
	}
}

func TestBadRegistration(t *testing.T) {
	e := newEnv(t)
	defer e.stop()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Proof for another origin.
	body, _ := json.Marshal(RegisterRequest{PublicKey: pub, Proof: ed25519.Sign(priv, envelope.RegistrationMessage("evil.example/log", pub))})
	if code := e.do("POST", "/v0/sources", "", body, nil); code != http.StatusBadRequest {
		t.Errorf("wrong-origin proof: %d", code)
	}
	good, _ := json.Marshal(RegisterRequest{PublicKey: pub, Proof: ed25519.Sign(priv, envelope.RegistrationMessage(origin, pub))})
	if code := e.do("POST", "/v0/sources", "", good, nil); code != http.StatusCreated {
		t.Fatalf("register: %d", code)
	}
	if code := e.do("POST", "/v0/sources", "", good, nil); code != http.StatusConflict {
		t.Errorf("duplicate key: %d, want 409", code)
	}
	if code := e.do("GET", "/v0/sources/me", "kw_nope", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("unknown token: %d", code)
	}
}

func TestRegistrationRateLimit(t *testing.T) {
	e := newEnv(t)
	defer e.stop()
	e.api.cfg.Limits.RegistrationsPerIP = 2
	e.api.perIP = map[string]*rate.Limiter{}
	codes := ""
	for range 3 {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		body, _ := json.Marshal(RegisterRequest{PublicKey: pub, Proof: ed25519.Sign(priv, envelope.RegistrationMessage(origin, pub))})
		codes += fmt.Sprint(e.do("POST", "/v0/sources", "", body, nil), " ")
	}
	if codes != "201 201 429 " {
		t.Errorf("codes = %s", codes)
	}
}

// TestReconcile simulates a crash after a state write whose leaf never
// reached the log: restarting rolls it back and the head is restored.
func TestReconcile(t *testing.T) {
	e := newEnv(t)
	alice := e.register()
	obj := e.object(alice)
	raw := alice.sign(t, obj, 0, nil, "lost")
	parsed, _ := envelope.Parse(raw)
	kid := envelope.KeyID(alice.priv.Public().(ed25519.PublicKey))
	// Accepted into state, never appended.
	if err := e.st.AcceptEvent(state.Event{Hash: parsed.Hash[:], Source: alice.id, Object: obj, OSeq: 0, KeyID: kid[:], KSeq: 0}); err != nil {
		t.Fatal(err)
	}
	e.stop()
	e.start()
	defer e.stop()

	var hist struct {
		NextOSeq uint64 `json:"next_oseq"`
	}
	if code := e.do("GET", "/v0/objects/"+hex.EncodeToString(obj), alice.token, nil, &hist); code != http.StatusOK || hist.NextOSeq != 0 {
		t.Fatalf("after reconcile: %d next_oseq=%d, want 0", code, hist.NextOSeq)
	}
	// And the same event can now be submitted for real.
	if code := e.do("POST", "/v0/events", alice.token, raw, nil); code != http.StatusOK {
		t.Fatalf("resubmit: %d", code)
	}
}

func TestCORS(t *testing.T) {
	e := newEnv(t)
	defer e.stop()
	req, _ := http.NewRequest(http.MethodOptions, e.srv.URL+"/v0/events", nil)
	req.Header.Set("Origin", "https://example.org")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight: status %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
		t.Fatalf("preflight: Allow-Headers %q", got)
	}
	resp, err = http.Get(e.srv.URL + "/v0/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("GET: Allow-Origin %q", got)
	}
}

func TestLeaves(t *testing.T) {
	e := newEnv(t)
	defer e.stop()

	// System key + 4 registrations: the checkpoint leaf lands at index 4.
	for range 4 {
		e.register()
	}
	for _, i := range []uint64{0, 4, 5} {
		var lr LeafResponse
		if code := e.do("GET", fmt.Sprintf("/v0/leaves/%d", i), "", nil, &lr); code != http.StatusOK {
			t.Fatalf("leaf %d: %d", i, code)
		}
		cp, err := verify.TreeHead([]byte(lr.TreeHead), origin, e.verifier)
		if err != nil {
			t.Fatalf("leaf %d: tree head: %v", i, err)
		}
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, i, cp.Size, leaf.Hash(lr.Leaf), lr.InclusionProof, cp.Hash); err != nil {
			t.Fatalf("leaf %d: inclusion: %v", i, err)
		}
		l, err := leaf.Parse(lr.Leaf)
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		if want := i == 4; (l.Type == leaf.TypeCheckpoint) != want {
			t.Errorf("leaf %d: type %d", i, l.Type)
		}
	}
	for path, want := range map[string]int{
		"/v0/leaves/6":   http.StatusNotFound,
		"/v0/leaves/-1":  http.StatusBadRequest,
		"/v0/leaves/01":  http.StatusBadRequest,
		"/v0/leaves/abc": http.StatusBadRequest,
	} {
		if code := e.do("GET", path, "", nil, nil); code != want {
			t.Errorf("%s: %d, want %d", path, code, want)
		}
	}
}
