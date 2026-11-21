// Package api is the Kirowen HTTP API: self-service source registration,
// object creation, event submission and reads.
//
// Authentication: registration returns a bearer token per source. The
// token is required to write and to read private data (envelopes, object
// histories). Without a token a caller is anonymous and sees only public
// data: inclusion proofs by envelope hash, and key statements.
//
// The token only says who is calling. Events must still be signed by the
// source's key, so the operator cannot forge events in a source's name.
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/pasta0126/kirowen/envelope"
	"github.com/pasta0126/kirowen/registry"
	"github.com/pasta0126/kirowen/state"
)

// Limits are the abuse limits (docs/envelope-v0.md §7).
type Limits struct {
	EventsPerSecond     float64 // sustained, per source
	EventsBurst         int     // per source
	EventsPerDay        int64   // per source, UTC day
	MaxObjects          int64   // per source
	RegistrationsPerIP  int     // per IP per hour
	RegistrationsPerDay int     // global
}

// DefaultLimits are the initial parameters.
var DefaultLimits = Limits{
	EventsPerSecond: 10, EventsBurst: 100, EventsPerDay: 100_000, MaxObjects: 1_000_000,
	RegistrationsPerIP: 5, RegistrationsPerDay: 200,
}

// Config configures a Server.
type Config struct {
	Registry  *registry.Registry
	State     *state.Store
	SystemKey ed25519.PrivateKey // signs key registration events
	LogURL    string             // public URL of the log, for /v0/
	Limits    Limits
	// TrustProxy takes the client IP from the last X-Forwarded-For entry
	// (set it only behind a reverse proxy that sets that header).
	TrustProxy bool
}

// Server serves the API. Create it with New.
type Server struct {
	cfg    Config
	reg    *registry.Registry
	st     *state.Store
	sysKID [envelope.HashSize]byte
	ctx    context.Context // for appends, which must not be cut short by a client

	// mu serializes validation against state, the state write and the
	// append, so that heads and log order always agree.
	mu     sync.Mutex
	broken atomic.Bool // set if the log failed to sequence an entry

	lmu       sync.Mutex
	perSource map[string]*rate.Limiter
	perIP     map[string]*rate.Limiter
	regGlobal *rate.Limiter
}

// New prepares the server: it registers the system key on first start and
// reconciles state with the log after a crash.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Limits == (Limits{}) {
		cfg.Limits = DefaultLimits
	}
	s := &Server{
		cfg: cfg, reg: cfg.Registry, st: cfg.State, ctx: ctx,
		sysKID:    envelope.KeyID(cfg.SystemKey.Public().(ed25519.PublicKey)),
		perSource: map[string]*rate.Limiter{},
		perIP:     map[string]*rate.Limiter{},
		regGlobal: rate.NewLimiter(rate.Every(24*time.Hour/time.Duration(max(cfg.Limits.RegistrationsPerDay, 1))), cfg.Limits.RegistrationsPerDay),
	}
	if err := s.reconcile(ctx); err != nil {
		return nil, err
	}
	if err := s.initSystem(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// reconcile resolves events that were accepted into state but whose leaf
// index was never recorded: found in the log → record the index; not in
// the log (lost in a crash) → roll back.
func (s *Server) reconcile(ctx context.Context) error {
	pending, err := s.st.Pending()
	if err != nil || len(pending) == 0 {
		return err
	}
	from, err := s.st.NextUnconfirmedFrom()
	if err != nil {
		return err
	}
	// Pending entries are at most the appender's outstanding queue, so
	// they lie close to the highest confirmed index.
	const window = 10_000
	if from > window {
		from -= window
	} else {
		from = 0
	}
	inLog, err := s.reg.EventHashes(ctx, from)
	if err != nil {
		return err
	}
	var lost [][]byte
	for _, e := range pending {
		var h [envelope.HashSize]byte
		copy(h[:], e.Hash)
		if i, ok := inLog[h]; ok {
			if err := s.st.SetLeafIndex(e.Hash, i); err != nil {
				return err
			}
		} else {
			lost = append(lost, e.Hash)
		}
	}
	if len(lost) > 0 {
		slog.Warn("rolling back events that never reached the log", "count", len(lost))
		return s.st.Rollback(lost)
	}
	return nil
}

func (s *Server) initSystem(ctx context.Context) error {
	k, err := s.st.Key(s.sysKID[:])
	if err == nil {
		if !bytes.Equal(k.Source, envelope.SystemSource) {
			return errors.New("api: system key id belongs to another source")
		}
		return nil
	}
	if !errors.Is(err, state.ErrNotFound) {
		return err
	}
	pub := s.cfg.SystemKey.Public().(ed25519.PublicKey)
	stmt, err := envelope.KeyStatement{Source: envelope.SystemSource, PublicKey: pub, Alg: envelope.AlgEdDSA, Action: envelope.KeyActionAdd}.Encode()
	if err != nil {
		return err
	}
	env, ev, err := s.systemEvent(envelope.SystemSource, 0, nil, 0, stmt)
	if err != nil {
		return err
	}
	key := state.Key{ID: s.sysKID[:], Source: envelope.SystemSource, Public: pub, Statement: stmt, EventHash: env.Hash[:]}
	s.mu.Lock()
	err = s.st.InitSystem(key, ev)
	var future func() (uint64, error)
	if err == nil {
		future, err = s.appendLocked(env, ev)
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = future()
	return err
}

// systemEvent signs a system-source event on a system object.
func (s *Server) systemEvent(object []byte, oseq uint64, prev []byte, kseq uint64, statement []byte) (*envelope.Envelope, state.Event, error) {
	p := envelope.Payload{
		Version: envelope.Version, Source: envelope.SystemSource, Object: object,
		ObjectSeq: oseq, Prev: prev, KeySeq: kseq, Digest: envelope.StatementDigest(statement),
	}
	raw, err := envelope.Sign(p, s.cfg.SystemKey)
	if err != nil {
		return nil, state.Event{}, err
	}
	env, err := envelope.Parse(raw)
	if err != nil {
		return nil, state.Event{}, err
	}
	return env, state.Event{Hash: env.Hash[:], Source: envelope.SystemSource, Object: object, OSeq: oseq, KeyID: s.sysKID[:], KSeq: kseq}, nil
}

// appendLocked appends an event already recorded as pending in state. s.mu
// must be held. The returned function waits for the leaf index and
// records it.
func (s *Server) appendLocked(env *envelope.Envelope, ev state.Event) (func() (uint64, error), error) {
	future, err := s.reg.AppendEvent(s.ctx, env)
	if err != nil {
		if rbErr := s.st.Rollback([][]byte{ev.Hash}); rbErr != nil {
			s.broken.Store(true)
			slog.Error("rollback failed; refusing writes until restart", "err", rbErr)
		}
		return nil, err
	}
	return func() (uint64, error) {
		idx, err := future()
		if err != nil {
			// The leaf may or may not be in the log; only a restart
			// (reconcile) can tell.
			s.broken.Store(true)
			slog.Error("log failed to sequence an entry; refusing writes until restart", "err", err)
			return 0, err
		}
		if err := s.st.SetLeafIndex(ev.Hash, idx.Index); err != nil {
			return 0, err
		}
		return idx.Index, nil
	}, nil
}

// --- HTTP plumbing ---

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/{$}", s.info)
	mux.HandleFunc("POST /v0/sources", s.register)
	mux.HandleFunc("GET /v0/sources/me", s.me)
	mux.HandleFunc("POST /v0/objects", s.createObject)
	mux.HandleFunc("GET /v0/objects/{id}", s.getObject)
	mux.HandleFunc("POST /v0/events", s.submit)
	mux.HandleFunc("GET /v0/events/{hash}", s.getEvent)
	mux.HandleFunc("GET /v0/leaves/{index}", s.getLeaf)
	mux.HandleFunc("GET /v0/envelopes/{hash}", s.getEnvelope)
	mux.HandleFunc("GET /v0/keys/{id}", s.getKey)
	return cors(mux)
}

// cors lets browser clients on any origin call the API. Auth is a bearer
// token in a header, never a cookie, so a foreign page cannot act with a
// visitor's credentials: it would need the token itself.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Expose-Headers", "Content-Type")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "GET, POST")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type apiError struct {
	status int
	msg    string
	extra  map[string]any
}

func (e *apiError) Error() string { return e.msg }

func fail(status int, format string, args ...any) *apiError {
	return &apiError{status: status, msg: fmt.Sprintf(format, args...)}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		switch {
		case errors.Is(err, envelope.ErrTooLarge):
			ae = fail(http.StatusRequestEntityTooLarge, "%v", err)
		case errors.Is(err, envelope.ErrMalformed), errors.Is(err, envelope.ErrInvalidField):
			ae = fail(http.StatusBadRequest, "%v", err)
		case errors.Is(err, envelope.ErrBadSignature), errors.Is(err, envelope.ErrWrongKey):
			ae = fail(http.StatusBadRequest, "%v", err)
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			ae = fail(http.StatusGatewayTimeout, "timed out")
		default:
			slog.Error("internal error", "err", err)
			ae = fail(http.StatusInternalServerError, "internal error")
		}
	}
	body := map[string]any{"error": ae.msg}
	for k, v := range ae.extra {
		body[k] = v
	}
	writeJSON(w, ae.status, body)
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// TokenPrefix marks Kirowen API tokens.
const TokenPrefix = "kw_"

func tokenHash(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

// auth returns the caller's source id, or nil for an anonymous caller.
// A presented but unknown token is an error, not anonymity.
func (s *Server) auth(r *http.Request) ([]byte, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, nil
	}
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || !strings.HasPrefix(tok, TokenPrefix) {
		return nil, fail(http.StatusUnauthorized, "malformed Authorization header")
	}
	src, err := s.st.SourceByToken(tokenHash(tok))
	if errors.Is(err, state.ErrNotFound) {
		return nil, fail(http.StatusUnauthorized, "unknown token")
	}
	return src, err
}

func (s *Server) mustAuth(r *http.Request) ([]byte, error) {
	src, err := s.auth(r)
	if err == nil && src == nil {
		err = fail(http.StatusUnauthorized, "this endpoint needs a token")
	}
	return src, err
}

func pathID(r *http.Request, name string, size int) ([]byte, error) {
	b, err := hex.DecodeString(r.PathValue(name))
	if err != nil || len(b) != size {
		return nil, fail(http.StatusBadRequest, "%s must be %d bytes in hex", name, size)
	}
	return b, nil
}

func (s *Server) writable() error {
	if s.broken.Load() {
		return fail(http.StatusServiceUnavailable, "writes are suspended; the registry needs a restart")
	}
	return nil
}

// --- handlers ---

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"origin":        s.reg.Origin(),
		"log_url":       s.cfg.LogURL,
		"system_key_id": hex.EncodeToString(s.sysKID[:]),
		"limits":        s.cfg.Limits,
	})
}

// Confirmation is the JSON form of a confirmation.
type Confirmation struct {
	EnvelopeHash   string   `json:"envelope_hash"`
	LeafIndex      uint64   `json:"leaf_index"`
	TreeHead       string   `json:"tree_head"`
	InclusionProof [][]byte `json:"inclusion_proof"`
}

func toJSON(c *registry.Confirmation) Confirmation {
	return Confirmation{EnvelopeHash: hex.EncodeToString(c.EnvelopeHash), LeafIndex: c.LeafIndex, TreeHead: string(c.TreeHead), InclusionProof: c.InclusionProof}
}

// RegisterRequest is the body of POST /v0/sources.
type RegisterRequest struct {
	PublicKey []byte `json:"public_key"` // Ed25519, base64
	Proof     []byte `json:"proof"`      // signature over envelope.RegistrationMessage
}

// RegisterResponse is the reply to POST /v0/sources.
type RegisterResponse struct {
	SourceID     string       `json:"source_id"`
	KeyID        string       `json:"key_id"`
	Token        string       `json:"token"`
	Registration Confirmation `json:"registration"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	resp, err := s.doRegister(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) doRegister(r *http.Request) (*RegisterResponse, error) {
	if err := s.writable(); err != nil {
		return nil, err
	}
	var req RegisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4096)).Decode(&req); err != nil {
		return nil, fail(http.StatusBadRequest, "bad JSON: %v", err)
	}
	if len(req.PublicKey) != ed25519.PublicKeySize {
		return nil, fail(http.StatusBadRequest, "public_key must be an Ed25519 public key")
	}
	pub := ed25519.PublicKey(req.PublicKey)
	if !ed25519.Verify(pub, envelope.RegistrationMessage(s.reg.Origin(), pub), req.Proof) {
		return nil, fail(http.StatusBadRequest, "proof does not verify: sign the registration message with the key")
	}
	if !s.allowRegistration(s.clientIP(r)) {
		return nil, fail(http.StatusTooManyRequests, "too many registrations; try later")
	}

	source := make([]byte, envelope.IDSize)
	rand.Read(source)
	secret := make([]byte, 32)
	rand.Read(secret)
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(secret)
	kid := envelope.KeyID(pub)
	stmt, err := envelope.KeyStatement{Source: source, PublicKey: pub, Alg: envelope.AlgEdDSA, Action: envelope.KeyActionAdd}.Encode()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if _, err := s.st.Key(kid[:]); err == nil {
		s.mu.Unlock()
		return nil, fail(http.StatusConflict, "this key is already registered")
	}
	sys, err := s.st.Key(s.sysKID[:])
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	env, ev, err := s.systemEvent(source, 0, nil, sys.NextKSeq, stmt)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	key := state.Key{ID: kid[:], Source: source, Public: pub, Statement: stmt, EventHash: env.Hash[:]}
	var wait func() (uint64, error)
	if err = s.st.Register(source, tokenHash(token), key, ev); err == nil {
		wait, err = s.appendLocked(env, ev)
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	idx, err := wait()
	if err != nil {
		return nil, err
	}
	c, err := s.reg.Prove(r.Context(), env.Hash[:], idx)
	if err != nil {
		return nil, err
	}
	slog.Info("source registered", "source", hex.EncodeToString(source), "leaf", idx)
	return &RegisterResponse{
		SourceID: hex.EncodeToString(source), KeyID: hex.EncodeToString(kid[:]),
		Token: token, Registration: toJSON(c),
	}, nil
}

func (s *Server) allowRegistration(ip string) bool {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	l := s.perIP[ip]
	if l == nil {
		n := max(s.cfg.Limits.RegistrationsPerIP, 1)
		l = rate.NewLimiter(rate.Every(time.Hour/time.Duration(n)), n)
		s.perIP[ip] = l
	}
	return l.Allow() && s.regGlobal.Allow()
}

func (s *Server) allowEvent(source []byte) bool {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	l := s.perSource[string(source)]
	if l == nil {
		l = rate.NewLimiter(rate.Limit(s.cfg.Limits.EventsPerSecond), s.cfg.Limits.EventsBurst)
		s.perSource[string(source)] = l
	}
	return l.Allow()
}

// KeyInfo describes a key.
type KeyInfo struct {
	KeyID     string  `json:"key_id"`
	SourceID  string  `json:"source_id"`
	PublicKey []byte  `json:"public_key"`
	Statement []byte  `json:"statement"`
	EventHash string  `json:"registration_event_hash"`
	NextKSeq  *uint64 `json:"next_kseq,omitempty"` // only for the owner
	Revoked   bool    `json:"revoked"`
}

func keyInfo(k state.Key, owner bool) KeyInfo {
	ki := KeyInfo{
		KeyID: hex.EncodeToString(k.ID), SourceID: hex.EncodeToString(k.Source), PublicKey: k.Public,
		Statement: k.Statement, EventHash: hex.EncodeToString(k.EventHash), Revoked: k.Revoked,
	}
	if owner {
		n := k.NextKSeq
		ki.NextKSeq = &n
	}
	return ki
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	src, err := s.mustAuth(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	keys, err := s.st.KeysOf(src)
	if err != nil {
		writeErr(w, err)
		return
	}
	nobj, err := s.st.CountObjects(src)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := []KeyInfo{}
	for _, k := range keys {
		out = append(out, keyInfo(k, true))
	}
	writeJSON(w, http.StatusOK, map[string]any{"source_id": hex.EncodeToString(src), "keys": out, "objects": nobj})
}

func (s *Server) getKey(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id", envelope.HashSize)
	if err != nil {
		writeErr(w, err)
		return
	}
	k, err := s.st.Key(id)
	if errors.Is(err, state.ErrNotFound) {
		writeErr(w, fail(http.StatusNotFound, "unknown key"))
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	src, _ := s.auth(r)
	writeJSON(w, http.StatusOK, keyInfo(*k, src != nil && bytes.Equal(src, k.Source)))
}

func (s *Server) createObject(w http.ResponseWriter, r *http.Request) {
	src, err := s.mustAuth(r)
	if err == nil {
		err = s.writable()
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	n, err := s.st.CountObjects(src)
	if err != nil {
		writeErr(w, err)
		return
	}
	if n >= s.cfg.Limits.MaxObjects {
		writeErr(w, fail(http.StatusTooManyRequests, "object limit reached (%d)", s.cfg.Limits.MaxObjects))
		return
	}
	id := make([]byte, envelope.IDSize)
	rand.Read(id)
	if err := s.st.CreateObject(id, src); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"object_id": hex.EncodeToString(id), "next_oseq": 0})
}

// ObjectEvent is one entry of an object's history.
type ObjectEvent struct {
	OSeq         uint64  `json:"oseq"`
	EnvelopeHash string  `json:"envelope_hash"`
	LeafIndex    *uint64 `json:"leaf_index"`
}

func (s *Server) getObject(w http.ResponseWriter, r *http.Request) {
	src, err := s.mustAuth(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	id, err := pathID(r, "id", envelope.IDSize)
	if err != nil {
		writeErr(w, err)
		return
	}
	o, err := s.st.Object(id)
	if errors.Is(err, state.ErrNotFound) || (err == nil && !bytes.Equal(o.Source, src)) {
		writeErr(w, fail(http.StatusNotFound, "unknown object"))
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	evs, err := s.st.ObjectEvents(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	hist := []ObjectEvent{}
	for _, e := range evs {
		hist = append(hist, ObjectEvent{OSeq: e.OSeq, EnvelopeHash: hex.EncodeToString(e.Hash), LeafIndex: e.LeafIndex})
	}
	var last *string
	if o.LastHash != nil {
		h := hex.EncodeToString(o.LastHash)
		last = &h
	}
	writeJSON(w, http.StatusOK, map[string]any{"object_id": hex.EncodeToString(id), "next_oseq": o.NextOSeq, "last_hash": last, "events": hist})
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	c, err := s.doSubmit(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toJSON(c))
}

func (s *Server) doSubmit(r *http.Request) (*registry.Confirmation, error) {
	src, err := s.mustAuth(r)
	if err != nil {
		return nil, err
	}
	if err := s.writable(); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, envelope.MaxSize+1))
	if err != nil {
		return nil, fail(http.StatusBadRequest, "reading body: %v", err)
	}
	env, err := envelope.Parse(raw)
	if err != nil {
		return nil, err
	}
	p := &env.Payload
	if !bytes.Equal(p.Source, src) {
		return nil, fail(http.StatusForbidden, "envelope src does not match the token's source")
	}

	// Idempotency: an identical envelope returns its original confirmation.
	if prev, err := s.st.Event(env.Hash[:]); err == nil {
		if prev.LeafIndex == nil {
			return nil, fail(http.StatusConflict, "this envelope is still being sequenced; retry")
		}
		return s.reg.Prove(r.Context(), env.Hash[:], *prev.LeafIndex)
	} else if !errors.Is(err, state.ErrNotFound) {
		return nil, err
	}

	if !s.allowEvent(src) {
		return nil, fail(http.StatusTooManyRequests, "rate limit: %v events/s, burst %d", s.cfg.Limits.EventsPerSecond, s.cfg.Limits.EventsBurst)
	}
	day := time.Now().UTC().Truncate(24 * time.Hour)
	if n, err := s.st.CountEventsSince(src, day); err != nil {
		return nil, err
	} else if n >= s.cfg.Limits.EventsPerDay {
		return nil, fail(http.StatusTooManyRequests, "daily quota reached (%d events)", s.cfg.Limits.EventsPerDay)
	}

	s.mu.Lock()
	wait, err := s.acceptLocked(src, env)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	idx, err := wait()
	if err != nil {
		return nil, err
	}
	return s.reg.Prove(r.Context(), env.Hash[:], idx)
}

// acceptLocked applies the stateful acceptance rules and appends.
func (s *Server) acceptLocked(src []byte, env *envelope.Envelope) (func() (uint64, error), error) {
	p := &env.Payload
	key, err := s.st.Key(env.KeyID[:])
	if errors.Is(err, state.ErrNotFound) || (err == nil && !bytes.Equal(key.Source, src)) {
		return nil, fail(http.StatusForbidden, "kid is not a key of this source")
	}
	if err != nil {
		return nil, err
	}
	if key.Revoked {
		return nil, fail(http.StatusForbidden, "key is revoked")
	}
	if err := env.Verify(ed25519.PublicKey(key.Public)); err != nil {
		return nil, err
	}

	obj, err := s.st.Object(p.Object)
	if errors.Is(err, state.ErrNotFound) || (err == nil && !bytes.Equal(obj.Source, src)) {
		return nil, fail(http.StatusForbidden, "obj is not an object of this source (create it with POST /v0/objects)")
	}
	if err != nil {
		return nil, err
	}
	if p.ObjectSeq != obj.NextOSeq || !bytes.Equal(p.Prev, obj.LastHash) {
		e := fail(http.StatusConflict, "object head moved: re-read the object and re-sign")
		e.extra = map[string]any{"next_oseq": obj.NextOSeq, "last_hash": hex.EncodeToString(obj.LastHash)}
		return nil, e
	}
	if p.KeySeq != key.NextKSeq {
		e := fail(http.StatusConflict, "kseq out of order")
		e.extra = map[string]any{"next_kseq": key.NextKSeq}
		return nil, e
	}
	for i, ref := range p.Refs {
		re, err := s.st.Event(ref)
		if errors.Is(err, state.ErrNotFound) || (err == nil && !bytes.Equal(re.Source, src)) {
			return nil, fail(http.StatusBadRequest, "refs[%d] is not an event of this source", i)
		}
		if err != nil {
			return nil, err
		}
	}

	ev := state.Event{Hash: env.Hash[:], Source: src, Object: p.Object, OSeq: p.ObjectSeq, KeyID: env.KeyID[:], KSeq: p.KeySeq}
	if err := s.st.AcceptEvent(ev); err != nil {
		return nil, err
	}
	return s.appendLocked(env, ev)
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	h, err := pathID(r, "hash", envelope.HashSize)
	if err != nil {
		writeErr(w, err)
		return
	}
	e, err := s.st.Event(h)
	if errors.Is(err, state.ErrNotFound) {
		writeErr(w, fail(http.StatusNotFound, "unknown event"))
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	if e.LeafIndex == nil {
		writeErr(w, fail(http.StatusConflict, "still being sequenced; retry"))
		return
	}
	c, err := s.reg.Prove(r.Context(), h, *e.LeafIndex)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toJSON(c))
}

// LeafResponse is the body of GET /v0/leaves/{index}.
type LeafResponse struct {
	LeafIndex      uint64   `json:"leaf_index"`
	Leaf           []byte   `json:"leaf"`
	TreeHead       string   `json:"tree_head"`
	InclusionProof [][]byte `json:"inclusion_proof"`
}

func (s *Server) getLeaf(w http.ResponseWriter, r *http.Request) {
	v := r.PathValue("index")
	i, err := strconv.ParseUint(v, 10, 64)
	if err != nil || strconv.FormatUint(i, 10) != v {
		writeErr(w, fail(http.StatusBadRequest, "index must be a decimal integer"))
		return
	}
	raw, c, err := s.reg.Leaf(r.Context(), i)
	if errors.Is(err, registry.ErrNoLeaf) {
		writeErr(w, fail(http.StatusNotFound, "no such leaf"))
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, LeafResponse{LeafIndex: i, Leaf: raw, TreeHead: string(c.TreeHead), InclusionProof: c.InclusionProof})
}

func (s *Server) getEnvelope(w http.ResponseWriter, r *http.Request) {
	src, err := s.mustAuth(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	h, err := pathID(r, "hash", envelope.HashSize)
	if err != nil {
		writeErr(w, err)
		return
	}
	e, err := s.st.Event(h)
	if errors.Is(err, state.ErrNotFound) || (err == nil && !bytes.Equal(e.Source, src)) {
		writeErr(w, fail(http.StatusNotFound, "unknown envelope"))
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	raw, err := s.reg.Envelope(h)
	if err != nil {
		writeErr(w, fail(http.StatusNotFound, "envelope no longer stored"))
		return
	}
	w.Header().Set("Content-Type", "application/cose; cose-type=\"cose-sign1\"")
	w.Write(raw)
}
