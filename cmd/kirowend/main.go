// Command kirowend runs the Kirowen registry: the sequencer, the public
// log on disk and the HTTP API.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/pasta0126/kirowen/api"
	"github.com/pasta0126/kirowen/registry"
	"github.com/pasta0126/kirowen/state"
)

func main() {
	dataDir := flag.String("data", "data", "data directory (log/, envelopes/, state.db)")
	logKey := flag.String("log-key", "keys/log.key", "log signing key; its .pub must sit next to it")
	sysKey := flag.String("system-key", "keys/system.key", "system source key (kirowen keygen)")
	listen := flag.String("listen", ":8080", "HTTP listen address")
	logURL := flag.String("log-url", "", "public URL of the log, reported by GET /v0/")
	trustProxy := flag.Bool("trust-proxy", false, "take client IPs from X-Forwarded-For (only behind a proxy)")
	flag.Parse()

	if err := run(*dataDir, *logKey, *sysKey, *listen, *logURL, *trustProxy); err != nil {
		slog.Error("kirowend", "err", err)
		os.Exit(1)
	}
}

func readNoteKeys(skeyPath string) (note.Signer, note.Verifier, error) {
	b, err := os.ReadFile(skeyPath)
	if err != nil {
		return nil, nil, err
	}
	s, err := note.NewSigner(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, nil, err
	}
	b, err = os.ReadFile(strings.TrimSuffix(skeyPath, ".key") + ".pub")
	if err != nil {
		return nil, nil, err
	}
	v, err := note.NewVerifier(strings.TrimSpace(string(b)))
	return s, v, err
}

func readSystemKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k struct {
		Seed string `json:"ed25519_seed"`
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(k.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("system key: bad ed25519_seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func run(dataDir, logKey, sysKeyPath, listen, logURL string, trustProxy bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	signer, verifier, err := readNoteKeys(logKey)
	if err != nil {
		return err
	}
	sysKey, err := readSystemKey(sysKeyPath)
	if err != nil {
		return err
	}
	// The registry and API outlive ctx until the HTTP server has drained.
	bg := context.Background()
	reg, err := registry.Open(bg, registry.Config{Dir: dataDir, Signer: signer, Verifier: verifier})
	if err != nil {
		return err
	}
	defer reg.Close(bg)
	st, err := state.Open(filepath.Join(dataDir, "state.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	srv, err := api.New(bg, api.Config{
		Registry: reg, State: st, SystemKey: sysKey, LogURL: logURL, TrustProxy: trustProxy,
	})
	if err != nil {
		return err
	}

	hs := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	slog.Info("kirowend listening", "addr", listen, "origin", reg.Origin())

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	sctx, cancel := context.WithTimeout(bg, 30*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}
