// Package state is the registry's private state, kept in SQLite: sources
// and their token hashes, source keys, objects and their heads, and the
// index from envelope hash to leaf position.
//
// None of it is needed to verify the log. It is what lets the registry
// enforce the stateful acceptance rules (docs/envelope-v0.md §3.3) and
// serve per-object histories. Tokens are never stored, only their SHA-256.
package state

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("state: not found")

// SystemSource is the reserved source id of the system source.
var SystemSource = make([]byte, 16)

const schema = `
CREATE TABLE IF NOT EXISTS sources (
	id          BLOB PRIMARY KEY,
	token_hash  BLOB UNIQUE,
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
	id          BLOB PRIMARY KEY,
	source_id   BLOB NOT NULL REFERENCES sources(id),
	public_key  BLOB NOT NULL,
	next_kseq   INTEGER NOT NULL DEFAULT 0,
	statement   BLOB NOT NULL,
	event_hash  BLOB NOT NULL,
	revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS keys_source ON keys(source_id);
CREATE TABLE IF NOT EXISTS objects (
	id          BLOB PRIMARY KEY,
	source_id   BLOB NOT NULL REFERENCES sources(id),
	next_oseq   INTEGER NOT NULL DEFAULT 0,
	last_hash   BLOB,
	created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS objects_source ON objects(source_id);
CREATE TABLE IF NOT EXISTS events (
	hash        BLOB PRIMARY KEY,
	source_id   BLOB NOT NULL REFERENCES sources(id),
	object_id   BLOB NOT NULL REFERENCES objects(id),
	oseq        INTEGER NOT NULL,
	key_id      BLOB NOT NULL REFERENCES keys(id),
	kseq        INTEGER NOT NULL,
	leaf_index  INTEGER UNIQUE,
	created_at  INTEGER NOT NULL,
	UNIQUE (object_id, oseq),
	UNIQUE (key_id, kseq)
);
CREATE INDEX IF NOT EXISTS events_source_time ON events(source_id, created_at);
`

// Store is the state database. Writes are expected to be serialized by
// the caller; each write method is one transaction.
type Store struct{ db *sql.DB }

// Open opens or creates the database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("state: schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Key is a source key.
type Key struct {
	ID        []byte
	Source    []byte
	Public    []byte
	NextKSeq  uint64
	Statement []byte // the key statement whose hash was logged
	EventHash []byte // envelope hash of the event that registered it
	Revoked   bool
}

// Object is an object and its head.
type Object struct {
	ID       []byte
	Source   []byte
	NextOSeq uint64
	LastHash []byte // nil if the object has no events yet
}

// Event is an accepted envelope.
type Event struct {
	Hash      []byte
	Source    []byte
	Object    []byte
	OSeq      uint64
	KeyID     []byte
	KSeq      uint64
	LeafIndex *uint64 // nil while pending
	CreatedAt int64
}

func now() int64 { return time.Now().Unix() }

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// --- reads ---

// SourceByToken returns the source id for a token hash.
func (s *Store) SourceByToken(tokenHash []byte) ([]byte, error) {
	var id []byte
	err := s.db.QueryRow(`SELECT id FROM sources WHERE token_hash = ?`, tokenHash).Scan(&id)
	return id, notFound(err)
}

// Key returns a key by id.
func (s *Store) Key(id []byte) (*Key, error) {
	k := &Key{ID: id}
	err := s.db.QueryRow(`SELECT source_id, public_key, next_kseq, statement, event_hash, revoked FROM keys WHERE id = ?`, id).
		Scan(&k.Source, &k.Public, &k.NextKSeq, &k.Statement, &k.EventHash, &k.Revoked)
	return k, notFound(err)
}

// KeysOf returns the keys of a source.
func (s *Store) KeysOf(source []byte) ([]Key, error) {
	rows, err := s.db.Query(`SELECT id, public_key, next_kseq, statement, event_hash, revoked FROM keys WHERE source_id = ? ORDER BY rowid`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		k := Key{Source: source}
		if err := rows.Scan(&k.ID, &k.Public, &k.NextKSeq, &k.Statement, &k.EventHash, &k.Revoked); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Object returns an object by id.
func (s *Store) Object(id []byte) (*Object, error) {
	o := &Object{ID: id}
	err := s.db.QueryRow(`SELECT source_id, next_oseq, last_hash FROM objects WHERE id = ?`, id).
		Scan(&o.Source, &o.NextOSeq, &o.LastHash)
	return o, notFound(err)
}

// Event returns an event by envelope hash.
func (s *Store) Event(hash []byte) (*Event, error) {
	e := &Event{Hash: hash}
	var idx sql.NullInt64
	err := s.db.QueryRow(`SELECT source_id, object_id, oseq, key_id, kseq, leaf_index, created_at FROM events WHERE hash = ?`, hash).
		Scan(&e.Source, &e.Object, &e.OSeq, &e.KeyID, &e.KSeq, &idx, &e.CreatedAt)
	if idx.Valid {
		i := uint64(idx.Int64)
		e.LeafIndex = &i
	}
	return e, notFound(err)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var idx sql.NullInt64
		if err := rows.Scan(&e.Hash, &e.Source, &e.Object, &e.OSeq, &e.KeyID, &e.KSeq, &idx, &e.CreatedAt); err != nil {
			return nil, err
		}
		if idx.Valid {
			i := uint64(idx.Int64)
			e.LeafIndex = &i
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const eventCols = `hash, source_id, object_id, oseq, key_id, kseq, leaf_index, created_at`

// ObjectEvents returns an object's events in oseq order.
func (s *Store) ObjectEvents(object []byte) ([]Event, error) {
	rows, err := s.db.Query(`SELECT `+eventCols+` FROM events WHERE object_id = ? ORDER BY oseq`, object)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

// Pending returns events whose leaf index is not known yet.
func (s *Store) Pending() ([]Event, error) {
	rows, err := s.db.Query(`SELECT ` + eventCols + ` FROM events WHERE leaf_index IS NULL`)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

// NextUnconfirmedFrom returns one past the highest known leaf index (0 if none).
func (s *Store) NextUnconfirmedFrom() (uint64, error) {
	var m sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(leaf_index) FROM events`).Scan(&m); err != nil {
		return 0, err
	}
	if !m.Valid {
		return 0, nil
	}
	return uint64(m.Int64) + 1, nil
}

// CountObjects returns the number of objects owned by a source.
func (s *Store) CountObjects(source []byte) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM objects WHERE source_id = ?`, source).Scan(&n)
	return n, err
}

// CountEventsSince returns the number of events a source sent since t.
func (s *Store) CountEventsSince(source []byte, t time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE source_id = ? AND created_at >= ?`, source, t.Unix()).Scan(&n)
	return n, err
}

// --- writes ---

func (s *Store) tx(f func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := f(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func execAll(tx *sql.Tx, stmts ...func(*sql.Tx) error) error {
	for _, f := range stmts {
		if err := f(tx); err != nil {
			return err
		}
	}
	return nil
}

func insertSource(id, tokenHash []byte) func(*sql.Tx) error {
	return func(tx *sql.Tx) error {
		var th any
		if tokenHash != nil {
			th = tokenHash
		}
		_, err := tx.Exec(`INSERT INTO sources (id, token_hash, created_at) VALUES (?, ?, ?)`, id, th, now())
		return err
	}
}

func insertKey(k Key) func(*sql.Tx) error {
	return func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO keys (id, source_id, public_key, statement, event_hash) VALUES (?, ?, ?, ?, ?)`,
			k.ID, k.Source, k.Public, k.Statement, k.EventHash)
		return err
	}
}

func insertObject(id, source []byte) func(*sql.Tx) error {
	return func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO objects (id, source_id, created_at) VALUES (?, ?, ?)`, id, source, now())
		return err
	}
}

// acceptEvent inserts a pending event and advances its object and key heads.
func acceptEvent(e Event) func(*sql.Tx) error {
	return func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO events (hash, source_id, object_id, oseq, key_id, kseq, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			e.Hash, e.Source, e.Object, e.OSeq, e.KeyID, e.KSeq, now()); err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE objects SET next_oseq = next_oseq + 1, last_hash = ? WHERE id = ? AND next_oseq = ?`, e.Hash, e.Object, e.OSeq)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("state: object head moved")
		}
		res, err = tx.Exec(`UPDATE keys SET next_kseq = next_kseq + 1 WHERE id = ? AND next_kseq = ?`, e.KeyID, e.KSeq)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("state: key sequence moved")
		}
		return nil
	}
}

// InitSystem records the system source, its key and the event that
// registered that key on the system object (whose id is the system
// source id).
func (s *Store) InitSystem(key Key, ev Event) error {
	return s.tx(func(tx *sql.Tx) error {
		return execAll(tx, insertSource(SystemSource, nil), insertKey(key), insertObject(SystemSource, SystemSource), acceptEvent(ev))
	})
}

// Register creates a source with its token hash and first key, plus the
// system event that registers the key. The key's history lives on a
// system object whose id is the new source id.
func (s *Store) Register(source, tokenHash []byte, key Key, ev Event) error {
	return s.tx(func(tx *sql.Tx) error {
		return execAll(tx, insertSource(source, tokenHash), insertKey(key), insertObject(source, SystemSource), acceptEvent(ev))
	})
}

// CreateObject creates an empty object owned by source.
func (s *Store) CreateObject(id, source []byte) error {
	return s.tx(func(tx *sql.Tx) error { return insertObject(id, source)(tx) })
}

// AcceptEvent records a pending event and advances the heads.
func (s *Store) AcceptEvent(e Event) error {
	return s.tx(func(tx *sql.Tx) error { return acceptEvent(e)(tx) })
}

// SetLeafIndex records where an event landed in the log.
func (s *Store) SetLeafIndex(hash []byte, index uint64) error {
	_, err := s.db.Exec(`UPDATE events SET leaf_index = ? WHERE hash = ?`, index, hash)
	return err
}

// Rollback deletes pending events that never reached the log, and
// recomputes the heads of the objects and keys they touched. If one of
// them registered a source, that whole registration (source, keys,
// objects) is removed too: it never existed in the log.
func (s *Store) Rollback(hashes [][]byte) error {
	return s.tx(func(tx *sql.Tx) error {
		objs, keys := map[string]bool{}, map[string]bool{}
		for _, h := range hashes {
			var obj, kid []byte
			if err := tx.QueryRow(`SELECT object_id, key_id FROM events WHERE hash = ? AND leaf_index IS NULL`, h).Scan(&obj, &kid); err != nil {
				return notFound(err)
			}
			if _, err := tx.Exec(`DELETE FROM events WHERE hash = ?`, h); err != nil {
				return err
			}
			objs[string(obj)], keys[string(kid)] = true, true
		}
		for _, h := range hashes {
			var src []byte
			err := tx.QueryRow(`SELECT source_id FROM keys WHERE event_hash = ?`, h).Scan(&src)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM events WHERE source_id = ?`, src).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return fmt.Errorf("state: rolled-back source %x still has logged events", src)
			}
			for _, q := range []string{
				`DELETE FROM objects WHERE source_id = ?1 OR id = ?1`,
				`DELETE FROM keys WHERE source_id = ?1`,
				`DELETE FROM sources WHERE id = ?1`,
			} {
				if _, err := tx.Exec(q, src); err != nil {
					return err
				}
			}
			delete(objs, string(src))
		}
		for o := range objs {
			if _, err := tx.Exec(`UPDATE objects SET
				next_oseq = COALESCE((SELECT MAX(oseq) + 1 FROM events WHERE object_id = ?1), 0),
				last_hash = (SELECT hash FROM events WHERE object_id = ?1 ORDER BY oseq DESC LIMIT 1)
				WHERE id = ?1`, []byte(o)); err != nil {
				return err
			}
		}
		for k := range keys {
			if _, err := tx.Exec(`UPDATE keys SET next_kseq = COALESCE((SELECT MAX(kseq) + 1 FROM events WHERE key_id = ?1), 0) WHERE id = ?1`, []byte(k)); err != nil {
				return err
			}
		}
		return nil
	})
}
