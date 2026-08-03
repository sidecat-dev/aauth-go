package reference

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
)

var (
	ErrR3IssuanceNotFound  = errors.New("reference: R3 per-call issuance was not found")
	ErrR3IssuanceCollision = errors.New("reference: R3 resource-token issuance identity collided")
	ErrR3IssuanceCapacity  = errors.New("reference: R3 per-call issuance capacity is exhausted")
	ErrR3IssuanceIntegrity = errors.New("reference: R3 per-call issuance integrity check failed")
)

// R3PerCallIssuance is the atomic recovery candidate for one proposal resource
// token. AuthToken is retained exactly so a lost response can be recovered
// without minting a second usable token. Audit carries the stable identity and
// semantics needed to retry the independent durable R3Audit before release.
type R3PerCallIssuance struct {
	Schema                   string              `json:"schema"`
	Resource                 string              `json:"resource"`
	ResourceTokenID          string              `json:"resource_token_id"`
	ResourceTokenFingerprint string              `json:"resource_token_fingerprint"`
	AuthToken                string              `json:"auth_token"`
	ExpiresAt                time.Time           `json:"expires_at"`
	Audit                    aauth.R3AuditRecord `json:"audit"`
}

// R3PerCallIssuanceStore atomically commits or recovers the one exact auth
// token and candidate audit associated with a proposal resource token. It is
// short-lived token recovery custody, not the durable audit system of record.
type R3PerCallIssuanceStore interface {
	Load(context.Context, string, string, string) (R3PerCallIssuance, error)
	Commit(context.Context, R3PerCallIssuance) (R3PerCallIssuance, error)
}

type FileR3PerCallIssuanceStoreConfig struct {
	Directory  string
	Clock      aauth.Clock
	MaxRecords int
}

// FileR3PerCallIssuanceStore is a bounded, single-writer, restart-safe
// reference implementation. Each resource-token identity owns one mode-0600
// atomically replaced JSON record.
type FileR3PerCallIssuanceStore struct {
	directory  string
	clock      aauth.Clock
	maxRecords int

	mu      sync.Mutex
	records map[string]time.Time
}

func OpenFileR3PerCallIssuanceStore(
	config FileR3PerCallIssuanceStoreConfig,
) (*FileR3PerCallIssuanceStore, error) {
	if config.Clock == nil {
		return nil, errors.New("reference: R3 issuance store requires a clock")
	}
	directory, err := filepath.Abs(config.Directory)
	if err != nil || config.Directory == "" || filepath.Clean(directory) != directory {
		return nil, errors.New("reference: R3 issuance store directory is invalid")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("reference: create R3 issuance store: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("reference: R3 issuance store directory is unsafe")
	}
	maxRecords := config.MaxRecords
	if maxRecords == 0 {
		maxRecords = 1024
	}
	if maxRecords < 0 {
		return nil, errors.New("reference: R3 issuance store record limit is invalid")
	}
	store := &FileR3PerCallIssuanceStore{
		directory:  directory,
		clock:      config.Clock,
		maxRecords: maxRecords,
		records:    make(map[string]time.Time),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *FileR3PerCallIssuanceStore) Load(
	ctx context.Context,
	resource string,
	resourceTokenID string,
	fingerprint string,
) (R3PerCallIssuance, error) {
	var zero R3PerCallIssuance
	if err := contextError(ctx); err != nil {
		return zero, err
	}
	key, err := r3IssuanceKey(resource, resourceTokenID)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	expiresAt, exists := store.records[key]
	if !exists {
		return zero, ErrR3IssuanceNotFound
	}
	if !expiresAt.After(store.clock.Now()) {
		if err := store.remove(key); err != nil {
			return zero, err
		}
		return zero, ErrR3IssuanceNotFound
	}
	record, err := store.read(key)
	if err != nil {
		return zero, err
	}
	if record.Resource != resource || record.ResourceTokenID != resourceTokenID {
		return zero, ErrR3IssuanceIntegrity
	}
	if record.ResourceTokenFingerprint != fingerprint {
		return zero, ErrR3IssuanceCollision
	}
	return record, nil
}

func (store *FileR3PerCallIssuanceStore) Commit(
	ctx context.Context,
	candidate R3PerCallIssuance,
) (R3PerCallIssuance, error) {
	var zero R3PerCallIssuance
	if err := contextError(ctx); err != nil {
		return zero, err
	}
	if err := validateR3PerCallIssuance(candidate, store.clock.Now()); err != nil {
		return zero, err
	}
	key, err := r3IssuanceKey(candidate.Resource, candidate.ResourceTokenID)
	if err != nil {
		return zero, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.removeExpired(store.clock.Now()); err != nil {
		return zero, err
	}
	if _, exists := store.records[key]; exists {
		existing, err := store.read(key)
		if err != nil {
			return zero, err
		}
		if existing.ResourceTokenFingerprint != candidate.ResourceTokenFingerprint {
			return zero, ErrR3IssuanceCollision
		}
		return existing, nil
	}
	if len(store.records) >= store.maxRecords {
		return zero, ErrR3IssuanceCapacity
	}
	candidate.Schema = "aauth.reference.r3-per-call-issuance.v1"
	if err := store.write(key, candidate); err != nil {
		return zero, err
	}
	store.records[key] = candidate.ExpiresAt.UTC()
	return candidate, nil
}

func validateR3PerCallIssuance(record R3PerCallIssuance, now time.Time) error {
	if err := aauth.ValidateServerIdentifier(record.Resource); err != nil {
		return err
	}
	if record.ResourceTokenID == "" || record.ResourceTokenFingerprint == "" ||
		record.AuthToken == "" || !record.ExpiresAt.After(now) {
		return errors.New("reference: R3 per-call issuance is incomplete")
	}
	if record.Audit.Resource != record.Resource ||
		record.Audit.ResourceTokenID != record.ResourceTokenID ||
		record.Audit.R3URI == "" || record.Audit.R3S256 == "" ||
		record.Audit.Agent == "" || record.Audit.TokenID == "" ||
		record.Audit.IssuedAt.IsZero() || record.Audit.IssuedAt.After(record.ExpiresAt) {
		return errors.New("reference: R3 per-call issuance audit is incomplete")
	}
	if record.Audit.R3Granted == nil || record.Audit.R3Granted.Validate() != nil ||
		len(record.Audit.R3Granted.Operations) != 1 || record.Audit.R3Conditional != nil {
		return errors.New("reference: R3 per-call issuance audit does not retain one direct operation")
	}
	if record.Audit.Mission != nil && record.Audit.Mission.Validate() != nil {
		return errors.New("reference: R3 per-call issuance audit contains an invalid mission")
	}
	return nil
}

func (store *FileR3PerCallIssuanceStore) load() error {
	entries, err := os.ReadDir(store.directory)
	if err != nil {
		return fmt.Errorf("reference: read R3 issuance store: %w", err)
	}
	now := store.clock.Now()
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".r3-issuance-") {
			if entry.Type().IsRegular() {
				_ = os.Remove(filepath.Join(store.directory, name))
			}
			continue
		}
		key, ok := fileR3IssuanceKey(name)
		if !ok || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("reference: R3 issuance store contains unexpected entry %q", name)
		}
		record, err := store.read(key)
		if err != nil {
			return err
		}
		if !record.ExpiresAt.After(now) {
			if err := os.Remove(filepath.Join(store.directory, name)); err != nil {
				return fmt.Errorf("reference: remove expired R3 issuance: %w", err)
			}
			continue
		}
		if len(store.records) >= store.maxRecords {
			return errors.New("reference: retained R3 issuances exceed configured capacity")
		}
		store.records[key] = record.ExpiresAt.UTC()
	}
	return syncR3Directory(store.directory)
}

func (store *FileR3PerCallIssuanceStore) removeExpired(now time.Time) error {
	for key, expiresAt := range store.records {
		if expiresAt.After(now) {
			continue
		}
		if err := store.remove(key); err != nil {
			return err
		}
	}
	return nil
}

func (store *FileR3PerCallIssuanceStore) remove(key string) error {
	path, err := store.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("reference: remove R3 issuance: %w", err)
	}
	delete(store.records, key)
	return syncR3Directory(store.directory)
}

func (store *FileR3PerCallIssuanceStore) read(key string) (R3PerCallIssuance, error) {
	var record R3PerCallIssuance
	path, err := store.path(key)
	if err != nil {
		return record, err
	}
	file, err := os.Open(path)
	if err != nil {
		return record, fmt.Errorf("reference: open R3 issuance: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return record, errors.New("reference: R3 issuance file is unsafe")
	}
	if err := decodeJSONBytes(io.LimitReader(file, maxJSONBody+1), &record); err != nil {
		return record, fmt.Errorf("reference: decode R3 issuance: %w", err)
	}
	if record.Schema != "aauth.reference.r3-per-call-issuance.v1" {
		return record, ErrR3IssuanceIntegrity
	}
	if err := validateR3PerCallIssuance(record, time.Unix(0, 1)); err != nil {
		return record, ErrR3IssuanceIntegrity
	}
	expected, err := r3IssuanceKey(record.Resource, record.ResourceTokenID)
	if err != nil || expected != key {
		return record, ErrR3IssuanceIntegrity
	}
	return record, nil
}

func (store *FileR3PerCallIssuanceStore) write(key string, record R3PerCallIssuance) error {
	path, err := store.path(key)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("reference: encode R3 issuance: %w", err)
	}
	if len(encoded) > maxJSONBody {
		return ErrR3IssuanceCapacity
	}
	temporary, err := os.CreateTemp(store.directory, ".r3-issuance-*")
	if err != nil {
		return fmt.Errorf("reference: create R3 issuance temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("reference: protect R3 issuance temporary file: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		return fmt.Errorf("reference: write R3 issuance: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("reference: sync R3 issuance: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("reference: close R3 issuance: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("reference: publish R3 issuance: %w", err)
	}
	return syncR3Directory(store.directory)
}

func (store *FileR3PerCallIssuanceStore) path(key string) (string, error) {
	canonical, ok := fileR3IssuanceKey(key + ".issuance")
	if !ok || canonical != key {
		return "", ErrR3IssuanceIntegrity
	}
	return filepath.Join(store.directory, key+".issuance"), nil
}

func r3IssuanceKey(resource, resourceTokenID string) (string, error) {
	if err := aauth.ValidateServerIdentifier(resource); err != nil || resourceTokenID == "" {
		return "", errors.New("reference: R3 issuance identity is invalid")
	}
	digest := sha256.Sum256([]byte(resource + "\x00" + resourceTokenID))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func fileR3IssuanceKey(name string) (string, bool) {
	if !strings.HasSuffix(name, ".issuance") {
		return "", false
	}
	key := strings.TrimSuffix(name, ".issuance")
	decoded, err := base64.RawURLEncoding.DecodeString(key)
	return key, len(key) == 43 && err == nil && len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == key
}
