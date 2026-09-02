package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var errInteropNoteConflict = errors.New("interop note request key conflicts with retained input")

type interopNoteResult struct {
	NoteID           string `json:"note_id"`
	Person           string `json:"person"`
	Text             string `json:"text"`
	Replayed         bool   `json:"replayed"`
	ConsequenceCount int    `json:"consequence_count"`
}

type interopNoteRecord struct {
	RequestKey string `json:"request_key"`
	NoteID     string `json:"note_id"`
	Person     string `json:"person"`
	Text       string `json:"text"`
}

type interopNoteState struct {
	Records map[string]interopNoteRecord `json:"records"`
}

type interopNoteStore struct {
	mu   sync.Mutex
	path string
}

func newInteropNoteStore(path string) *interopNoteStore {
	return &interopNoteStore{path: path}
}

func (store *interopNoteStore) Create(requestKey, text, person string) (interopNoteResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if requestKey == "" || text == "" || person == "" {
		return interopNoteResult{}, errors.New("request key, note text, and person are required")
	}
	state, err := store.load()
	if err != nil {
		return interopNoteResult{}, err
	}
	if retained, ok := state.Records[requestKey]; ok {
		if retained.Text != text || retained.Person != person {
			return interopNoteResult{}, errInteropNoteConflict
		}
		return noteResult(retained, true, len(state.Records)), nil
	}
	record := interopNoteRecord{
		RequestKey: requestKey, NoteID: fmt.Sprintf("note-%d", len(state.Records)+1),
		Person: person, Text: text,
	}
	state.Records[requestKey] = record
	if err := store.save(state); err != nil {
		return interopNoteResult{}, err
	}
	return noteResult(record, false, len(state.Records)), nil
}

func noteResult(record interopNoteRecord, replayed bool, count int) interopNoteResult {
	return interopNoteResult{
		NoteID: record.NoteID, Person: record.Person, Text: record.Text,
		Replayed: replayed, ConsequenceCount: count,
	}
}

func (store *interopNoteStore) load() (interopNoteState, error) {
	state := interopNoteState{Records: make(map[string]interopNoteRecord)}
	exact, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return interopNoteState{}, err
	}
	if err := json.Unmarshal(exact, &state); err != nil {
		return interopNoteState{}, err
	}
	if state.Records == nil {
		state.Records = make(map[string]interopNoteRecord)
	}
	return state, nil
}

func (store *interopNoteStore) save(state interopNoteState) error {
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".notes-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := json.NewEncoder(temporary).Encode(state); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return err
	}
	remove = false
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
