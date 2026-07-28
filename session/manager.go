package session

import (
	"context"
	"fmt"
	"sync"
)

// ManagedSession adapts a recorded Session Manager role to the Session
// interface consumed by Raptor. Refresh always replays the recorded login
// protocol in a clean browser and captures fresh cookies/storage/tokens.
type ManagedSession struct {
	store *Store
	id    string
	mu    sync.RWMutex
	state *State
}

func NewManagedSession(store *Store, sessionID string) *ManagedSession {
	return &ManagedSession{store: store, id: sessionID}
}

func (s *ManagedSession) ID() string { return s.id }

func (s *ManagedSession) State(ctx context.Context) (*State, error) {
	s.mu.RLock()
	if s.state != nil {
		state, err := cloneState(s.state)
		s.mu.RUnlock()
		return state, err
	}
	s.mu.RUnlock()

	injected, err := InjectSession(ctx, s.store, s.id)
	if err != nil {
		return nil, err
	}
	defer injected.Close()
	state, err := CaptureState(injected.Ctx, s.id)
	if err != nil {
		return nil, err
	}
	s.setState(state)
	return cloneState(state)
}

func (s *ManagedSession) Refresh(ctx context.Context) (*State, error) {
	sep, err := s.store.LoadSEP(s.id)
	if err != nil {
		return nil, fmt.Errorf("load login replay for %s: %w", s.id, err)
	}
	provider := NewChromiumProvider(ChromiumOptions{Headless: true})
	browser, err := provider.NewContext(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer browser.Close()
	if err := ReplaySEP(ctx, browser.Context(), sep); err != nil {
		return nil, fmt.Errorf("refresh session %s: %w", s.id, err)
	}
	state, err := CaptureState(browser.Context(), s.id)
	if err != nil {
		return nil, err
	}
	s.setState(state)
	return cloneState(state)
}

func (s *ManagedSession) Export(ctx context.Context, path string, refresh bool) error {
	var state *State
	var err error
	if refresh {
		state, err = s.Refresh(ctx)
	} else {
		state, err = s.State(ctx)
	}
	if err != nil {
		return err
	}
	return SaveState(path, state)
}

func (s *ManagedSession) setState(state *State) {
	s.mu.Lock()
	s.state = state
	s.mu.Unlock()
}
