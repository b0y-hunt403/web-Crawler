package session

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// State is Raptor's browser-neutral storage-state format. It is compatible
// with Playwright's cookies/origins shape and extends it with sessionStorage
// and extracted token metadata.
type State struct {
	ID        string        `json:"id,omitempty"`
	Cookies   []StateCookie `json:"cookies"`
	Origins   []OriginState `json:"origins"`
	Tokens    []Token       `json:"tokens,omitempty"`
	CreatedAt time.Time     `json:"created_at,omitempty"`
}

type StateCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires,omitempty"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	SameSite string  `json:"sameSite,omitempty"`
}

type StorageValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type OriginState struct {
	Origin         string         `json:"origin"`
	LocalStorage   []StorageValue `json:"localStorage,omitempty"`
	SessionStorage []StorageValue `json:"sessionStorage,omitempty"`
}

type Token struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"`
	Kind   string `json:"kind"`
}

// Session supplies reusable browser state. Authentication implementations
// may refresh by replaying a login flow; file sessions simply reload the file.
type Session interface {
	ID() string
	State(context.Context) (*State, error)
	Refresh(context.Context) (*State, error)
}

// BrowserContext is a ready-to-crawl browser context owned by its provider.
type BrowserContext interface {
	Context() context.Context
	ApplyState(context.Context, *State) error
	Close() error
}

// BrowserContextProvider creates isolated contexts. The crawler never needs
// to know whether the context came from Playwright, chromedp, or another engine.
type BrowserContextProvider interface {
	NewContext(context.Context, *State) (BrowserContext, error)
}

// FileSession loads a storage_state-style JSON document.
type FileSession struct {
	path  string
	mu    sync.RWMutex
	state *State
}

func NewFileSession(path string) (*FileSession, error) {
	session := &FileSession{path: path}
	if _, err := session.Refresh(context.Background()); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *FileSession) ID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state != nil && s.state.ID != "" {
		return s.state.ID
	}
	return s.path
}

func (s *FileSession) State(context.Context) (*State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil, fmt.Errorf("session state is not loaded")
	}
	return cloneState(s.state)
}

func (s *FileSession) Refresh(context.Context) (*State, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read session state %s: %w", s.path, err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode session state %s: %w", s.path, err)
	}
	state.Tokens = mergeTokens(state.Tokens, ExtractTokens(&state))
	s.mu.Lock()
	s.state = &state
	s.mu.Unlock()
	return cloneState(&state)
}

func SaveState(path string, state *State) error {
	if state == nil {
		return fmt.Errorf("cannot save a nil session state")
	}
	state.Tokens = mergeTokens(state.Tokens, ExtractTokens(state))
	if state.CreatedAt.IsZero() {
		state.CreatedAt = time.Now().UTC()
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write session state %s: %w", path, err)
	}
	return nil
}

type ChromiumOptions struct {
	UserAgent string
	Proxy     string
	Headless  bool
}

type ChromiumProvider struct {
	options ChromiumOptions
}

func NewChromiumProvider(options ChromiumOptions) *ChromiumProvider {
	return &ChromiumProvider{options: options}
}

// ExistingChromiumProvider lets a Session Manager hand Raptor an already
// created chromedp context. The original owner retains lifecycle control.
type ExistingChromiumProvider struct {
	ctx context.Context
}

func NewExistingChromiumProvider(ctx context.Context) *ExistingChromiumProvider {
	return &ExistingChromiumProvider{ctx: ctx}
}

func (p *ExistingChromiumProvider) NewContext(ctx context.Context, state *State) (BrowserContext, error) {
	if p.ctx == nil {
		return nil, fmt.Errorf("existing Chromium context is nil")
	}
	handle := &chromiumContext{ctx: p.ctx}
	if err := handle.ApplyState(ctx, state); err != nil {
		return nil, err
	}
	return handle, nil
}

func (p *ChromiumProvider) NewContext(parent context.Context, state *State) (BrowserContext, error) {
	options := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", p.options.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	if p.options.UserAgent != "" {
		options = append(options, chromedp.UserAgent(p.options.UserAgent))
	}
	if p.options.Proxy != "" {
		options = append(options, chromedp.ProxyServer(p.options.Proxy))
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(parent, options...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	handle := &chromiumContext{
		ctx: browserCtx, cancelBrowser: browserCancel, cancelAllocator: allocCancel,
	}
	if err := chromedp.Run(browserCtx, network.Enable()); err != nil {
		handle.Close()
		return nil, fmt.Errorf("start Chromium context: %w", err)
	}
	if err := handle.ApplyState(browserCtx, state); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}

type chromiumContext struct {
	ctx             context.Context
	cancelBrowser   context.CancelFunc
	cancelAllocator context.CancelFunc
	mu              sync.Mutex
	closed          bool
}

func (c *chromiumContext) Context() context.Context { return c.ctx }

func (c *chromiumContext) ApplyState(ctx context.Context, state *State) error {
	if state == nil {
		return nil
	}
	cookies := make([]*network.CookieParam, 0, len(state.Cookies))
	for _, cookie := range state.Cookies {
		param := &network.CookieParam{
			Name: cookie.Name, Value: cookie.Value, Domain: cookie.Domain, Path: cookie.Path,
			HTTPOnly: cookie.HTTPOnly, Secure: cookie.Secure,
		}
		switch strings.ToLower(cookie.SameSite) {
		case "strict":
			param.SameSite = network.CookieSameSiteStrict
		case "lax":
			param.SameSite = network.CookieSameSiteLax
		case "none":
			param.SameSite = network.CookieSameSiteNone
		}
		if cookie.Expires > 0 {
			expires := cdp.TimeSinceEpoch(time.Unix(int64(cookie.Expires), 0))
			param.Expires = &expires
		}
		cookies = append(cookies, param)
	}
	actions := []chromedp.Action{network.Enable(), network.ClearBrowserCookies()}
	if len(cookies) > 0 {
		actions = append(actions, network.SetCookies(cookies))
	}
	script, err := storageInitScript(state.Origins)
	if err != nil {
		return err
	}
	if script != "" {
		actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(script).Do(ctx)
			return err
		}))
	}
	if err := chromedp.Run(c.ctx, actions...); err != nil {
		return fmt.Errorf("apply browser session state: %w", err)
	}
	return nil
}

func (c *chromiumContext) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.cancelBrowser != nil {
		c.cancelBrowser()
	}
	if c.cancelAllocator != nil {
		c.cancelAllocator()
	}
	return nil
}

func storageInitScript(origins []OriginState) (string, error) {
	if len(origins) == 0 {
		return "", nil
	}
	data, err := json.Marshal(origins)
	if err != nil {
		return "", fmt.Errorf("encode origin storage: %w", err)
	}
	return fmt.Sprintf(`(() => {
	  const origins = %s;
	  const state = origins.find(item => item.origin === location.origin);
	  if (!state) return;
	  localStorage.clear();
	  sessionStorage.clear();
	  for (const item of state.localStorage || []) localStorage.setItem(item.name, item.value);
	  for (const item of state.sessionStorage || []) sessionStorage.setItem(item.name, item.value);
	})()`, data), nil
}

// CaptureState snapshots cookies and storage from the current page.
func CaptureState(ctx context.Context, id string) (*State, error) {
	var cookies []*network.Cookie
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		cookies, err = network.GetCookies().Do(ctx)
		return err
	})); err != nil {
		return nil, fmt.Errorf("capture cookies: %w", err)
	}
	state := &State{ID: id, CreatedAt: time.Now().UTC()}
	for _, cookie := range cookies {
		state.Cookies = append(state.Cookies, StateCookie{
			Name: cookie.Name, Value: cookie.Value, Domain: cookie.Domain, Path: cookie.Path,
			Expires: cookie.Expires, HTTPOnly: cookie.HTTPOnly, Secure: cookie.Secure,
			SameSite: string(cookie.SameSite),
		})
	}
	var storageJSON string
	err := chromedp.Run(ctx, chromedp.Evaluate(`JSON.stringify({
	  origin: location.origin,
	  localStorage: Object.entries(localStorage).map(([name,value]) => ({name,value})),
	  sessionStorage: Object.entries(sessionStorage).map(([name,value]) => ({name,value})),
	  csrfTokens: Array.from(document.querySelectorAll(
	    'input[type="hidden"][name*="csrf" i],input[type="hidden"][name*="xsrf" i],meta[name*="csrf" i]'
	  )).map(el => ({
	    name: el.getAttribute('name') || 'csrf',
	    value: el.value || el.getAttribute('content') || ''
	  })).filter(item => item.value)
	})`, &storageJSON))
	if err == nil {
		var pageState struct {
			Origin         string         `json:"origin"`
			LocalStorage   []StorageValue `json:"localStorage"`
			SessionStorage []StorageValue `json:"sessionStorage"`
			CSRFTokens     []StorageValue `json:"csrfTokens"`
		}
		if json.Unmarshal([]byte(storageJSON), &pageState) == nil && pageState.Origin != "" && pageState.Origin != "null" {
			state.Origins = append(state.Origins, OriginState{
				Origin: pageState.Origin, LocalStorage: pageState.LocalStorage, SessionStorage: pageState.SessionStorage,
			})
			for _, token := range pageState.CSRFTokens {
				state.Tokens = append(state.Tokens, Token{Name: token.Name, Value: token.Value, Source: "dom", Kind: "csrf"})
			}
		}
	}
	state.Tokens = mergeTokens(state.Tokens, ExtractTokens(state))
	return state, nil
}

func ExtractTokens(state *State) []Token {
	if state == nil {
		return nil
	}
	var tokens []Token
	for _, cookie := range state.Cookies {
		name := strings.ToLower(cookie.Name)
		switch {
		case strings.Contains(name, "csrf") || strings.Contains(name, "xsrf"):
			tokens = append(tokens, Token{Name: cookie.Name, Value: cookie.Value, Source: "cookie", Kind: "csrf"})
		case looksLikeJWT(cookie.Value):
			tokens = append(tokens, Token{Name: cookie.Name, Value: cookie.Value, Source: "cookie", Kind: "jwt"})
		}
	}
	for _, origin := range state.Origins {
		for _, storage := range []struct {
			source string
			values []StorageValue
		}{{"localStorage", origin.LocalStorage}, {"sessionStorage", origin.SessionStorage}} {
			for _, item := range storage.values {
				name := strings.ToLower(item.Name)
				kind := ""
				switch {
				case strings.Contains(name, "csrf") || strings.Contains(name, "xsrf"):
					kind = "csrf"
				case looksLikeJWT(item.Value):
					kind = "jwt"
				case strings.Contains(name, "token") || name == "authorization":
					kind = "token"
				}
				if kind != "" {
					tokens = append(tokens, Token{Name: item.Name, Value: item.Value, Source: storage.source, Kind: kind})
				}
			}
		}
	}
	return mergeTokens(nil, tokens)
}

func looksLikeJWT(value string) bool {
	value = strings.TrimPrefix(strings.TrimSpace(value), "Bearer ")
	return strings.Count(value, ".") == 2 && strings.HasPrefix(value, "eyJ")
}

func mergeTokens(existing, discovered []Token) []Token {
	seen := make(map[string]struct{})
	out := make([]Token, 0, len(existing)+len(discovered))
	for _, token := range append(existing, discovered...) {
		key := token.Source + "\x00" + token.Name + "\x00" + token.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, token)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func cloneState(state *State) (*State, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	var clone State
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, err
	}
	return &clone, nil
}
