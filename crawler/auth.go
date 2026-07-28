package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
)

type authPageState struct {
	URL           string `json:"url"`
	BodyText      string `json:"body_text"`
	HasLogout     bool   `json:"has_logout"`
	CSRFField     string `json:"csrf_field"`
	CSRFToken     string `json:"csrf_token"`
	UsernameField string `json:"username_field"`
	PasswordField string `json:"password_field"`
	FormAction    string `json:"form_action"`
}

type authExport struct {
	Session      *AuthSession      `json:"session"`
	CookieHeader string            `json:"cookie_header"`
	Headers      map[string]string `json:"headers"`
	ToolHints    map[string]string `json:"tool_hints"`
}

func (c *DynamicCrawler) authenticate(ctx context.Context) error {
	if !c.config.Auth.Enabled() {
		return nil
	}

	c.authMu.Lock()
	defer c.authMu.Unlock()

	cfg := c.config.Auth
	loginCtx, cancel := context.WithTimeout(c.browserCtx, c.config.RequestTimeout)
	defer cancel()

	if err := chromedp.Run(loginCtx, network.Enable(), chromedp.Navigate(cfg.LoginURL), chromedp.WaitReady("body", chromedp.ByQuery)); err != nil {
		return fmt.Errorf("open login page: %w", err)
	}

	before, err := readAuthPageState(loginCtx, cfg)
	if err != nil {
		return err
	}
	beforeCookies, _ := c.browserCookies(loginCtx)
	loginMethod := strings.ToLower(strings.TrimSpace(cfg.LoginMethod))
	if loginMethod == "" {
		loginMethod = "form"
	}

	var requestBody string
	var requestHeaders map[string]string
	switch loginMethod {
	case "form":
		requestBody, requestHeaders, err = submitFormLogin(loginCtx, cfg, before)
	case "json":
		requestBody, requestHeaders, err = submitJSONLogin(loginCtx, cfg, before)
	default:
		return fmt.Errorf("unsupported login method %q (expected form or json)", loginMethod)
	}
	if err != nil {
		return err
	}

	state, reason, err := c.waitForLoginSuccess(loginCtx, before.URL, beforeCookies)
	if err != nil {
		return err
	}
	if state.CSRFField == "" {
		state.CSRFField = before.CSRFField
		state.CSRFToken = before.CSRFToken
	}
	session, err := c.captureAuthSession(loginCtx, state, reason, loginMethod)
	if err != nil {
		return err
	}
	c.authSession = session
	c.authExpired = false

	contentType := HeaderValue(requestHeaders, "Content-Type")
	loginRequestURL := cfg.LoginURL
	if loginMethod == "form" && before.FormAction != "" {
		loginRequestURL = before.FormAction
	}
	c.emit(&DiscoveredRequest{
		ID:            CalculateFingerprint("POST", loginRequestURL, requestBody, contentType),
		AuthSessionID: session.ID,
		URL:           loginRequestURL,
		Method:        "POST",
		Headers:       requestHeaders,
		Body:          requestBody,
		BodyType:      bodyTypeFromContentType(contentType),
		SourceType:    "login_request",
		NormalizedURL: NormalizeURL(loginRequestURL),
		Parameters:    ExtractParameters(loginRequestURL, requestBody, contentType),
		Cookies:       parseCookieHeader(session.CookieHeader),
		JSONFormat:    ParseJSONFormat(requestBody, contentType),
		CreatedAt:     time.Now().UTC(),
	})
	if c.authCallback != nil {
		c.authCallback(session)
	}
	if cfg.CookieFile != "" {
		if err := exportAuthSession(cfg.CookieFile, session); err != nil {
			return fmt.Errorf("export authenticated session: %w", err)
		}
	}
	return nil
}

func readAuthPageState(ctx context.Context, cfg AuthConfig) (authPageState, error) {
	configJSON, _ := json.Marshal(cfg)
	script := fmt.Sprintf(`(() => {
	  const cfg = %s;
	  const byConfigured = (v) => {
	    if (!v) return null;
	    try { const q = document.querySelector(v); if (q) return q; } catch (_) {}
	    return document.querySelector('[name="' + CSS.escape(v) + '"],#' + CSS.escape(v));
	  };
	  const user = byConfigured(cfg.username_field) ||
	    document.querySelector('input[autocomplete="username"],input[type="email"],input[name*="user" i],input[name*="email" i],input[type="text"]');
	  const pass = byConfigured(cfg.password_field) ||
	    document.querySelector('input[autocomplete="current-password"],input[type="password"]');
	  const csrf = byConfigured(cfg.csrf_field) ||
	    document.querySelector('input[type="hidden"][name*="csrf" i],input[type="hidden"][name*="xsrf" i],input[type="hidden"][name*="token" i],meta[name="csrf-token"]');
	  return JSON.stringify({
	    url: location.href,
	    body_text: (document.body && document.body.innerText || '').slice(0, 200000),
	    has_logout: !!document.querySelector('a[href*="logout" i],button[id*="logout" i],button[name*="logout" i],[data-testid*="logout" i]'),
	    csrf_field: csrf ? (csrf.getAttribute('name') || cfg.csrf_field || '') : '',
	    csrf_token: csrf ? (csrf.value || csrf.getAttribute('content') || '') : '',
	    username_field: user ? (user.getAttribute('name') || user.id || '') : '',
	    password_field: pass ? (pass.getAttribute('name') || pass.id || '') : '',
	    form_action: pass && pass.form ? pass.form.action : (user && user.form ? user.form.action : '')
	  });
	})()`, configJSON)
	var raw string
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &raw)); err != nil {
		return authPageState{}, fmt.Errorf("inspect login page: %w", err)
	}
	var state authPageState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return state, fmt.Errorf("decode login page state: %w", err)
	}
	if state.UsernameField == "" || state.PasswordField == "" {
		return state, fmt.Errorf("could not detect login username/password fields")
	}
	return state, nil
}

func submitFormLogin(ctx context.Context, cfg AuthConfig, state authPageState) (string, map[string]string, error) {
	values := map[string]string{
		state.UsernameField: cfg.Username,
		state.PasswordField: cfg.Password,
	}
	if state.CSRFField != "" && state.CSRFToken != "" {
		values[state.CSRFField] = state.CSRFToken
	}
	bodyValues := url.Values{}
	for key, value := range values {
		bodyValues.Set(key, value)
	}

	cfgJSON, _ := json.Marshal(cfg)
	script := fmt.Sprintf(`(() => {
	  const cfg = %s;
	  const find = (v, fallback) => {
	    if (v) {
	      try { const q = document.querySelector(v); if (q) return q; } catch (_) {}
	      const q = document.querySelector('[name="' + CSS.escape(v) + '"],#' + CSS.escape(v));
	      if (q) return q;
	    }
	    return document.querySelector(fallback);
	  };
	  const user = find(cfg.username_field, 'input[autocomplete="username"],input[type="email"],input[name*="user" i],input[name*="email" i],input[type="text"]');
	  const pass = find(cfg.password_field, 'input[autocomplete="current-password"],input[type="password"]');
	  if (!user || !pass) throw new Error('login fields disappeared');
	  const set = (el, value) => {
	    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value');
	    if (setter && setter.set) setter.set.call(el, value); else el.value = value;
	    el.dispatchEvent(new Event('input', {bubbles:true}));
	    el.dispatchEvent(new Event('change', {bubbles:true}));
	  };
	  set(user, cfg.username); set(pass, cfg.password);
	  const form = pass.form || user.form || document.querySelector('form');
	  if (!form) throw new Error('login form not found');
	  if (form.requestSubmit) form.requestSubmit(); else form.submit();
	  return true;
	})()`, cfgJSON)
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, nil)); err != nil && !strings.Contains(err.Error(), "context canceled") {
		return "", nil, fmt.Errorf("submit login form: %w", err)
	}
	return bodyValues.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Referer":      state.URL,
		"Origin":       originOf(state.URL),
	}, nil
}

func submitJSONLogin(ctx context.Context, cfg AuthConfig, state authPageState) (string, map[string]string, error) {
	payload := map[string]string{state.UsernameField: cfg.Username, state.PasswordField: cfg.Password}
	headers := map[string]string{"Content-Type": "application/json", "Accept": "application/json"}
	if state.CSRFToken != "" {
		name := cfg.CSRFField
		if name == "" {
			name = "X-CSRF-Token"
		}
		headers[name] = state.CSRFToken
		if state.CSRFField != "" {
			payload[state.CSRFField] = state.CSRFToken
		}
	}
	body, _ := json.Marshal(payload)
	input, _ := json.Marshal(map[string]interface{}{"url": cfg.LoginURL, "body": string(body), "headers": headers})
	script := fmt.Sprintf(`(async () => {
	  const x = %s;
	  const response = await fetch(x.url, {method:'POST', credentials:'include', headers:x.headers, body:x.body});
	  const text = await response.text();
	  if (!response.ok) throw new Error('login returned HTTP ' + response.status + ': ' + text.slice(0,200));
	  try { const data = JSON.parse(text); if (data.redirect || data.redirect_url) location.href = data.redirect || data.redirect_url; } catch (_) {}
	  return response.status;
	})()`, input)
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, nil)); err != nil {
		return "", nil, fmt.Errorf("submit JSON login: %w", err)
	}
	headers["Referer"] = state.URL
	headers["Origin"] = originOf(state.URL)
	return string(body), headers, nil
}

func (c *DynamicCrawler) waitForLoginSuccess(ctx context.Context, initialURL string, initialCookies []CookieInfo) (authPageState, string, error) {
	deadline := time.Now().Add(c.config.RequestTimeout)
	var successRE *regexp.Regexp
	if c.config.Auth.SuccessRegex != "" {
		var err error
		successRE, err = regexp.Compile(c.config.Auth.SuccessRegex)
		if err != nil {
			return authPageState{}, "", fmt.Errorf("invalid login success regex: %w", err)
		}
	}
	for time.Now().Before(deadline) {
		var raw string
		err := chromedp.Run(ctx, chromedp.Sleep(300*time.Millisecond), chromedp.Evaluate(`JSON.stringify({
		  url: location.href,
		  body_text: (document.body && document.body.innerText || '').slice(0,200000),
		  has_logout: !!document.querySelector('a[href*="logout" i],button[id*="logout" i],button[name*="logout" i],[data-testid*="logout" i]')
		})`, &raw))
		if err == nil {
			var state authPageState
			if json.Unmarshal([]byte(raw), &state) == nil {
				switch {
				case successRE != nil && successRE.MatchString(state.URL+"\n"+state.BodyText):
					return state, "success_regex", nil
				case state.HasLogout:
					return state, "logout_control", nil
				case strings.Contains(strings.ToLower(state.URL), "dashboard") || strings.Contains(strings.ToLower(state.URL), "account"):
					return state, "authenticated_redirect", nil
				case state.URL != "" && NormalizeURL(state.URL) != NormalizeURL(initialURL):
					return state, "url_change", nil
				}
			}
		}
		if cookies, _ := c.browserCookies(ctx); len(cookies) > 0 {
			if c.config.Auth.SessionCookie != "" && hasCookie(cookies, c.config.Auth.SessionCookie) {
				return authPageState{URL: initialURL}, "session_cookie", nil
			}
			if hasNewCookie(initialCookies, cookies) {
				return authPageState{URL: initialURL}, "session_cookie_creation", nil
			}
		}
	}
	return authPageState{}, "", fmt.Errorf("login did not meet any success condition before timeout")
}

func (c *DynamicCrawler) captureAuthSession(ctx context.Context, state authPageState, reason, method string) (*AuthSession, error) {
	cookies, err := c.browserCookies(ctx)
	if err != nil {
		return nil, err
	}
	var storageRaw string
	_ = chromedp.Run(ctx, chromedp.Evaluate(`JSON.stringify({
	  origin: location.origin,
	  local_storage: Object.entries(localStorage).map(([name,value]) => ({name,value})),
	  session_storage: Object.entries(sessionStorage).map(([name,value]) => ({name,value}))
	})`, &storageRaw))
	var storage BrowserOriginStorage
	_ = json.Unmarshal([]byte(storageRaw), &storage)

	headerParts := make([]string, 0, len(cookies))
	var expiresAt *time.Time
	for _, cookie := range cookies {
		headerParts = append(headerParts, cookie.Name+"="+cookie.Value)
		if !cookie.Expires.IsZero() && (expiresAt == nil || cookie.Expires.Before(*expiresAt)) {
			exp := cookie.Expires
			expiresAt = &exp
		}
	}
	sort.Strings(headerParts)
	return &AuthSession{
		ID: uuid.NewString(), LoginURL: c.config.Auth.LoginURL, FinalURL: state.URL,
		LoginMethod: method, SuccessReason: reason, CookieHeader: strings.Join(headerParts, "; "),
		CSRFField: state.CSRFField, CSRFToken: state.CSRFToken, Cookies: cookies,
		Storage: []BrowserOriginStorage{storage}, AuthenticatedAt: time.Now().UTC(), ExpiresAt: expiresAt,
	}, nil
}

func (c *DynamicCrawler) browserCookies(ctx context.Context) ([]CookieInfo, error) {
	var raw []*network.Cookie
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		raw, err = network.GetCookies().Do(ctx)
		return err
	})); err != nil {
		return nil, fmt.Errorf("read browser cookies: %w", err)
	}
	out := make([]CookieInfo, 0, len(raw))
	for _, cookie := range raw {
		info := CookieInfo{Name: cookie.Name, Value: cookie.Value, Domain: cookie.Domain, Path: cookie.Path,
			HttpOnly: cookie.HTTPOnly, Secure: cookie.Secure, SameSite: string(cookie.SameSite), Session: cookie.Session}
		if cookie.Expires > 0 {
			info.Expires = time.Unix(int64(cookie.Expires), 0).UTC()
		}
		out = append(out, info)
	}
	return out, nil
}

func exportAuthSession(path string, session *AuthSession) error {
	export := authExport{
		Session: session, CookieHeader: session.CookieHeader,
		Headers: map[string]string{"Cookie": session.CookieHeader},
		ToolHints: map[string]string{
			"sqlmap": "--cookie=" + session.CookieHeader, "dalfox": "--cookie " + session.CookieHeader,
			"nuclei": "-H Cookie: " + session.CookieHeader, "ffuf": "-H Cookie: " + session.CookieHeader,
			"httpx": "-H Cookie: " + session.CookieHeader,
		},
	}
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func hasCookie(cookies []CookieInfo, name string) bool {
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Value != "" {
			return true
		}
	}
	return false
}

func hasNewCookie(before, after []CookieInfo) bool {
	known := make(map[string]string, len(before))
	for _, cookie := range before {
		known[cookie.Name+"\x00"+cookie.Domain+"\x00"+cookie.Path] = cookie.Value
	}
	for _, cookie := range after {
		key := cookie.Name + "\x00" + cookie.Domain + "\x00" + cookie.Path
		if value, ok := known[key]; !ok || value != cookie.Value {
			return true
		}
	}
	return false
}

func originOf(raw string) string {
	parts := strings.SplitN(raw, "/", 4)
	if len(parts) >= 3 {
		return strings.Join(parts[:3], "/")
	}
	return raw
}

func bodyTypeFromContentType(contentType string) string {
	info := DetectContentType(contentType)
	switch {
	case info.IsJSON:
		return "json"
	case info.IsMultipart:
		return "multipart"
	case info.IsURLEncoded:
		return "form-urlencoded"
	case info.IsGraphQL:
		return "graphql"
	case info.IsXML:
		return "xml"
	case info.IsText:
		return "text"
	default:
		return "binary"
	}
}
