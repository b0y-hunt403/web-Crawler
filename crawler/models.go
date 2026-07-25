// crawler/models.go
package crawler

import (
	"time"
)

// FieldType represents the type of form field
type FieldType string

const (
	FieldHidden   FieldType = "hidden"
	FieldPassword FieldType = "password"
	FieldText     FieldType = "text"
	FieldEmail    FieldType = "email"
	FieldNumber   FieldType = "number"
	FieldTel      FieldType = "tel"
	FieldURL      FieldType = "url"
	FieldDate     FieldType = "date"
	FieldSearch   FieldType = "search"
	FieldSelect   FieldType = "select"
	FieldTextarea FieldType = "textarea"
	FieldCheckbox FieldType = "checkbox"
	FieldRadio    FieldType = "radio"
	FieldFile     FieldType = "file"
)

// ValidationRules stores field validation metadata
type ValidationRules struct {
	Required    bool   `json:"required,omitempty"`
	MinLength   int    `json:"min_length,omitempty"`
	MaxLength   int    `json:"max_length,omitempty"`
	Min         int    `json:"min,omitempty"`
	Max         int    `json:"max,omitempty"`
	Pattern     string `json:"pattern,omitempty"`
	Step        int    `json:"step,omitempty"`
	Accept      string `json:"accept,omitempty"` // For file inputs
	Multiple    bool   `json:"multiple,omitempty"`
	AutoFocus   bool   `json:"autofocus,omitempty"`
	ReadOnly    bool   `json:"readonly,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
}

// FormFramework represents detected form framework
type FormFramework string

const (
	FrameworkReactHookForm FormFramework = "react-hook-form"
	FrameworkFormik        FormFramework = "formik"
	FrameworkZod           FormFramework = "zod"
	FrameworkYup           FormFramework = "yup"
	FrameworkReduxForm     FormFramework = "redux-form"
	FrameworkTanStack      FormFramework = "tanstack-form"
	FrameworkNative        FormFramework = "native"
	FrameworkUnknown       FormFramework = "unknown"
)

// FormField represents a single form field with full metadata
type FormField struct {
	Name         string          `json:"name"`
	Type         FieldType       `json:"type"`
	Value        string          `json:"value"`
	Placeholder  string          `json:"placeholder"`
	Required     bool            `json:"required"`
	ID           string          `json:"id"`
	ClassName    string          `json:"class_name"`
	Autocomplete string          `json:"autocomplete"`
	Readonly     bool            `json:"readonly"`
	Disabled     bool            `json:"disabled"`
	Checked      bool            `json:"checked"`
	IsCSRFToken  bool            `json:"is_csrf_token,omitempty"`
	Options      []string        `json:"options,omitempty"`
	Pattern      string          `json:"pattern,omitempty"`
	MinLength    *int            `json:"min_length,omitempty"`
	MaxLength    *int            `json:"max_length,omitempty"`
	Min          *int            `json:"min,omitempty"`
	Max          *int            `json:"max,omitempty"`
	Step         *int            `json:"step,omitempty"`
	Accept       string          `json:"accept,omitempty"`
	Multiple     bool            `json:"multiple,omitempty"`
	AutoFocus    bool            `json:"autofocus,omitempty"`
	ReadOnly     bool            `json:"read_only,omitempty"`
	Validation   *ValidationRules `json:"validation,omitempty"`
}

// FormType represents the type of form
type FormType string

const (
	FormLogin          FormType = "login"
	FormRegister       FormType = "register"
	FormSearch         FormType = "search"
	FormContact        FormType = "contact"
	FormNewsletter     FormType = "newsletter"
	FormForgotPassword FormType = "forgot_password"
	FormCheckout       FormType = "checkout"
	FormUpload         FormType = "upload"
	FormUnknown        FormType = "unknown"
)

// Form represents an HTML form with full metadata
type Form struct {
	Action         string          `json:"action"`
	Method         string          `json:"method"`
	Fields         []FormField     `json:"fields"`
	SourceURL      string          `json:"source_url"`
	FormType       FormType        `json:"form_type"`
	ID             string          `json:"id,omitempty"`
	Name           string          `json:"name,omitempty"`
	ClassName      string          `json:"class_name,omitempty"`
	Enctype        string          `json:"enctype,omitempty"`
	CSRFTokenField string          `json:"csrf_token_field,omitempty"`
	RequiredFields []string        `json:"required_fields,omitempty"`
	DataFormat     string          `json:"data_format"`
	Framework      FormFramework   `json:"framework,omitempty"`
	ValidationLib  string          `json:"validation_lib,omitempty"`
	APIMapping     *APIMapping     `json:"api_mapping,omitempty"`
}

// APIMapping maps a page URL to its API endpoint
type APIMapping struct {
	PageURL     string `json:"page_url"`
	APIMethod   string `json:"api_method"`
	APIEndpoint string `json:"api_endpoint"`
	BodyFormat  string `json:"body_format"`
}

// ContentTypeInfo stores detailed content type information
type ContentTypeInfo struct {
	PrimaryType   string            `json:"primary_type"`
	SubType       string            `json:"sub_type"`
	Boundary      string            `json:"boundary,omitempty"`
	Charset       string            `json:"charset,omitempty"`
	FullType      string            `json:"full_type"`
	IsJSON        bool              `json:"is_json"`
	IsFormData    bool              `json:"is_form_data"`
	IsURLEncoded  bool              `json:"is_url_encoded"`
	IsMultipart   bool              `json:"is_multipart"`
	IsXML         bool              `json:"is_xml"`
	IsGraphQL     bool              `json:"is_graphql"`
	IsText        bool              `json:"is_text"`
	IsBinary      bool              `json:"is_binary"`
	Parameters    map[string]string `json:"parameters,omitempty"`
}

// FetchDetails captures actual fetch/XHR call details
type FetchDetails struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	BodyType    string            `json:"body_type"`
	Credentials string            `json:"credentials,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	Cache       string            `json:"cache,omitempty"`
	Redirect    string            `json:"redirect,omitempty"`
	Referrer    string            `json:"referrer,omitempty"`
	RawSnippet  string            `json:"raw_snippet,omitempty"`
	Initiator   string            `json:"initiator,omitempty"`
}

// SPARoute represents a single-page application route
type SPARoute struct {
	Path       string `json:"path"`
	SourceFile string `json:"source_file"`
	Depth      int    `json:"depth"`
}

// ResponseMetadata stores response information
type ResponseMetadata struct {
	StatusCode    int               `json:"status_code"`
	ContentType   string            `json:"content_type"`
	ContentLength int64             `json:"content_length"`
	Server        string            `json:"server"`
	CacheControl  string            `json:"cache_control"`
	Headers       map[string]string `json:"headers"`
	SetCookies    []string          `json:"set_cookies"`
}

// JSONFormat stores JSON payload information
type JSONFormat struct {
	Payload map[string]interface{} `json:"payload"`
	Raw     string                 `json:"raw"`
	IsJSON  bool                   `json:"is_json"`
}

// DiscoveredRequest represents a discovered request with full metadata
type DiscoveredRequest struct {
	ID                string                 `json:"id"`
	URL               string                 `json:"url"`
	Method            string                 `json:"method"`
	Headers           map[string]string      `json:"headers,omitempty"`
	Body              string                 `json:"body,omitempty"`
	BodyType          string                 `json:"body_type,omitempty"`
	SourceType        string                 `json:"source_type"`
	Depth             int                    `json:"depth"`
	NormalizedURL     string                 `json:"normalized_url"`
	Parameters        map[string]interface{} `json:"parameters,omitempty"`
	FormFields        []FormField            `json:"form_fields,omitempty"`
	Cookies           map[string]string      `json:"cookies,omitempty"`
	Response          *ResponseMetadata      `json:"response,omitempty"`
	Form              *Form                  `json:"form,omitempty"`
	SPARoute          *SPARoute              `json:"spa_route,omitempty"`
	JSONFormat        *JSONFormat            `json:"json_format,omitempty"`
	ShadowDOMElements []map[string]interface{} `json:"shadow_dom_elements,omitempty"`
	FetchDetails      *FetchDetails          `json:"fetch_details,omitempty"`
	ContentTypeInfo   *ContentTypeInfo       `json:"content_type_info,omitempty"`
	APIMapping        *APIMapping            `json:"api_mapping,omitempty"`
	CreatedAt         time.Time              `json:"created_at"`
}

// FormSubmission represents a form submission candidate
type FormSubmission struct {
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	BodyType string            `json:"body_type"` // "json", "form-urlencoded", "multipart", "query"
}

// RequestHeaders captures all important HTTP headers
type RequestHeaders struct {
    // Security Headers
    Authorization string `json:"authorization,omitempty"`
    Cookie        string `json:"cookie,omitempty"`
    CSRF          string `json:"x_csrf_token,omitempty"`
    XSRFToken     string `json:"x_xsrf_token,omitempty"`
    XRequestedWith string `json:"x_requested_with,omitempty"`
    
    // Context Headers
    Origin          string `json:"origin,omitempty"`
    Referer         string `json:"referer,omitempty"`
    Host            string `json:"host,omitempty"`
    UserAgent       string `json:"user_agent,omitempty"`
    Accept          string `json:"accept,omitempty"`
    AcceptLanguage  string `json:"accept_language,omitempty"`
    AcceptEncoding  string `json:"accept_encoding,omitempty"`
    
    // Content Headers
    ContentType     string `json:"content_type,omitempty"`
    ContentLength   string `json:"content_length,omitempty"`
    ContentEncoding string `json:"content_encoding,omitempty"`
    
    // Cache Headers
    CacheControl    string `json:"cache_control,omitempty"`
    Pragma          string `json:"pragma,omitempty"`
    
    // Connection
    Connection      string `json:"connection,omitempty"`
    Upgrade         string `json:"upgrade,omitempty"`
    
    // Custom headers
    Custom          map[string]string `json:"custom,omitempty"`
    
    // Raw headers
    Raw             map[string]string `json:"raw,omitempty"`
}

// MultipartFile represents a file in multipart upload
type MultipartFile struct {
    FieldName   string `json:"field_name"`
    FileName    string `json:"file_name"`
    ContentType string `json:"content_type"`
    Size        int64  `json:"size"`
    Content     []byte `json:"content,omitempty"` // Base64 encoded or omit
}

// MultipartForm represents a multipart form data
type MultipartForm struct {
    Boundary string                   `json:"boundary"`
    Fields   map[string]string        `json:"fields"`
    Files    []MultipartFile          `json:"files"`
    Raw      string                   `json:"raw"`
}

// RequestType represents the type of request
type RequestType string

const (
    RequestTypeFetch      RequestType = "fetch"
    RequestTypeAxios      RequestType = "axios"
    RequestTypeXHR        RequestType = "xmlhttprequest"
    RequestTypeGraphQL    RequestType = "graphql"
    RequestTypeWebSocket  RequestType = "websocket"
    RequestTypeSSE        RequestType = "sse"
    RequestTypeBeacon     RequestType = "beacon"
    RequestTypeForm       RequestType = "form_submit"
    RequestTypeNavigation RequestType = "navigation"
)

// RequestSource captures the source of a request
type RequestSource struct {
    Type        RequestType `json:"type"`
    JavaScript  string      `json:"javascript,omitempty"`   // The actual JS code
    LineNumber  int         `json:"line_number,omitempty"`
    FileURL     string      `json:"file_url,omitempty"`
    StackTrace  string      `json:"stack_trace,omitempty"`
}

// ResponseSchema captures the structure of an API response
type ResponseSchema struct {
    StatusCode    int                    `json:"status_code"`
    Headers       RequestHeaders         `json:"headers"`
    Body          string                 `json:"body"`
    BodyType      string                 `json:"body_type"`
    JSONSchema    map[string]interface{} `json:"json_schema,omitempty"`
    Fields        []ResponseField        `json:"fields,omitempty"`
}

// ResponseField represents a field in the response
type ResponseField struct {
    Name     string                 `json:"name"`
    Type     string                 `json:"type"`      // string, number, boolean, array, object
    Required bool                   `json:"required"`
    Pattern  string                 `json:"pattern,omitempty"`
    Example  interface{}            `json:"example,omitempty"`
    Children []ResponseField        `json:"children,omitempty"`
}
// CookieInfo represents a cookie with all attributes
type CookieInfo struct {
    Name      string    `json:"name"`
    Value     string    `json:"value"`
    Domain    string    `json:"domain"`
    Path      string    `json:"path"`
    Expires   time.Time `json:"expires,omitempty"`
    MaxAge    int       `json:"max_age,omitempty"`
    HttpOnly  bool      `json:"http_only"`
    Secure    bool      `json:"secure"`
    SameSite  string    `json:"same_site"` // Strict, Lax, None
    Session   bool      `json:"session"`
}

// AuthFlow represents an authentication flow
type AuthFlow struct {
    Steps      []AuthStep      `json:"steps"`
    StartURL   string          `json:"start_url"`
    FinalURL   string          `json:"final_url"`
    Success    bool            `json:"success"`
    Token      string          `json:"token,omitempty"`
    SessionID  string          `json:"session_id,omitempty"`
}

// AuthStep represents a single step in authentication flow
type AuthStep struct {
    Order       int               `json:"order"`
    URL         string            `json:"url"`
    Method      string            `json:"method"`
    Request     RequestHeaders    `json:"request"`
    Response    AuthResponse      `json:"response"`
    RedirectURL string            `json:"redirect_url,omitempty"`
    IsLogin     bool              `json:"is_login"`
    IsLogout    bool              `json:"is_logout"`
    IsRedirect  bool              `json:"is_redirect"`
}

// AuthResponse represents response at auth step
type AuthResponse struct {
    StatusCode int               `json:"status_code"`
    Headers    RequestHeaders    `json:"headers"`
    Body       string            `json:"body"`
    Cookies    []CookieInfo      `json:"cookies"`
    JSON       map[string]interface{} `json:"json,omitempty"`
}

// MultipartForm represents a multipart form data upload
type MultipartForm struct {
    Boundary string                   `json:"boundary"`
    Fields   map[string]string        `json:"fields"`
    Files    []MultipartFile          `json:"files"`
    Raw      string                   `json:"raw"`
    Enctype  string                   `json:"enctype"`
}

// MultipartFile represents a file in multipart upload
type MultipartFile struct {
    FieldName   string `json:"field_name"`
    FileName    string `json:"file_name"`
    ContentType string `json:"content_type"`
    Size        int64  `json:"size"`
    Content     []byte `json:"content,omitempty"`
    Base64      string `json:"base64,omitempty"`
}

// RequestHeaders captures all important HTTP headers
type RequestHeaders struct {
    // Security Headers
    Authorization  string `json:"authorization,omitempty"`
    Cookie         string `json:"cookie,omitempty"`
    CSRF           string `json:"x_csrf_token,omitempty"`
    XSRFToken      string `json:"x_xsrf_token,omitempty"`
    XRequestedWith string `json:"x_requested_with,omitempty"`
    
    // Context Headers
    Origin          string `json:"origin,omitempty"`
    Referer         string `json:"referer,omitempty"`
    Host            string `json:"host,omitempty"`
    UserAgent       string `json:"user_agent,omitempty"`
    Accept          string `json:"accept,omitempty"`
    AcceptLanguage  string `json:"accept_language,omitempty"`
    AcceptEncoding  string `json:"accept_encoding,omitempty"`
    
    // Content Headers
    ContentType     string `json:"content_type,omitempty"`
    ContentLength   string `json:"content_length,omitempty"`
    ContentEncoding string `json:"content_encoding,omitempty"`
    
    // Cache Headers
    CacheControl    string `json:"cache_control,omitempty"`
    Pragma          string `json:"pragma,omitempty"`
    
    // Connection
    Connection      string `json:"connection,omitempty"`
    Upgrade         string `json:"upgrade,omitempty"`
    
    // Custom headers
    Custom          map[string]string `json:"custom,omitempty"`
    
    // Raw headers
    Raw             map[string]string `json:"raw,omitempty"`
}

// CookieInfo represents a cookie with all attributes
type CookieInfo struct {
    Name      string    `json:"name"`
    Value     string    `json:"value"`
    Domain    string    `json:"domain"`
    Path      string    `json:"path"`
    Expires   time.Time `json:"expires,omitempty"`
    MaxAge    int       `json:"max_age,omitempty"`
    HttpOnly  bool      `json:"http_only"`
    Secure    bool      `json:"secure"`
    SameSite  string    `json:"same_site"`
    Session   bool      `json:"session"`
}
// ResponseFingerprint captures response metadata for comparison
type ResponseFingerprint struct {
    StatusCode    int    `json:"status_code"`
    ContentType   string `json:"content_type"`
    ContentLength int64  `json:"content_length"`
    Hash          string `json:"hash"`           // SHA256 of body
    MimeType      string `json:"mime_type"`
    Title         string `json:"title,omitempty"` // HTML title if any
    Server        string `json:"server,omitempty"`
    Etag          string `json:"etag,omitempty"`
    LastModified  string `json:"last_modified,omitempty"`
}