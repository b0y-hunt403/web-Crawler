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

// FormField represents a single form field
type FormField struct {
	Name         string    `json:"name"`
	Type         FieldType `json:"type"`
	Value        string    `json:"value"`
	Placeholder  string    `json:"placeholder"`
	Required     bool      `json:"required"`
	ID           string    `json:"id"`
	ClassName    string    `json:"class_name"`
	Autocomplete string    `json:"autocomplete"`
	Readonly     bool      `json:"readonly"`
	Disabled     bool      `json:"disabled"`
	Checked      bool      `json:"checked"`
	IsCSRFToken  bool      `json:"is_csrf_token,omitempty"`
	Options      []string  `json:"options,omitempty"`
	Pattern      string    `json:"pattern,omitempty"`
	MinLength    *int      `json:"min_length,omitempty"`
	MaxLength    *int      `json:"max_length,omitempty"`
	ReadOnly     bool      `json:"read_only,omitempty"`
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

// Form represents an HTML form
type Form struct {
	Action         string      `json:"action"`
	Method         string      `json:"method"`
	Fields         []FormField `json:"fields"`
	SourceURL      string      `json:"source_url"`
	FormType       FormType    `json:"form_type"`
	ID             string      `json:"id,omitempty"`
	Name           string      `json:"name,omitempty"`
	ClassName      string      `json:"class_name,omitempty"`
	Enctype        string      `json:"enctype,omitempty"`
	CSRFTokenField string      `json:"csrf_token_field,omitempty"`
	RequiredFields []string    `json:"required_fields,omitempty"`
	DataFormat     string      `json:"data_format"`
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

// DiscoveredRequest represents a discovered request
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