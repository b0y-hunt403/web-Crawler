// crawler/classifier.go
package crawler

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// SafeToRequeueAsGET lists form types idempotent enough to be re-crawled
var SafeToRequeueAsGET = map[FormType]bool{
	FormSearch: true,
}

// csrfFieldNames are common CSRF token field names
var csrfFieldNames = []string{
	"csrf_token", "csrfmiddlewaretoken", "csrf-token", "_csrf", "csrf",
	"authenticity_token", "xsrf-token", "xsrf_token", "_token",
	"__requestverificationtoken", "anti-forgery-token",
}

func isCSRFFieldName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	for _, candidate := range csrfFieldNames {
		if lower == candidate || strings.Contains(lower, candidate) {
			return true
		}
	}
	return false
}

// BuildFormFields converts raw field maps into []FormField
func BuildFormFields(raw []map[string]interface{}) []FormField {
	fields := make([]FormField, 0, len(raw))
	for _, f := range raw {
		ff := mapToFormFieldStatic(f)
		if ff.Type == FieldHidden && isCSRFFieldName(ff.Name) {
			ff.IsCSRFToken = true
		} else if isCSRFFieldName(ff.Name) || isCSRFFieldName(ff.ID) {
			ff.IsCSRFToken = true
		}
		fields = append(fields, ff)
	}
	return fields
}

// FormMeta returns CSRF field and required fields
func FormMeta(fields []FormField) (csrfField string, required []string) {
	for _, f := range fields {
		if f.IsCSRFToken && csrfField == "" {
			csrfField = f.Name
		}
		if f.Required {
			required = append(required, f.Name)
		}
	}
	return csrfField, required
}

// hasPasswordField reports if any field is a password input
func hasPasswordField(fields []FormField) bool {
	for _, f := range fields {
		if f.Type == FieldPassword {
			return true
		}
	}
	return false
}

func withQuery(rawURL string, data map[string]string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	for k, v := range data {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// BuildFormSubmissions returns every plausible form submission representation
func BuildFormSubmissions(actionURL string, hasExplicitMethod, hasExplicitEnctype bool, explicitMethod, explicitEnctype string, formData map[string]string, containsPassword bool) []FormSubmission {
	var out []FormSubmission

	declaredGET := hasExplicitMethod && strings.EqualFold(strings.TrimSpace(explicitMethod), "GET")
	wantsMultipart := hasExplicitEnctype && strings.Contains(strings.ToLower(explicitEnctype), "multipart")
	wantsJSON := hasExplicitEnctype && strings.Contains(strings.ToLower(explicitEnctype), "application/json")

	// If explicitly declared as GET and no password, return GET query
	if declaredGET && !containsPassword {
		out = append(out, FormSubmission{
			Method:   "GET",
			URL:      withQuery(actionURL, formData),
			BodyType: "query",
			Headers:  map[string]string{},
			Body:     "",
		})
		return out
	}

	// Always include POST urlencoded (traditional form)
	if !wantsMultipart && !wantsJSON {
		encodedBody := encodeFormData(formData)
		out = append(out, FormSubmission{
			Method: "POST",
			URL:    actionURL,
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			Body:     encodedBody,
			BodyType: "form-urlencoded",
		})
	}

	// If multipart, include that
	if wantsMultipart {
		out = append(out, FormSubmission{
			Method: "POST",
			URL:    actionURL,
			Headers: map[string]string{
				"Content-Type": explicitEnctype,
			},
			Body:     "[Multipart Form Data]",
			BodyType: "multipart",
		})
	}

	// ALWAYS include JSON variant with proper data
	jsonPayload := buildJSONPayload(formData, actionURL)
	jsonBody, _ := json.MarshalIndent(jsonPayload, "", "  ")
	
	out = append(out, FormSubmission{
		Method: "POST",
		URL:    actionURL,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
		Body:     string(jsonBody),
		BodyType: "json",
	})

	return out
}

// buildJSONPayload creates smart JSON payload from form data
func buildJSONPayload(formData map[string]string, actionURL string) map[string]interface{} {
	payload := make(map[string]interface{})
	
	// Convert values with proper types
	for k, v := range formData {
		if v == "" {
			continue
		}
		// Try to convert to appropriate types
		if num, err := strconv.Atoi(v); err == nil {
			payload[k] = num
		} else if num, err := strconv.ParseFloat(v, 64); err == nil {
			payload[k] = num
		} else if v == "true" || v == "false" {
			payload[k] = v == "true"
		} else {
			payload[k] = v
		}
	}

	actionLower := strings.ToLower(actionURL)

	// Special handling for login forms
	if strings.Contains(actionLower, "login") || strings.Contains(actionLower, "signin") {
		// Check if we have username/email and password
		loginPayload := make(map[string]interface{})
		
		// Try to extract credentials
		if username, ok := formData["username"]; ok && username != "" {
			loginPayload["username"] = username
		} else if email, ok := formData["email"]; ok && email != "" {
			loginPayload["email"] = email
		} else if user, ok := formData["user"]; ok && user != "" {
			loginPayload["username"] = user
		}
		
		if password, ok := formData["password"]; ok && password != "" {
			loginPayload["password"] = password
		}
		
		if len(loginPayload) > 0 {
			return loginPayload
		}
	}

	// Special handling for registration forms
	if strings.Contains(actionLower, "register") || strings.Contains(actionLower, "signup") {
		// Check if this is an organization registration
		orgPayload := make(map[string]interface{})
		adminPayload := make(map[string]interface{})
		userPayload := make(map[string]interface{})
		
		for k, v := range payload {
			lowerK := strings.ToLower(k)
			if strings.Contains(lowerK, "admin") || strings.Contains(lowerK, "administrator") {
				adminPayload[k] = v
			} else if strings.Contains(lowerK, "organization") || strings.Contains(lowerK, "company") {
				orgPayload[k] = v
			} else if strings.Contains(lowerK, "user") || strings.Contains(lowerK, "username") {
				userPayload[k] = v
			} else if strings.Contains(lowerK, "email") || strings.Contains(lowerK, "password") || strings.Contains(lowerK, "name") {
				userPayload[k] = v
			} else {
				// Default to user fields
				userPayload[k] = v
			}
		}
		
		// Build nested structure
		result := make(map[string]interface{})
		if len(orgPayload) > 0 {
			result["organization"] = orgPayload
		}
		if len(adminPayload) > 0 {
			result["admin"] = adminPayload
		}
		if len(userPayload) > 0 {
			result["user"] = userPayload
		}
		
		// If we have a single user payload, return it directly
		if len(result) == 1 && result["user"] != nil {
			return result
		}
		
		if len(result) > 0 {
			return result
		}
	}

	return payload
}

// ClassifyForm applies heuristics to guess a form's purpose
func ClassifyForm(fields []map[string]interface{}, pageURL string) FormType {
	lowerURL := strings.ToLower(pageURL)

	hasType := func(t string) bool {
		for _, f := range fields {
			if v, _ := f["type"].(string); strings.EqualFold(v, t) {
				return true
			}
		}
		return false
	}
	nameContains := func(sub string) bool {
		for _, f := range fields {
			name, _ := f["name"].(string)
			id, _ := f["id"].(string)
			ph, _ := f["placeholder"].(string)
			blob := strings.ToLower(name + " " + id + " " + ph)
			if strings.Contains(blob, sub) {
				return true
			}
		}
		return false
	}

	hasPassword := hasType("password")
	hasEmailOrUser := nameContains("email") || nameContains("user") || nameContains("login")

	switch {
	case strings.Contains(lowerURL, "forgot") || strings.Contains(lowerURL, "reset-password") || nameContains("forgot"):
		return FormForgotPassword
	case hasType("file") || strings.Contains(lowerURL, "upload"):
		return FormUpload
	case strings.Contains(lowerURL, "checkout") || strings.Contains(lowerURL, "cart") || nameContains("card") || nameContains("cvv"):
		return FormCheckout
	case hasPassword && (nameContains("confirm") || nameContains("first_name") || nameContains("full_name") ||
		strings.Contains(lowerURL, "register") || strings.Contains(lowerURL, "signup") || strings.Contains(lowerURL, "sign-up")):
		return FormRegister
	case hasPassword && hasEmailOrUser:
		return FormLogin
	case hasPassword:
		return FormLogin
	case hasType("search") || nameContains("search") || nameContains("query") || strings.Contains(lowerURL, "search"):
		return FormSearch
	case nameContains("newsletter") || nameContains("subscribe"):
		return FormNewsletter
	case nameContains("message") || nameContains("comment") || nameContains("subject"):
		return FormContact
	default:
		return FormUnknown
	}
}

// GetSmartValue returns a realistic default value for a field
func GetSmartValue(field map[string]interface{}, credentials map[string]string) string {
	name, _ := field["name"].(string)
	id, _ := field["id"].(string)
	fieldType, _ := field["type"].(string)
	blob := strings.ToLower(name + " " + id)

	if isCSRFFieldName(name) || isCSRFFieldName(id) {
		if v, _ := field["value"].(string); v != "" {
			return v
		}
	}

	if fieldType == "password" {
		if credentials != nil {
			if v := credentials["password"]; v != "" {
				return v
			}
		}
		return "Test1234!"
	}
	if strings.Contains(blob, "email") || fieldType == "email" {
		if credentials != nil {
			if v := credentials["username"]; v != "" && strings.Contains(v, "@") {
				return v
			}
		}
		return "test@example.com"
	}
	if strings.Contains(blob, "user") || strings.Contains(blob, "login") || strings.Contains(blob, "username") {
		if credentials != nil {
			if v := credentials["username"]; v != "" {
				return v
			}
		}
		return "testuser"
	}
	if strings.Contains(blob, "organization") || strings.Contains(blob, "company") {
		return "Test Organization"
	}
	if strings.Contains(blob, "admin") || strings.Contains(blob, "administrator") {
		return "admin@example.com"
	}
	if strings.Contains(blob, "name") && !strings.Contains(blob, "username") {
		return "Test User"
	}
	if strings.Contains(blob, "phone") || strings.Contains(blob, "tel") {
		return "555-555-5555"
	}
	if strings.Contains(blob, "address") {
		return "123 Test Street"
	}
	if strings.Contains(blob, "description") {
		return "Test description"
	}

	switch fieldType {
	case "tel":
		return "5555555555"
	case "url":
		return "https://example.com"
	case "number", "range":
		return "1"
	case "date":
		return "2026-01-01"
	case "datetime-local":
		return "2026-01-01T00:00"
	case "month":
		return "2026-01"
	case "week":
		return "2026-W01"
	case "color":
		return "#000000"
	case "checkbox":
		return "on"
	default:
		if v, _ := field["value"].(string); v != "" {
			return v
		}
		// Generate a meaningful default based on field name
		if strings.Contains(blob, "subject") {
			return "Test Subject"
		}
		if strings.Contains(blob, "message") || strings.Contains(blob, "comment") {
			return "Test message content"
		}
		return "test"
	}
}