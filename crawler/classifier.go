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

// formFrameworkPatterns detect form frameworks
var formFrameworkPatterns = map[string][]string{
	"react-hook-form": {
		"useForm", "Controller", "react-hook-form",
	},
	"formik": {
		"useFormik", "withFormik", "Formik",
	},
	"zod": {
		"z.object", "z.string", "z.number", "zod",
	},
	"yup": {
		"yup.object", "yup.string", "yup.number",
	},
	"redux-form": {
		"reduxForm", "Field", "redux-form",
	},
	"tanstack-form": {
		"useForm", "tanstack/react-form",
	},
}

// DetectFormFramework detects which form framework is being used
func DetectFormFramework(html, jsContent string) FormFramework {
	content := html + " " + jsContent
	lowerContent := strings.ToLower(content)

	for framework, patterns := range formFrameworkPatterns {
		for _, pattern := range patterns {
			if strings.Contains(lowerContent, strings.ToLower(pattern)) {
				return FormFramework(framework)
			}
		}
	}
	return FrameworkUnknown
}

// DetectValidationLibrary detects validation library from code
func DetectValidationLibrary(jsContent string) string {
	lower := strings.ToLower(jsContent)
	if strings.Contains(lower, "zod") || strings.Contains(lower, "z.object") {
		return "zod"
	}
	if strings.Contains(lower, "yup") || strings.Contains(lower, "yup.object") {
		return "yup"
	}
	if strings.Contains(lower, "joi") || strings.Contains(lower, "joi.object") {
		return "joi"
	}
	if strings.Contains(lower, "validator") || strings.Contains(lower, "validate") {
		return "custom"
	}
	return ""
}

// ExtractValidationRules extracts validation rules from field attributes
func ExtractValidationRules(field map[string]interface{}) *ValidationRules {
	rules := &ValidationRules{}

	if req, ok := field["required"].(bool); ok && req {
		rules.Required = true
	}

	if minLen, ok := field["min_length"].(int); ok {
		rules.MinLength = minLen
	}
	if maxLen, ok := field["max_length"].(int); ok {
		rules.MaxLength = maxLen
	}
	if min, ok := field["min"].(int); ok {
		rules.Min = min
	}
	if max, ok := field["max"].(int); ok {
		rules.Max = max
	}
	if pattern, ok := field["pattern"].(string); ok && pattern != "" {
		rules.Pattern = pattern
	}
	if step, ok := field["step"].(int); ok {
		rules.Step = step
	}
	if accept, ok := field["accept"].(string); ok && accept != "" {
		rules.Accept = accept
	}
	if multiple, ok := field["multiple"].(bool); ok {
		rules.Multiple = multiple
	}
	if autofocus, ok := field["autofocus"].(bool); ok {
		rules.AutoFocus = autofocus
	}
	if readonly, ok := field["readonly"].(bool); ok {
		rules.ReadOnly = readonly
	}
	if disabled, ok := field["disabled"].(bool); ok {
		rules.Disabled = disabled
	}
	if placeholder, ok := field["placeholder"].(string); ok && placeholder != "" {
		rules.Placeholder = placeholder
	}

	return rules
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

// BuildFormFields converts raw field maps into []FormField with validation
func BuildFormFields(raw []map[string]interface{}) []FormField {
	fields := make([]FormField, 0, len(raw))
	for _, f := range raw {
		ff := mapToFormFieldStatic(f)
		if ff.Type == FieldHidden && isCSRFFieldName(ff.Name) {
			ff.IsCSRFToken = true
		} else if isCSRFFieldName(ff.Name) || isCSRFFieldName(ff.ID) {
			ff.IsCSRFToken = true
		}
		// Add validation rules
		ff.Validation = ExtractValidationRules(f)
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

// Add to classifier.go
func DetectMultipartUpload(fields []map[string]interface{}) bool {
    for _, f := range fields {
        if ftype, ok := f["type"].(string); ok {
            if ftype == "file" {
                return true
            }
        }
        if accept, ok := f["accept"].(string); ok {
            if strings.Contains(accept, "image/") || 
               strings.Contains(accept, "application/") ||
               strings.Contains(accept, "audio/") ||
               strings.Contains(accept, "video/") {
                return true
            }
        }
    }
    return false
}

// Generate test file for multipart upload
func GenerateTestFile(fieldName, accept string) MultipartFile {
    var fileName, contentType string
    var content []byte
    
    switch {
    case strings.Contains(accept, "image/"):
        fileName = "test_image.png"
        contentType = "image/png"
        content = []byte{0x89, 0x50, 0x4E, 0x47} // PNG header
    case strings.Contains(accept, "application/pdf"):
        fileName = "test.pdf"
        contentType = "application/pdf"
        content = []byte("%PDF-1.4") // PDF header
    case strings.Contains(accept, "audio/"):
        fileName = "test.mp3"
        contentType = "audio/mpeg"
        content = []byte("ID3") // MP3 header
    case strings.Contains(accept, "video/"):
        fileName = "test.mp4"
        contentType = "video/mp4"
        content = []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70} // MP4 header
    default:
        fileName = "test.txt"
        contentType = "text/plain"
        content = []byte("Test file content")
    }
    
    return MultipartFile{
        FieldName:   fieldName,
        FileName:    fileName,
        ContentType: contentType,
        Size:        int64(len(content)),
        Content:     content,
    }
}
// Add to classifier.go
func InferJSONSchema(body string) map[string]interface{} {
    var data map[string]interface{}
    if err := json.Unmarshal([]byte(body), &data); err != nil {
        return nil
    }
    
    schema := make(map[string]interface{})
    for k, v := range data {
        schema[k] = inferFieldType(v)
    }
    return schema
}

func inferFieldType(value interface{}) map[string]interface{} {
    field := make(map[string]interface{})
    
    switch v := value.(type) {
    case string:
        field["type"] = "string"
        field["example"] = v
        // Check if it looks like an email
        if strings.Contains(v, "@") {
            field["format"] = "email"
        }
        // Check if it looks like a URL
        if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
            field["format"] = "url"
        }
        // Check if it looks like a date
        if _, err := time.Parse(time.RFC3339, v); err == nil {
            field["format"] = "date-time"
        }
    case float64:
        field["type"] = "number"
        field["example"] = v
    case bool:
        field["type"] = "boolean"
        field["example"] = v
    case map[string]interface{}:
        field["type"] = "object"
        properties := make(map[string]interface{})
        for k, val := range v {
            properties[k] = inferFieldType(val)
        }
        field["properties"] = properties
    case []interface{}:
        field["type"] = "array"
        if len(v) > 0 {
            field["items"] = inferFieldType(v[0])
        }
    default:
        field["type"] = "unknown"
    }
    
    return field
}

// DetectMultipartForm detects if a form is multipart
func DetectMultipartForm(form *Form) bool {
    if form == nil {
        return false
    }
    
    // Check enctype
    if strings.Contains(strings.ToLower(form.Enctype), "multipart/form-data") {
        return true
    }
    
    // Check for file inputs
    for _, field := range form.Fields {
        if field.Type == FieldFile {
            return true
        }
        if strings.Contains(strings.ToLower(field.Accept), "image/") ||
           strings.Contains(strings.ToLower(field.Accept), "application/") ||
           strings.Contains(strings.ToLower(field.Accept), "audio/") ||
           strings.Contains(strings.ToLower(field.Accept), "video/") {
            return true
        }
    }
    
    return false
}

// GenerateMultipartForm creates a test multipart form
func GenerateMultipartForm(form *Form) *MultipartForm {
    mf := &MultipartForm{
        Fields: make(map[string]string),
        Files:  []MultipartFile{},
        Enctype: "multipart/form-data",
    }
    
    for _, field := range form.Fields {
        if field.Type == FieldFile {
            // Generate test file
            file := GenerateTestFile(field.Name, field.Accept)
            mf.Files = append(mf.Files, file)
        } else {
            mf.Fields[field.Name] = GetSmartValueForField(field)
        }
    }
    
    return mf
}

// GenerateTestFile creates a test file for upload
func GenerateTestFile(fieldName, accept string) MultipartFile {
    var fileName, contentType string
    var content []byte
    
    switch {
    case strings.Contains(accept, "image/png") || strings.Contains(accept, "image/*"):
        fileName = "test_image.png"
        contentType = "image/png"
        content = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A} // PNG header
    case strings.Contains(accept, "image/jpeg"):
        fileName = "test_image.jpg"
        contentType = "image/jpeg"
        content = []byte{0xFF, 0xD8, 0xFF, 0xE0} // JPEG header
    case strings.Contains(accept, "application/pdf"):
        fileName = "test.pdf"
        contentType = "application/pdf"
        content = []byte{0x25, 0x50, 0x44, 0x46} // PDF header
    case strings.Contains(accept, "application/zip"):
        fileName = "test.zip"
        contentType = "application/zip"
        content = []byte{0x50, 0x4B, 0x03, 0x04} // ZIP header
    case strings.Contains(accept, "application/json"):
        fileName = "test.json"
        contentType = "application/json"
        content = []byte(`{"test": "data"}`)
    case strings.Contains(accept, "text/plain") || accept == "":
        fileName = "test.txt"
        contentType = "text/plain"
        content = []byte("Test file content for upload")
    case strings.Contains(accept, "audio/"):
        fileName = "test.mp3"
        contentType = "audio/mpeg"
        content = []byte{0x49, 0x44, 0x33} // MP3 header
    case strings.Contains(accept, "video/"):
        fileName = "test.mp4"
        contentType = "video/mp4"
        content = []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70} // MP4 header
    default:
        fileName = "test_" + fieldName + ".bin"
        contentType = "application/octet-stream"
        content = []byte("Binary test data")
    }
    
    return MultipartFile{
        FieldName:   fieldName,
        FileName:    fileName,
        ContentType: contentType,
        Size:        int64(len(content)),
        Content:     content,
        Base64:      "", // Could add base64 encoding here
    }
}

// GetSmartValueForField returns smart value for a field
func GetSmartValueForField(field FormField) string {
    switch field.Type {
    case FieldEmail:
        return "test@example.com"
    case FieldPassword:
        return "Test1234!"
    case FieldTel:
        return "555-555-5555"
    case FieldURL:
        return "https://example.com"
    case FieldNumber:
        return "1"
    case FieldDate:
        return "2026-01-01"
    default:
        if field.Placeholder != "" {
            return field.Placeholder
        }
        return "test_" + field.Name
    }
}
// InferAPISchema infers API schema from request/response pairs
func InferAPISchema(requests []*DiscoveredRequest) map[string]APISchema {
    schemas := make(map[string]APISchema)
    
    for _, req := range requests {
        if req.Response == nil || req.Response.Body == "" {
            continue
        }
        
        // Try to parse as JSON
        var data map[string]interface{}
        if err := json.Unmarshal([]byte(req.Response.Body), &data); err != nil {
            continue
        }
        
        // Infer schema
        schema := APISchema{
            Endpoint:   req.URL,
            Method:     req.Method,
            Fields:     inferFields(data),
            Example:    data,
        }
        
        schemas[req.URL] = schema
    }
    
    return schemas
}

// APISchema represents an API schema
type APISchema struct {
    Endpoint   string                 `json:"endpoint"`
    Method     string                 `json:"method"`
    Fields     []APIField             `json:"fields"`
    Example    map[string]interface{} `json:"example"`
}

// APIField represents a field in API schema
type APIField struct {
    Name     string      `json:"name"`
    Type     string      `json:"type"` // string, number, boolean, array, object
    Required bool        `json:"required"`
    Format   string      `json:"format,omitempty"` // email, url, date-time, etc.
    Example  interface{} `json:"example,omitempty"`
    Children []APIField  `json:"children,omitempty"`
}

// inferFields infers field types from data
func inferFields(data map[string]interface{}) []APIField {
    var fields []APIField
    
    for key, value := range data {
        field := APIField{
            Name: key,
        }
        
        switch v := value.(type) {
        case string:
            field.Type = "string"
            field.Example = v
            // Detect format
            if strings.Contains(v, "@") && strings.Contains(v, ".") {
                field.Format = "email"
            } else if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
                field.Format = "url"
            } else if _, err := time.Parse(time.RFC3339, v); err == nil {
                field.Format = "date-time"
            }
        case float64:
            field.Type = "number"
            field.Example = v
        case bool:
            field.Type = "boolean"
            field.Example = v
        case map[string]interface{}:
            field.Type = "object"
            field.Children = inferFields(v)
        case []interface{}:
            field.Type = "array"
            if len(v) > 0 {
                // Try to infer array item type
                if m, ok := v[0].(map[string]interface{}); ok {
                    field.Children = inferFields(m)
                }
            }
        default:
            field.Type = "unknown"
        }
        
        fields = append(fields, field)
    }
    
    return fields
}

// ExtractRouteParameters extracts route parameters from URL patterns
func ExtractRouteParameters(urls []string) []RoutePattern {
    patterns := make(map[string]RoutePattern)
    
    // Find URLs with numbers (likely IDs)
    for _, url := range urls {
        // Check for numeric IDs
        if strings.Contains(url, "/") {
            parts := strings.Split(url, "/")
            for i, part := range parts {
                // If part is numeric, it's likely an ID
                if _, err := strconv.Atoi(part); err == nil && part != "" {
                    // Create pattern: /users/123 -> /users/{id}
                    key := strings.Join(parts[:i+1], "/")
                    pattern := strings.Replace(key, part, "{id}", 1)
                    patterns[pattern] = RoutePattern{
                        Pattern: pattern,
                        Method:  "GET",
                        ParamType: "numeric",
                        Example: part,
                    }
                }
                // Check for UUID format
                if isUUID(part) {
                    key := strings.Join(parts[:i+1], "/")
                    pattern := strings.Replace(key, part, "{uuid}", 1)
                    patterns[pattern] = RoutePattern{
                        Pattern: pattern,
                        Method:  "GET",
                        ParamType: "uuid",
                        Example: part,
                    }
                }
                // Check for slug format
                if isSlug(part) {
                    key := strings.Join(parts[:i+1], "/")
                    pattern := strings.Replace(key, part, "{slug}", 1)
                    patterns[pattern] = RoutePattern{
                        Pattern: pattern,
                        Method:  "GET",
                        ParamType: "slug",
                        Example: part,
                    }
                }
            }
        }
    }
    
    var result []RoutePattern
    for _, p := range patterns {
        result = append(result, p)
    }
    return result
}

// RoutePattern represents a route with parameters
type RoutePattern struct {
    Pattern   string `json:"pattern"`
    Method    string `json:"method"`
    ParamType string `json:"param_type"` // numeric, uuid, slug
    Example   string `json:"example"`
}

// isUUID checks if string is a UUID
func isUUID(s string) bool {
    uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
    return uuidRegex.MatchString(strings.ToLower(s))
}

// isSlug checks if string is a slug
func isSlug(s string) bool {
    slugRegex := regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
    return slugRegex.MatchString(strings.ToLower(s))
}