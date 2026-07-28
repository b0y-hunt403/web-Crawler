package crawler

import (
	"encoding/json"
	"mime"
	"strings"
)

// DetectContentType classifies the media type without losing its parameters.
func DetectContentType(raw string) ContentTypeInfo {
	info := ContentTypeInfo{FullType: raw, Parameters: map[string]string{}}
	mediaType, params, err := mime.ParseMediaType(raw)
	if err != nil {
		mediaType = NormalizeContentType(raw)
	}
	mediaType = strings.ToLower(mediaType)
	info.Parameters = params
	info.Boundary = params["boundary"]
	info.Charset = params["charset"]
	parts := strings.SplitN(mediaType, "/", 2)
	if len(parts) > 0 {
		info.PrimaryType = parts[0]
	}
	if len(parts) == 2 {
		info.SubType = parts[1]
	}
	info.IsJSON = strings.Contains(mediaType, "json")
	info.IsFormData = mediaType == "multipart/form-data" || mediaType == "application/x-www-form-urlencoded"
	info.IsURLEncoded = mediaType == "application/x-www-form-urlencoded"
	info.IsMultipart = strings.HasPrefix(mediaType, "multipart/")
	info.IsXML = strings.Contains(mediaType, "xml")
	info.IsGraphQL = strings.Contains(mediaType, "graphql")
	info.IsText = strings.HasPrefix(mediaType, "text/") || info.IsJSON || info.IsXML || info.IsGraphQL
	info.IsBinary = mediaType != "" && !info.IsText && !info.IsFormData
	return info
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

func ParseJSONFormat(body, contentType string) *JSONFormat {
	if body == "" || !DetectContentType(contentType).IsJSON {
		return nil
	}
	var payload map[string]interface{}
	if json.Unmarshal([]byte(body), &payload) != nil {
		return &JSONFormat{Raw: body, IsJSON: false}
	}
	return &JSONFormat{Payload: payload, Raw: body, IsJSON: true}
}

func HeaderValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}
