package crawler

import "testing"

func TestNormalizeURLAndFingerprint(t *testing.T) {
	first := "HTTPS://Example.COM:443/api/?b=2&a=1#fragment"
	second := "https://example.com/api?a=1&b=2"
	if got, want := NormalizeURL(first), NormalizeURL(second); got != want {
		t.Fatalf("normalized URLs differ: %q != %q", got, want)
	}
	a := CalculateFingerprint("post", first, `{"b":2,"a":1}`, "Application/JSON; charset=utf-8")
	b := CalculateFingerprint("POST", second, `{ "a": 1, "b": 2 }`, "application/json")
	if a != b {
		t.Fatal("semantically equivalent JSON requests must deduplicate")
	}
}

func TestDetectContentTypes(t *testing.T) {
	tests := []struct {
		contentType string
		check       func(ContentTypeInfo) bool
	}{
		{"application/json", func(v ContentTypeInfo) bool { return v.IsJSON }},
		{"application/x-www-form-urlencoded", func(v ContentTypeInfo) bool { return v.IsURLEncoded }},
		{"multipart/form-data; boundary=raptor", func(v ContentTypeInfo) bool { return v.IsMultipart && v.Boundary == "raptor" }},
		{"application/graphql", func(v ContentTypeInfo) bool { return v.IsGraphQL }},
		{"application/xml", func(v ContentTypeInfo) bool { return v.IsXML }},
		{"text/plain; charset=utf-8", func(v ContentTypeInfo) bool { return v.IsText && v.Charset == "utf-8" }},
	}
	for _, test := range tests {
		if !test.check(DetectContentType(test.contentType)) {
			t.Errorf("classification failed for %s", test.contentType)
		}
	}
}
