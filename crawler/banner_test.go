package crawler

import (
	"bytes"
	"strings"
	"testing"
)

func TestFullBannerHasStableWidthWithoutColor(t *testing.T) {
	var output bytes.Buffer
	DefaultBanner().renderFull(&output, false)

	lines := strings.Split(strings.TrimSuffix(output.String(), "\n\n"), "\n")
	if len(lines) != 15 {
		t.Fatalf("banner line count = %d, want 15", len(lines))
	}
	for index, line := range lines {
		if width := visibleWidth(line); width != 76 {
			t.Errorf("line %d width = %d, want 76: %q", index+1, width, line)
		}
	}
}

func TestPaintRespectsDisabledColor(t *testing.T) {
	const text = "Raptor"
	if got := paint(false, colorCyan, text); got != text {
		t.Fatalf("paint(false) = %q, want %q", got, text)
	}
	if got := paint(true, colorCyan, text); !strings.Contains(got, "\x1b[") {
		t.Fatalf("paint(true) did not include ANSI styling: %q", got)
	}
}
