package crawler

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorPurple  = "\033[35m"
	colorCyan    = "\033[36m"
	colorHiCyan  = "\033[96m"
	colorHiGreen = "\033[92m"
)

// Banner describes the identity printed when the Raptor CLI starts.
type Banner struct {
	Name         string
	Version      string
	Author       string
	Description  string
	Capabilities []string
}

// DefaultBanner returns Raptor's default terminal identity.
func DefaultBanner() Banner {
	return Banner{
		Name:        "Raptor",
		Version:     "2.0.0",
		Author:      "B0y",
		Description: "Web reconnaissance and request intelligence",
		Capabilities: []string{
			"Katana",
			"Chromium",
			"Auth sessions",
			"SQLite",
		},
	}
}

var raptorASCII = buildRaptorWordmark()

// buildRaptorWordmark keeps every glyph independent and inserts an explicit
// two-column gap between letters. This prevents RAPTOR from becoming a single
// compact block in terminals with dense fonts.
func buildRaptorWordmark() []string {
	r := []string{
		`██████╗ `,
		`██╔══██╗`,
		`██████╔╝`,
		`██╔══██╗`,
		`██║  ██║`,
		`╚═╝  ╚═╝`,
	}
	a := []string{
		` █████╗ `,
		`██╔══██╗`,
		`███████║`,
		`██╔══██║`,
		`██║  ██║`,
		`╚═╝  ╚═╝`,
	}
	p := []string{
		`██████╗ `,
		`██╔══██╗`,
		`██████╔╝`,
		`██╔═══╝ `,
		`██║     `,
		`╚═╝     `,
	}
	t := []string{
		`████████`,
		`╚══██╔══`,
		`   ██║  `,
		`   ██║  `,
		`   ██║  `,
		`   ╚═╝  `,
	}
	o := []string{
		` ██████╗ `,
		`██╔═══██╗`,
		`██║   ██║`,
		`██║   ██║`,
		`╚██████╔╝`,
		` ╚═════╝ `,
	}

	lines := make([]string, len(r))
	for i := range lines {
		lines[i] = strings.Join([]string{r[i], a[i], p[i], t[i], o[i], r[i]}, "  ")
	}
	return lines
}

// PrintBanner renders the full banner, automatically falling back to a compact
// layout when stdout is narrow or non-interactive.
func (b Banner) PrintBanner() {
	width := terminalWidth()
	switch {
	case width > 0 && width < 48:
		b.PrintMiniBanner()
	case width > 0 && width < 78:
		b.PrintSimpleBanner()
	default:
		b.renderFull(os.Stdout, colorsEnabled(os.Stdout))
	}
}

func (b Banner) renderFull(w io.Writer, color bool) {
	const width = 76
	palette := []string{colorHiCyan, colorCyan, colorBlue, colorPurple, colorCyan, colorHiGreen}

	fmt.Fprintln(w, paint(color, colorCyan+colorDim, "╭"+strings.Repeat("─", width-2)+"╮"))
	fmt.Fprintln(w, paint(color, colorCyan+colorDim, "│")+strings.Repeat(" ", width-2)+paint(color, colorCyan+colorDim, "│"))
	for i, line := range raptorASCII {
		content := "  " + paint(color, palette[i], line)
		padding := width - 2 - 2 - visibleWidth(line)
		if padding < 0 {
			padding = 0
		}
		fmt.Fprintln(w, paint(color, colorCyan+colorDim, "│")+content+strings.Repeat(" ", padding)+paint(color, colorCyan+colorDim, "│"))
	}
	fmt.Fprintln(w, paint(color, colorCyan+colorDim, "│")+strings.Repeat(" ", width-2)+paint(color, colorCyan+colorDim, "│"))

	title := fmt.Sprintf("%s v%s", b.Name, b.Version)
	writeBannerRow(w, width, color, paint(color, colorBold+colorHiGreen, title))
	writeBannerRow(w, width, color, paint(color, colorHiCyan, b.Description))
	writeBannerRow(w, width, color, paint(color, colorDim, strings.Join(b.Capabilities, "  •  ")))

	fmt.Fprintln(w, paint(color, colorCyan+colorDim, "├"+strings.Repeat("─", width-2)+"┤"))
	build := fmt.Sprintf("Go %s  •  %s/%s  •  %s",
		strings.TrimPrefix(runtime.Version(), "go"),
		runtime.GOOS,
		runtime.GOARCH,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	writeBannerRow(w, width, color, paint(color, colorDim, build))
	fmt.Fprintln(w, paint(color, colorCyan+colorDim, "╰"+strings.Repeat("─", width-2)+"╯"))
	fmt.Fprintln(w)
}

func writeBannerRow(w io.Writer, width int, color bool, content string) {
	padding := width - 6 - visibleWidth(content)
	if padding < 0 {
		padding = 0
	}
	fmt.Fprintf(w, "%s  %s%s  %s\n",
		paint(color, colorCyan+colorDim, "│"),
		content,
		strings.Repeat(" ", padding),
		paint(color, colorCyan+colorDim, "│"),
	)
}

// PrintSimpleBanner prints a medium-width banner.
func (b Banner) PrintSimpleBanner() {
	color := colorsEnabled(os.Stdout)
	const width = 60
	fmt.Fprintln(os.Stdout, paint(color, colorCyan+colorDim, "╭"+strings.Repeat("─", width-2)+"╮"))
	writeBannerRow(os.Stdout, width, color,
		paint(color, colorBold+colorHiGreen, strings.ToUpper(b.Name))+
			paint(color, colorDim, "  v"+b.Version))
	writeBannerRow(os.Stdout, width, color, paint(color, colorHiCyan, b.Description))
	writeBannerRow(os.Stdout, width, color,
		paint(color, colorDim, runtime.GOOS+"/"+runtime.GOARCH+"  •  "+strings.Join(b.Capabilities, "  •  ")))
	fmt.Fprintln(os.Stdout, paint(color, colorCyan+colorDim, "╰"+strings.Repeat("─", width-2)+"╯"))
	fmt.Fprintln(os.Stdout)
}

// PrintMiniBanner prints a minimal single-line banner.
func (b Banner) PrintMiniBanner() {
	color := colorsEnabled(os.Stdout)
	fmt.Fprintf(os.Stdout, "%s %s %s\n\n",
		paint(color, colorBold+colorHiGreen, strings.ToUpper(b.Name)),
		paint(color, colorDim, "v"+b.Version),
		paint(color, colorHiCyan, "request intelligence"),
	)
}

func terminalWidth() int {
	if raw := strings.TrimSpace(os.Getenv("COLUMNS")); raw != "" {
		if width, err := strconv.Atoi(raw); err == nil && width > 0 {
			return width
		}
	}
	return 0
}

func colorsEnabled(file *os.File) bool {
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func paint(enabled bool, style, text string) string {
	if !enabled || text == "" {
		return text
	}
	return style + text + colorReset
}

func visibleWidth(text string) int {
	width := 0
	inEscape := false
	for _, r := range text {
		switch {
		case r == '\x1b':
			inEscape = true
		case inEscape && r == 'm':
			inEscape = false
		case !inEscape:
			width++
		}
	}
	return width
}

// PrintColoredMessage prints a message while respecting NO_COLOR.
func PrintColoredMessage(color, message string) {
	fmt.Fprintln(os.Stdout, paint(colorsEnabled(os.Stdout), color, message))
}

func PrintSuccess(message string) {
	printStatus(colorGreen, "[+]", message)
}

func PrintWarning(message string) {
	printStatus(colorYellow, "[!]", message)
}

func PrintError(message string) {
	printStatus(colorRed, "[-]", message)
}

func PrintInfo(message string) {
	printStatus(colorCyan, "[*]", message)
}

func printStatus(color, marker, message string) {
	enabled := colorsEnabled(os.Stdout)
	fmt.Fprintf(os.Stdout, "%s %s\n", paint(enabled, color+colorBold, marker), message)
}
