// crawler/banner.go
package crawler

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorRed    = "\033[31m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// Banner represents the crawler banner
type Banner struct {
	Name        string
	Version     string
	Author      string
	Description string
}

// DefaultBanner returns the default banner
func DefaultBanner() Banner {
	return Banner{
		Name:        "Raptor",
		Version:     "2.0.0",
		Author:      "B0y",
		Description: "Advanced Web Security Crawler with Request Intelligence",
	}
}

// PrintBanner prints the modern colored banner with Raptor ASCII art
func (b Banner) PrintBanner() {
	// Top border with gradient effect
	fmt.Println(colorCyan + strings.Repeat("━", 72) + colorReset)
	fmt.Println()

	// Raptor ASCII Art with colored "Raptor"
	fmt.Print("  ")
	fmt.Print(colorCyan + "██████╗  " + colorReset)
	fmt.Print(colorGreen + "██████╗ " + colorReset)
	fmt.Print(colorYellow + "██████╗ " + colorReset)
	fmt.Print(colorPurple + "████████╗" + colorReset)
	fmt.Print(colorRed + " ██████╗ " + colorReset)
	fmt.Print(colorGreen + "██████╗ " + colorReset)
	fmt.Println()

	fmt.Print("  ")
	fmt.Print(colorCyan + "██╔══██╗" + colorReset)
	fmt.Print(colorGreen + "██╔══██╗" + colorReset)
	fmt.Print(colorYellow + "██╔══██╗" + colorReset)
	fmt.Print(colorPurple + "╚══██╔══╝" + colorReset)
	fmt.Print(colorRed + "██╔═══██╗" + colorReset)
	fmt.Print(colorGreen + "██╔══██╗" + colorReset)
	fmt.Println()

	fmt.Print("  ")
	fmt.Print(colorCyan + "██████╔╝" + colorReset)
	fmt.Print(colorGreen + "██████╔╝" + colorReset)
	fmt.Print(colorYellow + "██████╔╝" + colorReset)
	fmt.Print(colorPurple + "   ██║   " + colorReset)
	fmt.Print(colorRed + "██║   ██║" + colorReset)
	fmt.Print(colorGreen + "██████╔╝" + colorReset)
	fmt.Println()

	fmt.Print("  ")
	fmt.Print(colorCyan + "██╔══██╗" + colorReset)
	fmt.Print(colorGreen + "██╔══██╗" + colorReset)
	fmt.Print(colorYellow + "██╔═══╝ " + colorReset)
	fmt.Print(colorPurple + "   ██║   " + colorReset)
	fmt.Print(colorRed + "██║   ██║" + colorReset)
	fmt.Print(colorGreen + "██╔══██╗" + colorReset)
	fmt.Println()

	fmt.Print("  ")
	fmt.Print(colorCyan + "██║  ██║" + colorReset)
	fmt.Print(colorGreen + "██║  ██║" + colorReset)
	fmt.Print(colorYellow + "██║     " + colorReset)
	fmt.Print(colorPurple + "   ██║   " + colorReset)
	fmt.Print(colorRed + "╚██████╔╝" + colorReset)
	fmt.Print(colorGreen + "██║  ██║" + colorReset)
	fmt.Println()

	fmt.Print("  ")
	fmt.Print(colorCyan + "╚═╝  ╚═╝" + colorReset)
	fmt.Print(colorGreen + "╚═╝  ╚═╝" + colorReset)
	fmt.Print(colorYellow + "╚═╝     " + colorReset)
	fmt.Print(colorPurple + "   ╚═╝   " + colorReset)
	fmt.Print(colorRed + " ╚═════╝ " + colorReset)
	fmt.Print(colorGreen + "╚═╝  ╚═╝" + colorReset)
	fmt.Println()

	fmt.Println()
	fmt.Print("  ")
	fmt.Print(colorGreen + colorBold + b.Name + colorReset)
	fmt.Print(" ")
	fmt.Print(colorDim + "v" + b.Version + colorReset)
	fmt.Print("  │  ")
	fmt.Print(colorBlue + b.Description + colorReset)
	fmt.Println()

	fmt.Print("  ")
	fmt.Print(colorPurple + "Author: " + colorReset + colorGreen + b.Author + colorReset)
	fmt.Print("  │  ")
	fmt.Print(colorBlue + "Go: " + colorReset + runtime.Version())
	fmt.Println()

	fmt.Print("  ")
	fmt.Print(colorBlue + "OS: " + colorReset + runtime.GOOS + "/" + runtime.GOARCH)
	fmt.Print("  │  ")
	fmt.Print(colorBlue + "Time: " + colorReset + time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	fmt.Println()
	fmt.Println(colorCyan + strings.Repeat("━", 72) + colorReset)
	fmt.Println()
}

// PrintSimpleBanner prints a simpler colored banner (for smaller terminals)
func (b Banner) PrintSimpleBanner() {
	fmt.Println(colorCyan + strings.Repeat("─", 60) + colorReset)
	fmt.Println()
	fmt.Printf("  %s%s%s %s v%s\n", colorGreen, colorBold, b.Name, colorReset, b.Version)
	fmt.Printf("  %s%s\n", colorBlue, b.Description)
	fmt.Printf("  %sAuthor: %s%s%s\n", colorBlue, colorGreen, b.Author, colorReset)
	fmt.Printf("  %sGo: %s | OS: %s/%s%s\n", colorBlue, runtime.Version(), runtime.GOOS, runtime.GOARCH, colorReset)
	fmt.Println()
	fmt.Println(colorCyan + strings.Repeat("─", 60) + colorReset)
	fmt.Println()
}

// PrintMiniBanner prints a minimal banner
func (b Banner) PrintMiniBanner() {
	fmt.Printf("%s%s%s %s v%s %s|%s %s%s%s\n",
		colorGreen, colorBold, b.Name, colorReset, b.Version,
		colorDim, colorReset,
		colorBlue, time.Now().Format("15:04:05"), colorReset)
}

// PrintColoredMessage prints a colored message
func PrintColoredMessage(color, message string) {
	fmt.Printf("%s%s%s\n", color, message, colorReset)
}

// PrintSuccess prints a success message in green
func PrintSuccess(message string) {
	fmt.Printf("%s✅ %s%s\n", colorGreen, message, colorReset)
}

// PrintWarning prints a warning message in yellow
func PrintWarning(message string) {
	fmt.Printf("%s⚠️  %s%s\n", colorYellow, message, colorReset)
}

// PrintError prints an error message in red
func PrintError(message string) {
	fmt.Printf("%s❌ %s%s\n", colorRed, message, colorReset)
}

// PrintInfo prints an info message in cyan
func PrintInfo(message string) {
	fmt.Printf("%sℹ️  %s%s\n", colorCyan, message, colorReset)
}