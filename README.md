# 🦅 Raptor Crawler

<div align="center">
  <img src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=for-the-badge&logo=go" alt="Go Version"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" alt="Platform"/>
  <img src="https://img.shields.io/badge/Version-2.0.0-green?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/Built%20with-Go-blue?style=for-the-badge&logo=go" alt="Built with Go"/>
  
  <br><br>
  
  > **Advanced Web Security Crawler with Request Intelligence**  
  > Discover endpoints, forms, API routes, and hidden attack surfaces in modern web applications.
</div>

## 🔥 Features

- 🎯 **Static & Dynamic Crawling** - Fast static crawling + headless browser for SPAs
- 🔐 **Form Discovery** - Automatically detect and extract all forms with parameters
- 📦 **JSON Support** - Capture JSON payloads from modern SPAs
- 🕸️ **SPA Detection** - Discover React, Vue, Angular, and Next.js routes
- 📊 **AJAX/Fetch Detection** - Capture XHR, fetch, and axios requests
- 📝 **Request Templates** - Generate reusable request templates with JSON schemas
- 💾 **SQLite Storage** - All results saved to SQLite database
- 🎨 **Beautiful CLI** - Colored output with professional banner
- 🔄 **Both Modes** - Run static and dynamic in one command

## 🚀 Quick Install

### Option 1: Go Install (Recommended)

```bash
go install github.com/Anduamlk/raptor-crawler/cmd/crawler@latest

Clone & Build

bash
git clone https://github.com/yourusername/raptor-crawler.git
cd raptor-crawler
go mod download
go build -o raptor cmd/crawler/main.go


Using curl (Linux/macOS)
bash
curl -L https://github.com/yourusername/raptor-crawler/releases/latest/download/raptor-linux-amd64 -o raptor
chmod +x raptor
sudo mv raptor /usr/local/bin/



📖 Usage
Basic Commands
bash
# Static crawling only
raptor -url http://localhost:3000 -db results.db -depth 3 -pages 100

# Dynamic crawling only
raptor -url http://localhost:3000 -db results.db -depth 3 -pages 100 -dynamic

# Both static AND dynamic (Recommended)
raptor -url http://localhost:3000 -db results.db -depth 3 -pages 100 -both

# With JSON output
raptor -url http://localhost:3000 -db results.db -depth 3 -pages 100 -both -output results.json

# With session (authenticated crawling)
raptor -url http://localhost:3000 -db results.db -session session.json -both