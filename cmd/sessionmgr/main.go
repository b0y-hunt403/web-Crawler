package main

import (
	"context"
	"fmt"
	"github.com/Anduamlk/web-Crawler/session"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	loadDotEnv(".env")

	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "record":
		cmdRecord(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "export":
		cmdExport(os.Args[2:])
	default:
		usage()
	}
}

// loadDotEnv applies KEY=VALUE lines from a .env file in the working
// directory, if one exists. Deliberately dependency-free (no godotenv) for
// something this small. Real environment variables always win — a .env
// value never overrides one already set, matching how every other tool
// with this convention behaves (docker-compose, dotenv, etc.), so
// PLAYSCAN_* set explicitly in a shell or Kubernetes manifest still takes
// precedence over whatever's checked into .env.
func loadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // no .env file present — not an error, just nothing to load
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if _, alreadySet := os.LookupEnv(key); alreadySet {
			continue
		}
		_ = os.Setenv(key, value)
	}
}

func usage() {
	fmt.Println(`Usage:
  sessionmgr record <target_url> <role_name>     capture a login session for one role
  sessionmgr scan   <target_url> [role1,role2]   crawl unauthenticated + each role
                                                  (omit roles to use every role on file for this target)
  sessionmgr verify <target_url> <role_name>     replay the recorded login in a HEADED browser
                                                  you can watch, to confirm it still logs in
  sessionmgr export <target_url> <role_name> <session.json> [--refresh]
                                                export reusable storage_state JSON;
                                                --refresh replays login first

Archive storage (profile archives, not the sqlite index):
  MinIO is used automatically when configured and reachable. Set:
    PLAYSCAN_MINIO_ENDPOINT     e.g. minio.playscan.svc:9000
    PLAYSCAN_MINIO_ACCESS_KEY
    PLAYSCAN_MINIO_SECRET_KEY
    PLAYSCAN_MINIO_BUCKET       optional, defaults to "playscan-sessions"
    PLAYSCAN_MINIO_USE_SSL      optional, "true"/"false", defaults to false

  Local disk is used only if explicitly requested or MinIO can't be reached:
    PLAYSCAN_ARCHIVE_BACKEND=local
    PLAYSCAN_ARCHIVES_DIR        optional, defaults to ./profiles

  PLAYSCAN_ARCHIVE_BACKEND=minio forces MinIO and fails startup instead of
  falling back if it can't connect.`)
	os.Exit(1)
}

func cmdExport(args []string) {
	if len(args) < 3 {
		usage()
	}
	targetURL, roleName, outputPath := args[0], args[1], args[2]
	refresh := len(args) > 3 && args[3] == "--refresh"
	sessionID := fmt.Sprintf("%s|%s", targetURL, roleName)

	store, err := session.OpenStore("./scanner.db")
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	managed := session.NewManagedSession(store, sessionID)
	if err := managed.Export(context.Background(), outputPath, refresh); err != nil {
		log.Fatalf("export session: %v", err)
	}
	log.Printf("[+] Session %q exported to %s", sessionID, outputPath)
}

// cmdRecord launches the headless recording browser + local relay UI, and
// blocks until the operator finishes logging in through it.
func cmdRecord(args []string) {
	if len(args) < 2 {
		usage()
	}
	targetURL, roleName := args[0], args[1]

	store, err := session.OpenStore("./scanner.db")
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	rec := session.NewRecorder(store, targetURL, roleName)
	defer rec.Close()

	mux := http.NewServeMux()
	rec.RegisterHandlers(mux)
	srv := &http.Server{Addr: "0.0.0.0:8901", Handler: mux}
	go func() {
		log.Println("[+] Open http://0.0.0.0:8901 (tunnel this port from the scan pod) to log in as", roleName)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("recorder server: %v", err)
		}
	}()

	if err := rec.Start(context.Background()); err != nil {
		log.Fatalf("recording failed: %v", err)
	}
	_ = srv.Close()
	fmt.Printf("[\u2713] Session saved for role %q on %s\n", roleName, targetURL)
}

// cmdScan always runs the unauthenticated baseline crawl first, then one
// crawl per requested role, each in its own freshly injected headless
// context. Roles are optional on the CLI; if omitted, every role recorded
// for this target is pulled from the store.
func cmdScan(args []string) {
	if len(args) < 1 {
		usage()
	}
	targetURL := args[0]

	store, err := session.OpenStore("./scanner.db")
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	var roles []string
	if len(args) >= 2 && args[1] != "" {
		roles = strings.Split(args[1], ",")
	} else {
		roles, err = store.ListRoles(targetURL)
		if err != nil {
			log.Fatalf("list roles: %v", err)
		}
	}

	runCrawl(store, targetURL, "" /* unauthenticated baseline, always first */)
	for _, role := range roles {
		sessionID := fmt.Sprintf("%s|%s", targetURL, role)
		runCrawl(store, targetURL, sessionID)
	}
}

// cmdVerify replays a recorded login in a headed browser the operator can
// watch, to confirm the session establishment protocol still works before
// relying on it in an actual scan.
func cmdVerify(args []string) {
	if len(args) < 2 {
		usage()
	}
	targetURL, roleName := args[0], args[1]
	sessionID := fmt.Sprintf("%s|%s", targetURL, roleName)

	store, err := session.OpenStore("./scanner.db")
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	closeBrowser, verifyErr := session.VerifySEP(context.Background(), store, sessionID)
	if closeBrowser == nil {
		// The browser never launched at all (e.g. no SEP recorded for this
		// session) — nothing to inspect, so just report and exit.
		log.Fatalf("verify failed: %v", verifyErr)
	}

	// Deliberately not log.Fatalf on a replay failure below: that calls
	// os.Exit internally, which skips deferred/pending cleanup — meaning
	// the browser window (exactly what's needed to see where the replay
	// broke) would vanish instead of staying open for inspection.
	if verifyErr != nil {
		fmt.Printf("[!] Replay failed: %v\n", verifyErr)
		fmt.Println("    The browser window is still open so you can inspect where it stopped.")
	} else {
		fmt.Println("[\u2713] Replay finished. Check the browser window to confirm the login succeeded.")
	}
	fmt.Println("Press Enter here to close the browser.")
	fmt.Scanln()
	closeBrowser()

	if verifyErr != nil {
		os.Exit(1)
	}
}

func runCrawl(store *session.Store, targetURL, sessionID string) {
	label := "unauthenticated"
	if sessionID != "" {
		label = sessionID
	}
	log.Printf("[+] Starting crawl: %s", label)

	ic, err := session.InjectSession(context.Background(), store, sessionID)
	if err != nil {
		log.Printf("[!] Skipping %s: %v", label, err)
		return
	}
	defer ic.Close()

	// TODO: hand ic.Ctx to playscan's crawler.Crawl(ic.Ctx, targetURL, ...).
	// It's a normal chromedp context from here on; the crawler doesn't need
	// to know whether it was injected with a role or left bare.
	log.Printf("[\u2713] Context ready for crawl (id=%s)", ic.CrawlContextID)
}
