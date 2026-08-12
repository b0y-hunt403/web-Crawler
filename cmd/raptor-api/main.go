package main

import (
	"flag"
	"github.com/Anduamlk/web-Crawler/api"
	"log"
	"net/http"
	"os"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8787", "listen address")
	db := flag.String("db", "raptor-api.db", "sqlite database")
	flag.Parse()
	key := os.Getenv("RAPTOR_API_KEY")
	if key == "" && os.Getenv("RAPTOR_API_DEV_MODE") != "true" {
		log.Fatal("RAPTOR_API_KEY is required unless RAPTOR_API_DEV_MODE=true")
	}
	if key == "" {
		log.Print("WARNING: API development mode enabled; no API key configured")
	}
	s, e := api.New(*db, key)
	if e != nil {
		log.Fatal(e)
	}
	defer s.Close()
	log.Printf("Raptor API listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, s.Handler()))
}
