package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/apkbugfinder/scanner/internal/api"
	"github.com/apkbugfinder/scanner/internal/decompile"
	"github.com/apkbugfinder/scanner/internal/engine"
)

func main() {
	var (
		serve         bool
		addr          string
		apkPath       string
		dirPath       string
		workDir       string
		verifySecrets bool
	)

	flag.BoolVar(&serve, "serve", false, "Start HTTP API server")
	flag.StringVar(&addr, "addr", ":8080", "Server listen address")
	flag.StringVar(&apkPath, "p", "", "Path to single APK file")
	flag.StringVar(&dirPath, "m", "", "Path to directory of APK files")
	flag.StringVar(&workDir, "workdir", "", "Working directory for decompilation output")
	flag.BoolVar(&verifySecrets, "verify-secrets", false, "Opt-in: read-only liveness checks on discovered secrets (makes network calls)")
	flag.Parse()

	if serve {
		srv := &api.Server{Addr: addr, WorkDir: workDir, AllowVerify: verifySecrets}
		log.Printf("Apkbugfinder scanner API listening on %s", addr)
		log.Printf("Tools required: jadx, d2j-dex2jar, grep")
		if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := decompile.CheckRequirements(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	if apkPath != "" {
		runScan(apkPath, workDir, verifySecrets)
		return
	}

	if dirPath != "" {
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			log.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".apk" {
				continue
			}
			runScan(filepath.Join(dirPath, e.Name()), workDir, verifySecrets)
		}
		return
	}

	fmt.Println(`Apkbugfinder Scanner — OWASP MASVS (APKHunt parity + advanced)

Usage:
  apkbugfinder -serve [-addr :8080]          Start API server
  apkbugfinder -p /path/to/app.apk           Scan single APK (CLI)
  apkbugfinder -m /path/to/apks/             Scan directory of APKs

Requirements: jadx, d2j-dex2jar, grep`)
}

func runScan(apkPath, workDir string, verifySecrets bool) {
	fmt.Printf("[+] Scanning %s\n", apkPath)
	result, err := engine.Scan(apkPath, engine.Options{WorkDir: workDir, VerifySecrets: verifySecrets})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[+] Done: %d findings (%d bounty, %d live secrets) in %dms\n",
		result.Stats.Total, result.Stats.BountyEligible, result.Stats.LiveSecrets, result.DurationMs)
	for _, f := range result.Findings {
		fmt.Printf("  [%s] %s — %s (%s)\n", f.Severity, f.Title, f.MASVS, f.File)
	}
	if result.Recon != nil {
		fmt.Printf("[+] Recon: %d endpoints, %d hosts, %d secrets\n",
			len(result.Recon.Endpoints), len(result.Recon.Hosts), len(result.Recon.Secrets))
	}
}
