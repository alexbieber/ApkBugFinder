package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/apkbugfinder/scanner/internal/decompile"
	"github.com/apkbugfinder/scanner/internal/engine"
	"github.com/apkbugfinder/scanner/internal/types"
)

type Server struct {
	Addr    string
	WorkDir string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("POST /api/v1/scan", s.handleScan)
	mux.HandleFunc("GET /api/v1/requirements", s.handleRequirements)
	return withCORS(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	err := decompile.CheckRequirements()
	status := "ok"
	code := http.StatusOK
	var missing []string
	if err != nil {
		status = "degraded"
		missing = []string{err.Error()}
	}
	writeJSON(w, code, map[string]any{
		"status":  status,
		"engine":  "apkbugfinder-scanner",
		"version": "1.0.0",
		"missing": missing,
	})
}

func (s *Server) handleRequirements(w http.ResponseWriter, r *http.Request) {
	err := decompile.CheckRequirements()
	writeJSON(w, http.StatusOK, map[string]any{
		"ready": err == nil,
		"tools": []string{"jadx", "d2j-dex2jar", "grep"},
		"error": errMsg(err),
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		http.Error(w, "invalid multipart form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("apk")
	if err != nil {
		http.Error(w, "missing apk file field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	workDir := s.WorkDir
	if workDir == "" {
		workDir = filepath.Join(os.TempDir(), "apkbugfinder-uploads")
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	apkPath := filepath.Join(workDir, fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(header.Filename)))
	out, err := os.Create(apkPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out.Close()
	defer os.Remove(apkPath)

	result, err := engine.Scan(apkPath, engine.Options{WorkDir: workDir})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func errMsg(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Ensure types package is referenced for swagger/docs
var _ = types.ScanResult{}
