package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sast-demo/pkg/core"
	"sast-demo/pkg/engine"
	"sast-demo/pkg/lang/golang"
)

type AnalysisResult struct {
	File            string               `json:"file"`
	IR              *core.ProgramIR      `json:"ir"`
	Vulnerabilities []core.Vulnerability `json:"vulnerabilities"`
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "path required", 400)
		return
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		// Try relative to cwd
		if abs, err2 := filepath.Abs(filePath); err2 == nil {
			content, err = os.ReadFile(abs)
		}
	}

	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}

	w.Write(content)
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	// CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	filePath := r.URL.Query().Get("file")
	if filePath == "" {
		filePath = "examples/go/vuln.go" // Default
	}

	absPath, _ := filepath.Abs(filePath)
	fmt.Printf("Analyzing: %s\n", absPath)

	// 1. Generate IR
	gen := golang.NewIRGenerator()
	ir, err := gen.Generate(absPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// 2. Run Taint Analysis on IR
	cfg := engine.DefaultRules()
	eng := engine.NewEngine(cfg)
	vulns := eng.AnalyzeIR(ir, filePath)

	result := AnalysisResult{
		File:            filePath,
		IR:              ir,
		Vulnerabilities: vulns,
	}

	json.NewEncoder(w).Encode(result)
}

func main() {
	http.Handle("/", http.FileServer(http.Dir("cmd/sast-web/static")))
	http.HandleFunc("/api/analyze", analyzeHandler)
	http.HandleFunc("/api/file", fileHandler)

	fmt.Println("🌍 SAST Web Server running at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
