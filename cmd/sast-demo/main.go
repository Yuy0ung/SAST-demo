package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sast-demo/pkg/core"
	"sast-demo/pkg/engine"
	"sast-demo/pkg/lang/golang"
	"sast-demo/pkg/lang/java"
	"strings"
)

func main() {
	targetPath := flag.String("path", ".", "Path to file or directory to analyze")
	flag.Parse()

	info, err := os.Stat(*targetPath)
	if err != nil {
		fmt.Printf("Error accessing path: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("🚀 Starting SAST Demo Analysis...")
	fmt.Printf("📂 Target: %s\n", *targetPath)

	config := engine.DefaultRules()
	eng := engine.NewEngine(config)

	var files []string
	if info.IsDir() {
		filepath.Walk(*targetPath, func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() {
				files = append(files, path)
			}
			return nil
		})
	} else {
		files = append(files, *targetPath)
	}

	totalVulns := 0

	for _, file := range files {
		ext := strings.ToLower(filepath.Ext(file))
		var graph *core.Graph
		var analyzerErr error

		if ext == ".go" {
			fmt.Printf("   Analyzing Go file: %s\n", file)
			ga := golang.NewGoAnalyzer()
			analyzerErr = ga.AnalyzeFile(file)
			graph = ga.GetGraph()
		} else if ext == ".java" {
			fmt.Printf("   Analyzing Java file: %s\n", file)
			ja := java.NewJavaAnalyzer()
			analyzerErr = ja.AnalyzeFile(file)
			graph = ja.GetGraph()
		} else {
			continue
		}

		if analyzerErr != nil {
			fmt.Printf("   ⚠️ Error analyzing %s: %v\n", file, analyzerErr)
			continue
		}

		vulns := eng.Analyze(graph)
		if len(vulns) > 0 {
			for _, v := range vulns {
				fmt.Printf("\n🔴 VULNERABILITY DETECTED:\n")
				fmt.Printf("   Type: %s\n", v.Type)
				fmt.Printf("   Severity: %s\n", v.Severity)
				fmt.Printf("   Location: %s:%d\n", v.File, v.Source.Line)
				fmt.Printf("   Flow: %s (Source) -> ... -> %s (Sink)\n", v.Source.Code, v.Sink.Code)
			}
			totalVulns += len(vulns)
		}
	}

	fmt.Printf("\n✅ Analysis Complete. Found %d vulnerabilities.\n", totalVulns)
}
