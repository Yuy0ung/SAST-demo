package service

import (
	"fmt"
	"os"
	"path/filepath"
	"sast-demo/pkg/core"
	"sast-demo/pkg/engine"
	"sast-demo/pkg/lang/golang"
	"sast-demo/pkg/lang/java"
	"strings"
)

type AnalysisResult struct {
	File            string               `json:"file"`
	IR              *core.ProgramIR      `json:"ir"`
	AST             *core.ASTNode        `json:"ast"` // Abstract Syntax Tree
	Vulnerabilities []core.Vulnerability `json:"vulnerabilities"`
	Logs            []string             `json:"logs"`
}

func Analyze(filePath string) (*AnalysisResult, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}

	result := &AnalysisResult{
		File: filePath,
		Logs: []string{},
	}

	ext := strings.ToLower(filepath.Ext(absPath))
	cfg := engine.DefaultRules()
	eng := engine.NewEngine(cfg)

	result.Logs = append(result.Logs, fmt.Sprintf("Starting analysis for %s (Type: %s)", absPath, ext))

	var vulns []core.Vulnerability

	if ext == ".go" {
		result.Logs = append(result.Logs, "Using Go IR Generator...")
		gen := golang.NewIRGenerator()
		ir, err := gen.Generate(absPath)
		if err != nil {
			return nil, fmt.Errorf("Go IR Gen failed: %v", err)
		}
		result.IR = ir
		result.Logs = append(result.Logs, fmt.Sprintf("Generated IR with %d functions", len(ir.Functions)))

		// AST Generation
		result.Logs = append(result.Logs, "Generating Go AST...")
		astGen := golang.NewASTGenerator()
		astRoot, err := astGen.Generate(absPath)
		if err == nil {
			result.AST = astRoot
		} else {
			result.Logs = append(result.Logs, fmt.Sprintf("Go AST Gen failed: %v", err))
		}

		vulns = eng.AnalyzeIR(ir, absPath)
		result.Logs = append(result.Logs, fmt.Sprintf("Engine found %d vulnerabilities", len(vulns)))

	} else if ext == ".java" {
		result.Logs = append(result.Logs, "Using Java IR Generator (Experimental)...")
		gen := java.NewJavaIRGenerator()
		ir, err := gen.Generate(absPath)
		if err != nil {
			return nil, fmt.Errorf("Java IR Gen failed: %v", err)
		}
		result.IR = ir
		result.Logs = append(result.Logs, fmt.Sprintf("Generated IR with %d functions", len(ir.Functions)))

		// AST Generation
		result.Logs = append(result.Logs, "Generating Java AST...")
		astGen := java.NewJavaASTGenerator()
		astRoot, err := astGen.Generate(absPath)
		if err == nil {
			result.AST = astRoot
		} else {
			result.Logs = append(result.Logs, fmt.Sprintf("Java AST Gen failed: %v", err))
		}

		vulns = eng.AnalyzeIR(ir, absPath)
		result.Logs = append(result.Logs, fmt.Sprintf("Engine found %d vulnerabilities", len(vulns)))
	} else {
		return nil, fmt.Errorf("Unsupported file type: %s", ext)
	}

	// Post-process: Enrich Path with Source Code
	enrichVulnerabilities(absPath, vulns)
	result.Vulnerabilities = vulns

	return result, nil
}

func enrichVulnerabilities(filePath string, vulns []core.Vulnerability) {
	// Read file content once
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return
	}
	lines := strings.Split(string(fileContent), "\n")

	for i := range vulns {
		v := &vulns[i]
		var newPath []*core.Node
		lastLine := -1

		// Update Path Nodes and Deduplicate
		for _, node := range v.Path {
			if node.Line > 0 && node.Line <= len(lines) {
				// Replace Code with actual source line (trimmed)
				node.Code = strings.TrimSpace(lines[node.Line-1])
			}

			// Deduplication logic
			if node.Line != lastLine {
				newPath = append(newPath, node)
				lastLine = node.Line
			}
		}
		v.Path = newPath

		// Also update Source and Sink if needed
		if v.Source.Line > 0 && v.Source.Line <= len(lines) {
			v.Source.Code = strings.TrimSpace(lines[v.Source.Line-1])
		}
		if v.Sink.Line > 0 && v.Sink.Line <= len(lines) {
			v.Sink.Code = strings.TrimSpace(lines[v.Sink.Line-1])
		}
	}
}

func ReadFile(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		if abs, err2 := filepath.Abs(filePath); err2 == nil {
			content, err = os.ReadFile(abs)
		}
	}
	if err != nil {
		return "", err
	}
	return string(content), nil
}
