package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sast-demo/pkg/engine"
	"sast-demo/pkg/lang/golang"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sast-cli-ir <file>")
		os.Exit(1)
	}

	filePath, _ := filepath.Abs(os.Args[1])
	fmt.Printf("Analyzing: %s\n", filePath)

	// 1. Generate IR
	gen := golang.NewIRGenerator()
	ir, err := gen.Generate(filePath)
	if err != nil {
		panic(err)
	}

	// Print IR for debugging
	// irJSON, _ := json.MarshalIndent(ir, "", "  ")
	// fmt.Println(string(irJSON))

	// 2. Analyze
	cfg := engine.DefaultRules()
	eng := engine.NewEngine(cfg)
	vulns := eng.AnalyzeIR(ir, filePath)

	fmt.Printf("Found %d vulnerabilities:\n", len(vulns))
	for _, v := range vulns {
		fmt.Printf("- [%s] %s (Line %d)\n", v.Severity, v.Type, v.Line)
		fmt.Printf("  Path: %s -> %s\n", v.Source.Code, v.Sink.Code)
	}

	if len(vulns) == 0 {
		// Dump IR Instructions to see what went wrong
		fmt.Println("\n--- Debug IR ---")
		for _, fn := range ir.Functions {
			fmt.Printf("Function %s:\n", fn.Name)
			for _, bb := range fn.Blocks {
				for _, inst := range bb.Instructions {
					fmt.Printf("  %s: %s\n", inst.ID, inst.Code)
				}
			}
		}
	}
}
