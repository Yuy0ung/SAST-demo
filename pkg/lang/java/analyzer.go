package java

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sast-demo/pkg/core"
	"strings"
)

type JavaAnalyzer struct {
	graph *core.Graph
}

func NewJavaAnalyzer() *JavaAnalyzer {
	return &JavaAnalyzer{
		graph: core.NewGraph(),
	}
}

func (ja *JavaAnalyzer) GetGraph() *core.Graph {
	return ja.graph
}

func (ja *JavaAnalyzer) AnalyzeFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Regex patterns
	// 1. Assignment: String cmd = request.getParameter("cmd");
	// Matches: Type (optional), VarName, Value
	assignRegex := regexp.MustCompile(`\s*(?:String|var|int|boolean)?\s+(\w+)\s*=\s*(.*);`)

	// 2. Void Call: System.out.println(cmd); or exec(cmd);
	// Matches: FunctionName, Args
	// Modified to be greedy until the last opening parenthesis to handle chains like a.b().c()
	callRegex := regexp.MustCompile(`^\s*(.*)\((.*)\);`)

	// Scope tracking: VarName -> Node
	scope := make(map[string]*core.Node)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Check Assignment first
		if matches := assignRegex.FindStringSubmatch(line); matches != nil {
			varName := matches[1]
			rhs := matches[2]

			// Create LHS Node
			lhsNode := ja.createNode(varName, core.NodeVariable, lineNum, filePath)
			ja.graph.AddNode(lhsNode)
			scope[varName] = lhsNode

			// Analyze RHS
			ja.processRHS(rhs, lhsNode, lineNum, filePath, scope)
			continue
		}

		// Check Void Call
		if matches := callRegex.FindStringSubmatch(line); matches != nil {
			funcName := matches[1]
			args := matches[2]

			callNode := ja.createNode(funcName, core.NodeCall, lineNum, filePath)
			ja.graph.AddNode(callNode)

			ja.processArgs(args, callNode, lineNum, filePath, scope)
		}
	}

	return scanner.Err()
}

func (ja *JavaAnalyzer) processRHS(rhs string, lhsNode *core.Node, line int, file string, scope map[string]*core.Node) {
	// Check if RHS is a call (method call or constructor)
	// Supports: method(), obj.method(), new Class()
	// Regex: (new\s+)?([\w.]+(?:\.\w+)*)\((.*)\)
	callRegex := regexp.MustCompile(`(new\s+)?([\w.]+(?:\.\w+)*)\((.*)\)`)
	if matches := callRegex.FindStringSubmatch(rhs); matches != nil {
		prefix := strings.TrimSpace(matches[1]) // "new" or empty
		rawName := matches[2]
		argsStr := matches[3]

		funcName := rawName
		if prefix == "new" {
			funcName = "new " + rawName
		}

		callNode := ja.createNode(funcName, core.NodeCall, line, file)
		ja.graph.AddNode(callNode)

		// DFG: Call -> LHS
		ja.graph.AddEdge(callNode, lhsNode, core.EdgeDataFlow)

		// Process args
		ja.processArgs(argsStr, callNode, line, file, scope)
	} else {
		// Handle string concatenation or simple assignment
		parts := strings.Split(rhs, "+")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			part = strings.Trim(part, "\"") // Remove quotes for literals

			if part == "" {
				continue
			}

			if node, ok := scope[part]; ok {
				ja.graph.AddEdge(node, lhsNode, core.EdgeDataFlow)
			} else {
				// Literal
				litNode := ja.createNode(part, core.NodeLiteral, line, file)
				ja.graph.AddNode(litNode)
				ja.graph.AddEdge(litNode, lhsNode, core.EdgeDataFlow)
			}
		}
	}
}

func (ja *JavaAnalyzer) processArgs(argsStr string, callNode *core.Node, line int, file string, scope map[string]*core.Node) {
	args := strings.Split(argsStr, ",")
	for _, arg := range args {
		// Handle string concatenation in args
		parts := strings.Split(arg, "+")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			part = strings.Trim(part, "\"") // Remove quotes

			if part == "" {
				continue
			}

			if node, ok := scope[part]; ok {
				ja.graph.AddEdge(node, callNode, core.EdgeDataFlow)
			} else {
				litNode := ja.createNode(part, core.NodeLiteral, line, file)
				ja.graph.AddNode(litNode)
				ja.graph.AddEdge(litNode, callNode, core.EdgeDataFlow)
			}
		}
	}
}

func (ja *JavaAnalyzer) createNode(code string, nType core.NodeType, line int, file string) *core.Node {
	return &core.Node{
		ID:       fmt.Sprintf("%s:%d:%s", file, line, code),
		Type:     nType,
		Code:     code,
		Line:     line,
		File:     file,
		Function: "main", // Simplified
	}
}
