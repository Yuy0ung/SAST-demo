package java

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sast-demo/pkg/core"
	"strings"
)

// JavaASTGenerator creates a pseudo-AST for Java using regex
type JavaASTGenerator struct {
}

func NewJavaASTGenerator() *JavaASTGenerator {
	return &JavaASTGenerator{}
}

func (g *JavaASTGenerator) Generate(filePath string) (*core.ASTNode, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	root := &core.ASTNode{
		Key:   "root",
		Title: "File: " + filePath,
		Line:  1,
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Stack to keep track of hierarchy
	// 0: Root
	stack := []*core.ASTNode{root}
	
	// Regex patterns
	classRegex := regexp.MustCompile(`^\s*(?:public|private|protected)?\s*class\s+([a-zA-Z0-9_]+)`)
	methodRegex := regexp.MustCompile(`^\s*(?:public|private|protected|static|\s)*[\w<>[\]]+\s+([a-zA-Z0-9_]+)\s*\(.*\)`)
	ifRegex := regexp.MustCompile(`^\s*if\s*\((.*)\)`)
	elseRegex := regexp.MustCompile(`^\s*\}\s*else`)
	whileRegex := regexp.MustCompile(`^\s*while\s*\((.*)\)`)
	forRegex := regexp.MustCompile(`^\s*for\s*\((.*)\)`)
	callRegex := regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+\s*\(.*\));`)
	assignRegex := regexp.MustCompile(`^\s*([a-zA-Z0-9_]+)\s*=\s*(.+);`)
	closeRegex := regexp.MustCompile(`^\s*\}\s*$`)

	nodeCount := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		var newNode *core.ASTNode
		title := ""
		
		if matches := classRegex.FindStringSubmatch(line); matches != nil {
			title = "ClassDecl: " + matches[1]
			newNode = &core.ASTNode{Title: title, Line: lineNum}
		} else if matches := methodRegex.FindStringSubmatch(line); matches != nil && !strings.Contains(line, ";") && !strings.Contains(line, "=") {
			// Basic heuristic to avoid confusing method calls/assignments with declarations
			title = "MethodDecl: " + matches[1]
			newNode = &core.ASTNode{Title: title, Line: lineNum}
		} else if matches := ifRegex.FindStringSubmatch(line); matches != nil {
			title = "IfStmt: " + matches[1]
			newNode = &core.ASTNode{Title: title, Line: lineNum}
		} else if matches := elseRegex.FindStringSubmatch(line); matches != nil {
			title = "ElseStmt"
			newNode = &core.ASTNode{Title: title, Line: lineNum}
		} else if matches := whileRegex.FindStringSubmatch(line); matches != nil {
			title = "WhileStmt: " + matches[1]
			newNode = &core.ASTNode{Title: title, Line: lineNum}
		} else if matches := forRegex.FindStringSubmatch(line); matches != nil {
			title = "ForStmt: " + matches[1]
			newNode = &core.ASTNode{Title: title, Line: lineNum}
		} else if matches := assignRegex.FindStringSubmatch(line); matches != nil {
			title = fmt.Sprintf("AssignStmt: %s = %s", matches[1], matches[2])
			// Assignments are usually leaf nodes in this simplified view, but we add them
			leaf := &core.ASTNode{
				Key: fmt.Sprintf("%s-%d", stack[len(stack)-1].Key, nodeCount),
				Title: title,
				Line: lineNum,
			}
			nodeCount++
			stack[len(stack)-1].Children = append(stack[len(stack)-1].Children, leaf)
			continue
		} else if matches := callRegex.FindStringSubmatch(line); matches != nil {
			title = "ExprStmt: " + matches[1]
			leaf := &core.ASTNode{
				Key: fmt.Sprintf("%s-%d", stack[len(stack)-1].Key, nodeCount),
				Title: title,
				Line: lineNum,
			}
			nodeCount++
			stack[len(stack)-1].Children = append(stack[len(stack)-1].Children, leaf)
			continue
		} else if closeRegex.MatchString(line) {
			// Pop stack
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		}

		if newNode != nil {
			parent := stack[len(stack)-1]
			newNode.Key = fmt.Sprintf("%s-%d", parent.Key, nodeCount)
			nodeCount++
			parent.Children = append(parent.Children, newNode)
			
			// If it opens a block, push to stack
			if strings.HasSuffix(line, "{") {
				stack = append(stack, newNode)
			}
		}
	}

	return root, nil
}
