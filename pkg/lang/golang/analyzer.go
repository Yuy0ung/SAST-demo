package golang

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sast-demo/pkg/core"
)

type GoAnalyzer struct {
	graph *core.Graph
	fset  *token.FileSet
}

func NewGoAnalyzer() *GoAnalyzer {
	return &GoAnalyzer{
		graph: core.NewGraph(),
		fset:  token.NewFileSet(),
	}
}

func (ga *GoAnalyzer) GetGraph() *core.Graph {
	return ga.graph
}

func (ga *GoAnalyzer) AnalyzeFile(filePath string) error {
	node, err := parser.ParseFile(ga.fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	// We track variable definitions within functions
	// Map: FunctionName -> VariableName -> Node
	// Simple assumption: unique variable names per function for this demo
	scope := make(map[string]map[string]*core.Node)
	currentFunc := ""

	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			return true
		}

		switch x := n.(type) {
		case *ast.FuncDecl:
			currentFunc = x.Name.Name
			scope[currentFunc] = make(map[string]*core.Node)

			// Create function node
			fnNode := ga.createNode(x.Name.Name, core.NodeFunction, x.Pos(), filePath, currentFunc)
			ga.graph.AddNode(fnNode)

			// Handle parameters
			for _, field := range x.Type.Params.List {
				for _, name := range field.Names {
					paramNode := ga.createNode(name.Name, core.NodeParameter, name.Pos(), filePath, currentFunc)
					ga.graph.AddNode(paramNode)
					scope[currentFunc][name.Name] = paramNode
				}
			}

		case *ast.AssignStmt:
			// Handle assignments: lhs := rhs
			// We support simple 1-to-1 or N-to-N assignments
			for i, lhs := range x.Lhs {
				var rhs ast.Expr
				if i < len(x.Rhs) {
					rhs = x.Rhs[i]
				}

				// Resolve RHS node
				rhsNode := ga.resolveExpr(rhs, filePath, currentFunc, scope)

				// Handle LHS
				if ident, ok := lhs.(*ast.Ident); ok {
					lhsNode := ga.createNode(ident.Name, core.NodeVariable, ident.Pos(), filePath, currentFunc)
					ga.graph.AddNode(lhsNode)

					// Update scope with new definition
					scope[currentFunc][ident.Name] = lhsNode

					// Add DFG edge
					if rhsNode != nil {
						ga.graph.AddEdge(rhsNode, lhsNode, core.EdgeDataFlow)
					}
				}
			}

		case *ast.ExprStmt:
			// Standalone calls like sink(x)
			if call, ok := x.X.(*ast.CallExpr); ok {
				ga.processCall(call, filePath, currentFunc, scope)
			}
		}

		return true
	})

	return nil
}

func (ga *GoAnalyzer) resolveExpr(expr ast.Expr, filePath, funcName string, scope map[string]map[string]*core.Node) *core.Node {
	switch e := expr.(type) {
	case *ast.CallExpr:
		return ga.processCall(e, filePath, funcName, scope)
	case *ast.Ident:
		if def, ok := scope[funcName][e.Name]; ok {
			return def
		}
		// Undefined or global
		node := ga.createNode(e.Name, core.NodeVariable, e.Pos(), filePath, funcName)
		ga.graph.AddNode(node)
		return node
	case *ast.BasicLit:
		node := ga.createNode(e.Value, core.NodeLiteral, e.Pos(), filePath, funcName)
		ga.graph.AddNode(node)
		return node
	case *ast.IndexExpr:
		// Handle x[i] -> just return x for taint purposes
		return ga.resolveExpr(e.X, filePath, funcName, scope)
	case *ast.SelectorExpr:
		// Handle x.y -> return x.y as name
		name := ga.flattenSelector(e)
		node := ga.createNode(name, core.NodeVariable, e.Pos(), filePath, funcName)
		ga.graph.AddNode(node)
		return node
	}
	return nil
}

func (ga *GoAnalyzer) flattenSelector(sel *ast.SelectorExpr) string {
	if x, ok := sel.X.(*ast.Ident); ok {
		return x.Name + "." + sel.Sel.Name
	}
	if x, ok := sel.X.(*ast.SelectorExpr); ok {
		return ga.flattenSelector(x) + "." + sel.Sel.Name
	}
	return sel.Sel.Name
}

func (ga *GoAnalyzer) processCall(call *ast.CallExpr, filePath, funcName string, scope map[string]map[string]*core.Node) *core.Node {
	// Determine function name
	funName := ""
	switch f := call.Fun.(type) {
	case *ast.Ident:
		funName = f.Name
	case *ast.SelectorExpr:
		funName = ga.flattenSelector(f)
	default:
		funName = "unknown_call"
	}

	callNode := ga.createNode(funName, core.NodeCall, call.Pos(), filePath, funcName)
	ga.graph.AddNode(callNode)

	// Process arguments (Data Flow: Arg -> Call)
	for _, arg := range call.Args {
		argNode := ga.resolveExpr(arg, filePath, funcName, scope)
		if argNode != nil {
			ga.graph.AddEdge(argNode, callNode, core.EdgeDataFlow)
		}
	}

	return callNode
}

func (ga *GoAnalyzer) createNode(code string, nType core.NodeType, pos token.Pos, file, function string) *core.Node {
	position := ga.fset.Position(pos)
	return &core.Node{
		ID:       fmt.Sprintf("%s:%d:%s", file, position.Line, code), // Simple ID generation
		Type:     nType,
		Code:     code,
		Line:     position.Line,
		File:     file,
		Function: function,
	}
}
