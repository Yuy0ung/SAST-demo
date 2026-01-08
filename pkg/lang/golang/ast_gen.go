package golang

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sast-demo/pkg/core"
	"strconv"
)

type ASTGenerator struct {
	fset *token.FileSet
}

func NewASTGenerator() *ASTGenerator {
	return &ASTGenerator{
		fset: token.NewFileSet(),
	}
}

func (g *ASTGenerator) Generate(filePath string) (*core.ASTNode, error) {
	node, err := parser.ParseFile(g.fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	root := &core.ASTNode{
		Key:   "root",
		Title: "File: " + filePath,
		Line:  1,
	}

	g.visit(node, root, "0")
	return root, nil
}

func (g *ASTGenerator) visit(node ast.Node, parent *core.ASTNode, idPrefix string) {
	if node == nil || reflect.ValueOf(node).IsNil() {
		return
	}

	// Simple recursive visitor to build the tree
	// We use reflection to iterate over fields of ast.Node to make it generic

	val := reflect.ValueOf(node)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	typ := val.Type()

	// Get Line number
	line := g.fset.Position(node.Pos()).Line

	// Create current node
	currentNode := &core.ASTNode{
		Key:   idPrefix,
		Title: fmt.Sprintf("%v", typ),
		Line:  line,
	}

	// Enhance Title with specific info
	switch n := node.(type) {
	case *ast.Ident:
		currentNode.Title += fmt.Sprintf(" (Name: %s)", n.Name)
	case *ast.BasicLit:
		currentNode.Title += fmt.Sprintf(" (Value: %s)", n.Value)
	case *ast.FuncDecl:
		currentNode.Title += fmt.Sprintf(" (Name: %s)", n.Name.Name)
	case *ast.CallExpr:
		// Try to get function name
		if fun, ok := n.Fun.(*ast.Ident); ok {
			currentNode.Title += fmt.Sprintf(" (Call: %s)", fun.Name)
		} else if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
			currentNode.Title += fmt.Sprintf(" (Call: %s.%s)", sel.X, sel.Sel.Name)
		}
	}

	parent.Children = append(parent.Children, currentNode)

	// Iterate children
	childCount := 0
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil || n == node {
			return true
		}
		// This inspect is too deep, we need direct children.
		// Standard ast.Inspect does depth-first.
		// So we can't easily distinguish direct children from grandchildren using Inspect here
		// without manual field traversal.
		return false // Stop inspect, we will do manual traversal
	})

	// Manual traversal using reflection to find ast.Node fields
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)

		// If field is an AST node or slice of AST nodes
		if isASTNode(field.Type()) {
			if !field.IsNil() {
				if node, ok := field.Interface().(ast.Node); ok {
					childCount++
					g.visit(node, currentNode, idPrefix+"-"+strconv.Itoa(childCount))
				}
			}
		} else if field.Kind() == reflect.Slice {
			for j := 0; j < field.Len(); j++ {
				elem := field.Index(j)
				if isASTNode(elem.Type()) {
					if !elem.IsNil() {
						if node, ok := elem.Interface().(ast.Node); ok {
							childCount++
							g.visit(node, currentNode, idPrefix+"-"+strconv.Itoa(childCount))
						}
					}
				}
			}
		}
		// Also handle some specific non-node fields that are interesting?
		// Maybe later. For now, structural AST is enough.
	}
}

func isASTNode(t reflect.Type) bool {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	// Check if it implements ast.Node
	// In reflection, it's easier to check if it's in the ast package
	return t.PkgPath() == "go/ast"
}
