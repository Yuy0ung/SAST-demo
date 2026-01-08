package core

import "fmt"

// NodeType represents the type of code element
type NodeType string

const (
	NodeFunction    NodeType = "FUNCTION"
	NodeVariable    NodeType = "VARIABLE"
	NodeCall        NodeType = "CALL"
	NodeLiteral     NodeType = "LITERAL"
	NodeParameter   NodeType = "PARAMETER"
	NodeReturn      NodeType = "RETURN"
	NodeAssignment  NodeType = "ASSIGNMENT"
	NodeDeclaration NodeType = "DECLARATION"
)

// EdgeType represents the relationship between nodes
type EdgeType string

const (
	EdgeControlFlow EdgeType = "CFG" // Execution order
	EdgeDataFlow    EdgeType = "DFG" // Data dependency
)

// Node represents a vertex in the code graph
type Node struct {
	ID        string
	Type      NodeType
	Code      string // The actual code snippet
	Line      int
	File      string
	Function  string // Enclosing function name
	BlockID   string // Basic Block ID in CFG
}

// Edge represents a connection between two nodes
type Edge struct {
	From *Node
	To   *Node
	Type EdgeType
}

// Graph contains all nodes and edges for a file/program
type Graph struct {
	Nodes map[string]*Node
	Edges []Edge
}

func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]*Node),
		Edges: make([]Edge, 0),
	}
}

func (g *Graph) AddNode(n *Node) {
	g.Nodes[n.ID] = n
}

func (g *Graph) AddEdge(from, to *Node, edgeType EdgeType) {
	g.Edges = append(g.Edges, Edge{From: from, To: to, Type: edgeType})
}

// Vulnerability represents a detected security issue
type Vulnerability struct {
	Type        string
	Severity    string
	File        string
	Line        int
	Description string
	Source      *Node
	Sink        *Node
	Path        []*Node // The propagation path
}

func (v Vulnerability) String() string {
	return fmt.Sprintf("[%s] %s in %s:%d\n  Path: %s -> ... -> %s", v.Severity, v.Type, v.File, v.Line, v.Source.Code, v.Sink.Code)
}
