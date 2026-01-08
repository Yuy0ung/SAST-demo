package core

// ASTNode represents a node in the Abstract Syntax Tree for visualization
type ASTNode struct {
	Key      string     `json:"key"`      // Unique ID for the tree node
	Title    string     `json:"title"`    // Display text (Type: Value)
	Children []*ASTNode `json:"children"` // Child nodes
	Line     int        `json:"line,omitempty"`
}
