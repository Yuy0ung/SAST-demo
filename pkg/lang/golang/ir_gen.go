package golang

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sast-demo/pkg/core"
)

type IRGenerator struct {
	fset *token.FileSet
	prog *core.ProgramIR

	// Context for current function
	currentFunc  *core.FunctionIR
	currentBlock *core.BasicBlock
	blockCount   int
	instCount    int
}

func NewIRGenerator() *IRGenerator {
	return &IRGenerator{
		fset: token.NewFileSet(),
		prog: core.NewProgramIR(),
	}
}

func (g *IRGenerator) Generate(filePath string) (*core.ProgramIR, error) {
	node, err := parser.ParseFile(g.fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	for _, decl := range node.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			g.processFunction(fn)
		}
	}

	return g.prog, nil
}

func (g *IRGenerator) processFunction(fn *ast.FuncDecl) {
	funcName := fn.Name.Name
	g.currentFunc = &core.FunctionIR{
		Name:   funcName,
		Blocks: make(map[string]*core.BasicBlock),
	}
	g.blockCount = 0

	// Create entry block
	entryBlock := g.newBlock()
	g.currentFunc.Entry = entryBlock.ID
	g.currentBlock = entryBlock

	// Process params
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			g.emit(core.OpParam, name.Name, nil, name.Pos())
		}
	}

	// Process body
	g.processBlockStmt(fn.Body)

	g.prog.Functions[funcName] = g.currentFunc
}

func (g *IRGenerator) processBlockStmt(block *ast.BlockStmt) {
	for _, stmt := range block.List {
		g.processStmt(stmt)
	}
}

func (g *IRGenerator) processStmt(stmt ast.Stmt) {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		for i, lhs := range s.Lhs {
			var rhs ast.Expr
			if i < len(s.Rhs) {
				rhs = s.Rhs[i]
			}

			// Generate code for RHS
			rhsRes := g.processExpr(rhs)

			// Store to LHS
			if ident, ok := lhs.(*ast.Ident); ok {
				// x = ...
				g.emit(core.OpStore, ident.Name, []string{rhsRes}, s.Pos())
			}
		}
	case *ast.ExprStmt:
		g.processExpr(s.X)
	case *ast.ReturnStmt:
		var results []string
		for _, r := range s.Results {
			results = append(results, g.processExpr(r))
		}
		g.emit(core.OpRet, "", results, s.Pos())
	case *ast.IfStmt:
		g.processIf(s)
	case *ast.BlockStmt:
		g.processBlockStmt(s)
	}
}

func (g *IRGenerator) processIf(s *ast.IfStmt) {
	// 1. Condition
	condRes := g.processExpr(s.Cond)

	// 2. Blocks
	thenBlock := g.newBlock()
	elseBlock := g.newBlock() // Created even if empty to merge
	mergeBlock := g.newBlock()

	// Emit Branch in current block
	g.emit(core.OpBranch, "", []string{condRes, thenBlock.ID, elseBlock.ID}, s.Pos())

	// Connect CFG
	g.linkBlocks(g.currentBlock, thenBlock)
	g.linkBlocks(g.currentBlock, elseBlock)

	// Process Then
	g.currentBlock = thenBlock
	g.processBlockStmt(s.Body)
	// Jump to merge
	g.emit(core.OpJump, "", []string{mergeBlock.ID}, s.Body.End())
	g.linkBlocks(g.currentBlock, mergeBlock)

	// Process Else
	g.currentBlock = elseBlock
	elseEndPos := s.Body.End() // Fallback position
	if s.Else != nil {
		g.processStmt(s.Else)
		elseEndPos = s.Else.Pos()
	}
	// Jump to merge
	g.emit(core.OpJump, "", []string{mergeBlock.ID}, elseEndPos)
	g.linkBlocks(g.currentBlock, mergeBlock)

	// Continue in merge block
	g.currentBlock = mergeBlock
}

func (g *IRGenerator) processExpr(expr ast.Expr) string {
	if expr == nil {
		return ""
	}

	switch e := expr.(type) {
	case *ast.BasicLit:
		res := g.tempVar()
		g.emit(core.OpConst, res, []string{e.Value}, e.Pos())
		return res
	case *ast.Ident:
		// Loading a variable
		res := g.tempVar()
		g.emit(core.OpLoad, res, []string{e.Name}, e.Pos())
		return res
	case *ast.CallExpr:
		funName := "unknown"
		if id, ok := e.Fun.(*ast.Ident); ok {
			funName = id.Name
		} else if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			funName = g.resolveFlatName(sel)
		}

		var args []string
		for _, arg := range e.Args {
			args = append(args, g.processExpr(arg))
		}

		res := g.tempVar()
		ops := append([]string{funName}, args...)
		g.emit(core.OpCall, res, ops, e.Pos())
		return res
	case *ast.BinaryExpr:
		left := g.processExpr(e.X)
		right := g.processExpr(e.Y)
		res := g.tempVar()
		g.emit(core.OpBinOp, res, []string{left, e.Op.String(), right}, e.Pos())
		return res
	case *ast.SelectorExpr:
		// Handle field access like r.URL.Query
		// If it's part of a call, it's handled in CallExpr.
		// If it's a standalone access (like struct field), we resolve it.
		// However, complex selectors might need to be processed if they involve function calls.
		// For now, keep simple resolution for identifiers.
		name := g.resolveFlatName(e)
		res := g.tempVar()
		g.emit(core.OpLoad, res, []string{name}, e.Pos())
		return res
	case *ast.IndexExpr:
		// Handle array access like os.Args[1]
		// recursively process the container expression
		container := g.processExpr(e.X)
		res := g.tempVar()
		g.emit(core.OpLoad, res, []string{container}, e.Pos())
		return res
	}
	return ""
}

func (g *IRGenerator) resolveFlatName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return g.resolveFlatName(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + g.resolveFlatName(e.X)
	default:
		return "expr"
	}
}

// --- Helpers ---

func (g *IRGenerator) newBlock() *core.BasicBlock {
	id := fmt.Sprintf("B%d", g.blockCount)
	g.blockCount++
	bb := &core.BasicBlock{
		ID:           id,
		Instructions: make([]*core.Instruction, 0),
		Predecessors: make([]string, 0),
		Successors:   make([]string, 0),
	}
	g.currentFunc.Blocks[id] = bb
	return bb
}

func (g *IRGenerator) linkBlocks(from, to *core.BasicBlock) {
	from.Successors = append(from.Successors, to.ID)
	to.Predecessors = append(to.Predecessors, from.ID)
}

func (g *IRGenerator) emit(op core.OpCode, result string, operands []string, pos token.Pos) {
	position := g.fset.Position(pos)
	inst := &core.Instruction{
		ID:       fmt.Sprintf("i%d", g.instCount),
		Op:       op,
		Result:   result,
		Operands: operands,
		Line:     position.Line,
		Code:     g.formatCode(op, result, operands),
	}
	g.instCount++
	g.currentBlock.Instructions = append(g.currentBlock.Instructions, inst)
}

func (g *IRGenerator) tempVar() string {
	return fmt.Sprintf("t%d", g.instCount)
}

func (g *IRGenerator) formatCode(op core.OpCode, res string, ops []string) string {
	switch op {
	case core.OpStore:
		return fmt.Sprintf("%s = %s", res, ops[0])
	case core.OpLoad:
		return fmt.Sprintf("%s = load %s", res, ops[0])
	case core.OpCall:
		return fmt.Sprintf("%s = call %s(%v)", res, ops[0], ops[1:])
	case core.OpConst:
		return fmt.Sprintf("%s = const %s", res, ops[0])
	case core.OpBranch:
		return fmt.Sprintf("if %s goto %s else %s", ops[0], ops[1], ops[2])
	case core.OpJump:
		return fmt.Sprintf("goto %s", ops[0])
	default:
		return fmt.Sprintf("%s = %s %v", res, op, ops)
	}
}
