package java

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sast-demo/pkg/core"
	"strings"
)

// JavaIRGenerator generates IR from Java source code using a simplified stack-based parser.
type JavaIRGenerator struct {
	program    *core.ProgramIR
	currentFn  *core.FunctionIR
	currBlock  *core.BasicBlock
	blockCount int
	// Stack for handling control flow: stores merge blocks or loop headers
	ctrlStack []controlContext
}

type controlContext struct {
	type_      string // "if", "loop"
	mergeBlock *core.BasicBlock
	loopHeader *core.BasicBlock // for loops
}

func NewJavaIRGenerator() *JavaIRGenerator {
	return &JavaIRGenerator{
		program: &core.ProgramIR{
			Functions: make(map[string]*core.FunctionIR),
		},
		ctrlStack: make([]controlContext, 0),
	}
}

func (g *JavaIRGenerator) Generate(filePath string) (*core.ProgramIR, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Initialize a default "main" function
	g.currentFn = &core.FunctionIR{
		Name:   "main",
		Blocks: make(map[string]*core.BasicBlock),
	}
	g.program.Functions["main"] = g.currentFn
	g.newBlock() // Entry block

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Regex patterns
	// if (condition) {
	ifRegex := regexp.MustCompile(`^\s*if\s*\((.*)\)\s*\{?`)
	// } else {
	elseRegex := regexp.MustCompile(`^\s*\}\s*else\s*\{?`)
	// while (condition) {
	whileRegex := regexp.MustCompile(`^\s*while\s*\((.*)\)\s*\{?`)
	// for (...;...;...) {
	forRegex := regexp.MustCompile(`^\s*for\s*\((.*)\)\s*\{?`)
	// }
	closeRegex := regexp.MustCompile(`^\s*\}\s*$`)

	// Assignments: type var = val; or var = val;
	assignRegex := regexp.MustCompile(`^\s*(?:[a-zA-Z0-9_<>\[\]]+\s+)?([a-zA-Z0-9_]+)\s*=\s*(.+);`)
	// Method calls: obj.method(args); or method(args);
	callRegex := regexp.MustCompile(`^\s*([a-zA-Z0-9_.]+\s*\(.*\));`)
	// Return
	returnRegex := regexp.MustCompile(`^\s*return\s*(.*);`)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") {
			continue
		}

		// 1. Control Flow: IF
		if matches := ifRegex.FindStringSubmatch(line); matches != nil {
			cond := matches[1]

			// Create blocks
			thenBlock := g.createBlock()
			mergeBlock := g.createBlock()

			// Jump from current to then/merge
			g.emit(core.OpBranch, cond, []string{thenBlock.ID, mergeBlock.ID}, lineNum)

			// Push context
			g.pushCtrl(controlContext{type_: "if", mergeBlock: mergeBlock})

			// Switch to then
			g.currBlock = thenBlock
			continue
		}

		// 2. Control Flow: ELSE
		if elseRegex.MatchString(line) {
			if len(g.ctrlStack) > 0 {
				ctx := g.peekCtrl()
				if ctx.type_ == "if" {
					// End of THEN block, jump to MERGE
					g.emit(core.OpJump, "", []string{ctx.mergeBlock.ID}, lineNum)

					// Create ELSE block
					elseBlock := g.createBlock()
					g.currBlock = elseBlock
					continue
				}
			}
		}

		// 3. Control Flow: WHILE/FOR (Loops)
		if matches := whileRegex.FindStringSubmatch(line); matches != nil {
			cond := matches[1]
			g.handleLoop(cond, lineNum)
			continue
		}
		if matches := forRegex.FindStringSubmatch(line); matches != nil {
			g.handleLoop("loop_cond", lineNum) // Simplified condition for for-loop
			continue
		}

		// 4. Block End: }
		if closeRegex.MatchString(line) {
			if len(g.ctrlStack) > 0 {
				ctx := g.popCtrl()
				// Jump to merge block
				g.emit(core.OpJump, "", []string{ctx.mergeBlock.ID}, lineNum)
				g.currBlock = ctx.mergeBlock
			}
			continue
		}

		// 5. Instructions
		if matches := assignRegex.FindStringSubmatch(line); matches != nil {
			// var = val
			lhs := matches[1]
			rhs := matches[2]

			// Check if RHS is a call
			if strings.Contains(rhs, "(") && strings.Contains(rhs, ")") {
				// Simplified call handling
				g.emit(core.OpCall, rhs, nil, lineNum, lhs)
			} else {
				g.emit(core.OpStore, rhs, nil, lineNum, lhs)
			}
			continue
		}

		if matches := callRegex.FindStringSubmatch(line); matches != nil {
			call := matches[1]
			g.emit(core.OpCall, call, nil, lineNum)
			continue
		}

		if matches := returnRegex.FindStringSubmatch(line); matches != nil {
			val := matches[1]
			g.emit(core.OpRet, val, nil, lineNum)
			continue
		}
	}

	return g.program, nil
}

func (g *JavaIRGenerator) handleLoop(cond string, lineNum int) {
	headerBlock := g.createBlock()
	bodyBlock := g.createBlock()
	exitBlock := g.createBlock()

	// Current -> Header
	g.emit(core.OpJump, "", []string{headerBlock.ID}, lineNum)

	// Header -> Body or Exit
	g.currBlock = headerBlock
	g.emit(core.OpBranch, cond, []string{bodyBlock.ID, exitBlock.ID}, lineNum)

	// Stack: loop
	g.pushCtrl(controlContext{type_: "loop", mergeBlock: exitBlock, loopHeader: headerBlock})

	// Start Body
	g.currBlock = bodyBlock
}

func (g *JavaIRGenerator) newBlock() *core.BasicBlock {
	bb := g.createBlock()
	g.currBlock = bb
	return bb
}

func (g *JavaIRGenerator) createBlock() *core.BasicBlock {
	id := fmt.Sprintf("b%d", g.blockCount)
	g.blockCount++
	bb := &core.BasicBlock{
		ID:           id,
		Instructions: []*core.Instruction{},
		Predecessors: []string{},
		Successors:   []string{},
	}
	g.currentFn.Blocks[id] = bb
	return bb
}

func (g *JavaIRGenerator) emit(op core.OpCode, code string, successors []string, line int, result ...string) {
	res := ""
	if len(result) > 0 {
		res = result[0]
	}

	// Improved operand parsing: Extract identifiers from code, ignoring string literals
	var operands []string

	// 1. Remove string literals to avoid matching inside strings
	cleanCode := code
	quoteRegex := regexp.MustCompile(`"[^"]*"`)
	cleanCode = quoteRegex.ReplaceAllString(cleanCode, "")

	// 2. Find all identifiers
	identRegex := regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]*\b`)
	matches := identRegex.FindAllString(cleanCode, -1)

	// 3. Filter keywords and result variable
	keywords := map[string]bool{
		"new": true, "null": true, "true": true, "false": true,
		"if": true, "else": true, "return": true, "while": true, "for": true,
		"int": true, "boolean": true, "String": true, "void": true, "var": true,
		"public": true, "private": true, "protected": true, "static": true, "final": true,
		"class": true, "import": true, "package": true, "try": true, "catch": true,
	}

	for _, m := range matches {
		if !keywords[m] && m != res {
			operands = append(operands, m)
		}
	}

	inst := &core.Instruction{
		ID:       fmt.Sprintf("i%d", len(g.currBlock.Instructions)),
		Op:       op,
		Code:     code,
		Operands: operands,
		Line:     line,
		Result:   res,
	}
	g.currBlock.Instructions = append(g.currBlock.Instructions, inst)

	// Link blocks
	if len(successors) > 0 {
		for _, succID := range successors {
			g.currBlock.Successors = append(g.currBlock.Successors, succID)
			if succBlock, ok := g.currentFn.Blocks[succID]; ok {
				succBlock.Predecessors = append(succBlock.Predecessors, g.currBlock.ID)
			}
		}
	}
}

func (g *JavaIRGenerator) pushCtrl(ctx controlContext) {
	g.ctrlStack = append(g.ctrlStack, ctx)
}

func (g *JavaIRGenerator) popCtrl() controlContext {
	if len(g.ctrlStack) == 0 {
		return controlContext{}
	}
	ctx := g.ctrlStack[len(g.ctrlStack)-1]
	g.ctrlStack = g.ctrlStack[:len(g.ctrlStack)-1]
	return ctx
}

func (g *JavaIRGenerator) peekCtrl() controlContext {
	if len(g.ctrlStack) == 0 {
		return controlContext{}
	}
	return g.ctrlStack[len(g.ctrlStack)-1]
}
