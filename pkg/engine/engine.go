package engine

import (
	"regexp"
	"sast-demo/pkg/core"
)

type Engine struct {
	Config Config
}

func NewEngine(cfg Config) *Engine {
	return &Engine{Config: cfg}
}

// AnalyzeLegacy processes the old Graph model
func (e *Engine) AnalyzeLegacy(graph *core.Graph) []core.Vulnerability {
	var vulns []core.Vulnerability

	for _, rule := range e.Config.Rules {
		// Compile regexes
		var sourceRegexes []*regexp.Regexp
		for _, s := range rule.Sources {
			if r, err := regexp.Compile(s); err == nil {
				sourceRegexes = append(sourceRegexes, r)
			}
		}

		var sinkRegexes []*regexp.Regexp
		for _, s := range rule.Sinks {
			if r, err := regexp.Compile(s); err == nil {
				sinkRegexes = append(sinkRegexes, r)
			}
		}

		// Find Sources in the graph
		for _, node := range graph.Nodes {
			if e.matchesAny(node.Code, sourceRegexes) {
				// Start traversal
				if path := e.findPathToSinkLegacy(graph, node, sinkRegexes); path != nil {
					vulns = append(vulns, core.Vulnerability{
						Type:        rule.Name,
						Severity:    rule.Severity,
						File:        node.File,
						Line:        node.Line,
						Description: rule.Description,
						Source:      node,
						Sink:        path[len(path)-1],
						Path:        path,
					})
				}
			}
		}
	}

	return vulns
}

// AnalyzeIR processes the new ProgramIR model
func (e *Engine) AnalyzeIR(prog *core.ProgramIR, filePath string) []core.Vulnerability {
	var vulns []core.Vulnerability

	// 1. Build Use-Def chains
	// Map: VariableName -> [Instructions that use it]
	useMap := make(map[string][]*core.Instruction)
	// Map: InstructionID -> BlockID
	instToBlock := make(map[string]string)
	// Map: InstructionID -> FunctionName
	instToFunc := make(map[string]string)
	// List of all instructions for linear scanning
	var allInsts []*core.Instruction

	for _, fn := range prog.Functions {
		for _, bb := range fn.Blocks {
			for _, inst := range bb.Instructions {
				allInsts = append(allInsts, inst)
				instToBlock[inst.ID] = bb.ID
				instToFunc[inst.ID] = fn.Name
				for _, op := range inst.Operands {
					useMap[op] = append(useMap[op], inst)
				}
			}
		}
	}

	// 2. Scan for Vulnerabilities
	for _, rule := range e.Config.Rules {
		sourceRegexes := e.compileRegexes(rule.Sources)
		sinkRegexes := e.compileRegexes(rule.Sinks)

		for _, inst := range allInsts {
			// Check if instruction is a Source
			// We check the full code string or just the function call part
			if e.matchesAny(inst.Code, sourceRegexes) {
				// Start Taint Tracking
				if path := e.findPathToSinkIR(inst, sinkRegexes, useMap); path != nil {
					// Validate Control Flow (CFG Reachability)
					if !e.validatePath(path, prog, instToBlock, instToFunc) {
						continue
					}

					sinkInst := path[len(path)-1]
					vulns = append(vulns, core.Vulnerability{
						Type:        rule.Name,
						Severity:    rule.Severity,
						File:        filePath,
						Line:        inst.Line,
						Description: rule.Description,
						Source:      e.instToNode(inst, filePath, instToBlock, instToFunc),
						Sink:        e.instToNode(sinkInst, filePath, instToBlock, instToFunc),
						Path:        e.pathInstToNode(path, filePath, instToBlock, instToFunc),
					})
				}
			}
		}
	}

	return vulns
}

func (e *Engine) compileRegexes(patterns []string) []*regexp.Regexp {
	var regexes []*regexp.Regexp
	for _, s := range patterns {
		if r, err := regexp.Compile(s); err == nil {
			regexes = append(regexes, r)
		}
	}
	return regexes
}

func (e *Engine) matchesAny(s string, regexes []*regexp.Regexp) bool {
	for _, r := range regexes {
		if r.MatchString(s) {
			return true
		}
	}
	return false
}

func (e *Engine) findPathToSinkLegacy(g *core.Graph, start *core.Node, sinkRegexes []*regexp.Regexp) []*core.Node {
	queue := [][]*core.Node{{start}}
	visited := make(map[string]bool)
	visited[start.ID] = true

	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		curr := path[len(path)-1]

		if len(path) > 1 && e.matchesAny(curr.Code, sinkRegexes) {
			return path
		}

		for _, edge := range g.Edges {
			if edge.From.ID == curr.ID && edge.Type == core.EdgeDataFlow {
				if !visited[edge.To.ID] {
					visited[edge.To.ID] = true
					newPath := make([]*core.Node, len(path))
					copy(newPath, path)
					newPath = append(newPath, edge.To)
					queue = append(queue, newPath)
				}
			}
		}
	}
	return nil
}

func (e *Engine) findPathToSinkIR(start *core.Instruction, sinkRegexes []*regexp.Regexp, useMap map[string][]*core.Instruction) []*core.Instruction {
	queue := [][]*core.Instruction{{start}}
	visited := make(map[string]bool)
	visited[start.ID] = true

	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		curr := path[len(path)-1]

		// Check sink
		if len(path) > 1 && e.matchesAny(curr.Code, sinkRegexes) {
			return path
		}

		// Propagate taint: If curr produces a result, find all instructions that use it
		if curr.Result != "" {
			if users, ok := useMap[curr.Result]; ok {
				for _, nextInst := range users {
					if !visited[nextInst.ID] {
						visited[nextInst.ID] = true
						newPath := make([]*core.Instruction, len(path))
						copy(newPath, path)
						newPath = append(newPath, nextInst)
						queue = append(queue, newPath)
					}
				}
			}
		}
	}
	return nil
}

func (e *Engine) instToNode(i *core.Instruction, file string, instToBlock map[string]string, instToFunc map[string]string) *core.Node {
	return &core.Node{
		ID:       i.ID,
		Type:     core.NodeCall, // Generic
		Code:     i.Code,
		Line:     i.Line,
		File:     file,
		Function: instToFunc[i.ID],
		BlockID:  instToBlock[i.ID],
	}
}

func (e *Engine) pathInstToNode(path []*core.Instruction, file string, instToBlock map[string]string, instToFunc map[string]string) []*core.Node {
	var nodes []*core.Node
	for _, i := range path {
		nodes = append(nodes, e.instToNode(i, file, instToBlock, instToFunc))
	}
	return nodes
}

// validatePath checks if the taint path is valid according to the CFG
func (e *Engine) validatePath(path []*core.Instruction, prog *core.ProgramIR, instToBlock map[string]string, instToFunc map[string]string) bool {
	for i := 0; i < len(path)-1; i++ {
		curr := path[i]
		next := path[i+1]

		fName1 := instToFunc[curr.ID]
		fName2 := instToFunc[next.ID]

		// Skip inter-procedural checks for now
		if fName1 != fName2 {
			continue
		}

		fn := prog.Functions[fName1]
		if fn == nil {
			continue
		}

		b1ID := instToBlock[curr.ID]
		b2ID := instToBlock[next.ID]

		if b1ID == b2ID {
			// Same block: check order
			block := fn.Blocks[b1ID]
			if !e.isOrderedInBlock(curr, next, block) {
				return false
			}
		} else {
			// Different blocks: check CFG reachability
			if !e.isReachable(b1ID, b2ID, fn) {
				return false
			}
		}
	}
	return true
}

// isOrderedInBlock checks if a comes before b in the block
func (e *Engine) isOrderedInBlock(a, b *core.Instruction, block *core.BasicBlock) bool {
	foundA := false
	for _, inst := range block.Instructions {
		if inst.ID == a.ID {
			foundA = true
		}
		if inst.ID == b.ID {
			return foundA // If foundA is true, A is before B. If false, B is before A (invalid).
		}
	}
	return false
}

// isReachable checks if startBlock can reach endBlock in the function CFG
func (e *Engine) isReachable(startID, endID string, fn *core.FunctionIR) bool {
	if startID == endID {
		return true
	}

	visited := make(map[string]bool)
	queue := []string{startID}
	visited[startID] = true

	for len(queue) > 0 {
		currID := queue[0]
		queue = queue[1:]

		if currID == endID {
			return true
		}

		currBlock, ok := fn.Blocks[currID]
		if !ok {
			continue
		}

		for _, succID := range currBlock.Successors {
			if !visited[succID] {
				visited[succID] = true
				queue = append(queue, succID)
			}
		}
	}

	return false
}
