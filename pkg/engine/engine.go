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
