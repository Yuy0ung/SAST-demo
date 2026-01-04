package core

import "fmt"

// --- IR Definitions ---

type OpCode string

const (
	OpLoad   OpCode = "LOAD"   // x = y
	OpStore  OpCode = "STORE"  // *x = y
	OpCall   OpCode = "CALL"   // x = f(...)
	OpBinOp  OpCode = "BINOP"  // x = y + z
	OpRet    OpCode = "RET"    // return x
	OpParam  OpCode = "PARAM"  // parameter definition
	OpConst  OpCode = "CONST"  // x = 123
	OpPhi    OpCode = "PHI"    // SSA Phi node (simplified)
	OpBranch OpCode = "BRANCH" // if x goto L1 else L2
	OpJump   OpCode = "JUMP"   // goto L1
)

// Instruction represents a single operation in our IR
type Instruction struct {
	ID       string   `json:"id"`
	Op       OpCode   `json:"op"`
	Result   string   `json:"result,omitempty"`   // Variable name being assigned to
	Operands []string `json:"operands,omitempty"` // Arguments / Source variables
	Line     int      `json:"line"`
	Code     string   `json:"code"` // Human readable string
}

func (i Instruction) String() string {
	return fmt.Sprintf("%s: %s = %s %v", i.ID, i.Result, i.Op, i.Operands)
}

// --- CFG Definitions ---

// BasicBlock is a linear sequence of instructions with one entry and one exit (conceptually)
type BasicBlock struct {
	ID           string         `json:"id"`
	Instructions []*Instruction `json:"instructions"`
	Predecessors []string       `json:"predecessors"` // Block IDs
	Successors   []string       `json:"successors"`   // Block IDs
}

// FunctionIR holds the CFG and instructions for a single function
type FunctionIR struct {
	Name   string                 `json:"name"`
	Blocks map[string]*BasicBlock `json:"blocks"` // Map BlockID -> Block
	Entry  string                 `json:"entry"`  // Entry Block ID
}

// ProgramIR holds the IR for the entire file
type ProgramIR struct {
	Functions map[string]*FunctionIR `json:"functions"`
}

func NewProgramIR() *ProgramIR {
	return &ProgramIR{
		Functions: make(map[string]*FunctionIR),
	}
}
