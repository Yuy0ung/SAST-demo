package engine

type Rule struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Sources     []string `json:"sources"` // Regex patterns
	Sinks       []string `json:"sinks"`   // Regex patterns
}

type Config struct {
	Rules []Rule `json:"rules"`
}

// DefaultRules returns a set of built-in rules for the demo
func DefaultRules() Config {
	return Config{
		Rules: []Rule{
			{
				Name:        "Command Injection (RCE)",
				Description: "User input flows into command execution",
				Severity:    "CRITICAL",
				Sources: []string{
					"request\\.getParameter", // Java
					"os\\.Args",              // Go
					"scanner\\.nextLine",     // Java
					"r\\.URL\\.Query",        // Go
				},
				Sinks: []string{
					"Runtime\\.getRuntime\\(\\)\\.exec", // Java
					"os/exec\\.Command",                 // Go
					"exec\\.Command",                    // Go
					"syscall\\.Exec",                    // Go
					"ProcessBuilder",                    // Java
				},
			},
			{
				Name:        "SQL Injection",
				Description: "User input flows into SQL query",
				Severity:    "HIGH",
				Sources: []string{
					"request\\.getParameter",
					"r\\.URL\\.Query",
				},
				Sinks: []string{
					// Go
					"sql\\.Exec",
					"db\\.Query",
					// JDBC
					"executeQuery",
					"execute",
					// JPA / Hibernate
					"entityManager\\.createQuery",
					"session\\.createQuery",
					"session\\.createSQLQuery",
					// MyBatis (programmatic)
					"sqlSession\\.selectOne",
					"sqlSession\\.selectList",
				},
			},
			{
				Name:        "XSS (Cross-Site Scripting)",
				Description: "User input flows into HTML output",
				Severity:    "MEDIUM",
				Sources: []string{
					"request\\.getParameter",
					"r\\.URL\\.Query",
				},
				Sinks: []string{
					// Java
					"out\\.println",
					"response\\.getWriter\\(\\)\\.write",
					// Go
					"w\\.Write",
					"fmt\\.Fprintf",
					"template\\.Execute",
				},
			},
			{
				Name:        "SSRF (Server-Side Request Forgery)",
				Description: "User input controls network request target",
				Severity:    "HIGH",
				Sources: []string{
					"request\\.getParameter",
					"r\\.URL\\.Query",
				},
				Sinks: []string{
					// Java
					"new URL",
					"HttpClients\\.createDefault",
					"httpClient\\.execute",
					"openConnection",
					// Go
					"http\\.Get",
					"http\\.Post",
					"http\\.NewRequest",
				},
			},
			{
				Name:        "Path Traversal",
				Description: "User input controls file path",
				Severity:    "HIGH",
				Sources: []string{
					"request\\.getParameter",
					"r\\.URL\\.Query",
				},
				Sinks: []string{
					// Java
					"new File",
					"Paths\\.get",
					"new FileInputStream",
					"new FileReader",
					// Go
					"os\\.Open",
					"os\\.OpenFile",
					"ioutil\\.ReadFile",
					"os\\.ReadFile",
				},
			},
		},
	}
}
